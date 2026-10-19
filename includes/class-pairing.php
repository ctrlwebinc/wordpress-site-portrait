<?php
/**
 * Pairing lifecycle: start, completion, scopes, key rotation, revocation
 * (PROTOCOL.md §4, §10, §11).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

use WP_Error;

defined( 'ABSPATH' ) || exit;

/**
 * Manages the single pairing of this installation.
 */
final class Pairing {

	const PENDING_TTL         = 15 * MINUTE_IN_SECONDS;
	const KEY_GRACE_PERIOD    = 7 * DAY_IN_SECONDS;
	const KEY_REFRESH_SPACING = HOUR_IN_SECONDS;
	const PAIRING_ID_RE       = '/^[A-Za-z0-9._-]{1,64}$/';

	/**
	 * Returns the active pairing, or null.
	 *
	 * @return array|null
	 */
	public static function get() {
		$pairing = Store::get( Store::PAIRING );
		return is_array( $pairing ) && ! empty( $pairing['pairing_id'] ) ? $pairing : null;
	}

	/**
	 * Whether a pairing is active.
	 *
	 * @return bool
	 */
	public static function is_active() {
		return null !== self::get();
	}

	/**
	 * Saves the pairing.
	 *
	 * @param array $pairing Pairing data.
	 */
	private static function save( array $pairing ) {
		Store::set( Store::PAIRING, $pairing );
	}

	/**
	 * Transient name holding a user's pending pairing.
	 *
	 * @param int $user_id User id.
	 * @return string
	 */
	private static function pending_key( $user_id ) {
		return 'site_portrait_pending_' . (int) $user_id;
	}

	/**
	 * Starts a pairing and returns the authorization URL (PROTOCOL.md §4.1–4.2).
	 *
	 * @param array    $discovery Normalised discovery data.
	 * @param string[] $scopes    Scopes granted by the administrator.
	 * @param int      $user_id   Current user.
	 * @return string|WP_Error
	 */
	public static function begin( array $discovery, array $scopes, $user_id ) {
		$scopes = array_values( array_intersect( Scopes::sanitize( $scopes ), $discovery['scopes_supported'] ) );
		if ( empty( $scopes ) ) {
			return new WP_Error( 'site_portrait_no_scope', __( 'Select at least one category of data to share.', 'site-portrait' ) );
		}

		$keys     = Crypto::generate_keypair();
		$kid      = Crypto::thumbprint( $keys['public'] );
		$verifier = Crypto::random_token( 32 );
		$state    = Crypto::random_token( 32 );
		$redirect = self::callback_url();

		Store::set_transient(
			self::pending_key( $user_id ),
			array(
				'discovery'    => $discovery,
				'scopes'       => $scopes,
				'state'        => $state,
				'verifier'     => $verifier,
				'redirect_uri' => $redirect,
				'site_key'     => array(
					'kid'    => $kid,
					'public' => Crypto::b64url_encode( $keys['public'] ),
					'secret' => Crypto::b64url_encode( $keys['secret'] ),
				),
			),
			self::PENDING_TTL
		);

		$params = array(
			'response_type'         => 'code',
			'client_id'             => Plugin::origin( Plugin::home_url() ),
			'redirect_uri'          => $redirect,
			'state'                 => $state,
			'code_challenge'        => Crypto::pkce_challenge( $verifier ),
			'code_challenge_method' => 'S256',
			'scope'                 => implode( ' ', $scopes ),
			'site_key_thumbprint'   => $kid,
			'site_name'             => wp_strip_all_tags( get_bloginfo( 'name' ) ),
			'protocol_version'      => '1',
		);

		return add_query_arg( array_map( 'rawurlencode', $params ), $discovery['authorization_endpoint'] );
	}

	/**
	 * URL the service redirects the browser back to.
	 *
	 * The WordPress nonce is part of the URL, so the service returns it as is.
	 *
	 * @return string
	 */
	public static function callback_url() {
		return add_query_arg( '_wpnonce', wp_create_nonce( 'site_portrait_callback' ), Plugin::action_url( 'callback' ) );
	}

	/**
	 * Discards a user's pending pairing.
	 *
	 * @param int $user_id User id.
	 */
	public static function cancel_pending( $user_id ) {
		Store::delete_transient( self::pending_key( $user_id ) );
	}

	/**
	 * Completes the pairing after the browser came back (PROTOCOL.md §4.3–4.4).
	 *
	 * @param int    $user_id Current user.
	 * @param string $code    Authorization code.
	 * @param string $state   State returned by the service.
	 * @return true|WP_Error
	 */
	public static function complete( $user_id, $code, $state ) {
		$pending = Store::get_transient( self::pending_key( $user_id ) );
		self::cancel_pending( $user_id );

		if ( ! is_array( $pending ) || ! is_string( $state ) || ! hash_equals( $pending['state'], $state ) ) {
			return new WP_Error( 'site_portrait_state_mismatch', __( 'The connection request expired or was not started from this site. Please start again.', 'site-portrait' ) );
		}
		if ( ! is_string( $code ) || '' === $code || strlen( $code ) > 512 ) {
			return new WP_Error( 'site_portrait_invalid_code', __( 'The service returned an invalid authorization code.', 'site-portrait' ) );
		}
		if ( self::is_active() ) {
			return new WP_Error( 'site_portrait_already_paired', __( 'This site is already connected to a service. Disconnect it first.', 'site-portrait' ) );
		}

		$discovery = $pending['discovery'];
		$site_key  = $pending['site_key'];
		$secret    = Crypto::b64url_decode( $site_key['secret'] );
		$public    = Crypto::b64url_decode( $site_key['public'] );
		$endpoints = self::endpoints();

		$response = Service_Client::request(
			'POST',
			$discovery['token_endpoint'],
			array(
				'grant_type'       => 'authorization_code',
				'code'             => $code,
				'code_verifier'    => $pending['verifier'],
				'client_id'        => Plugin::origin( Plugin::home_url() ),
				'redirect_uri'     => $pending['redirect_uri'],
				'site_jwk'         => Crypto::public_jwk( $public ),
				'endpoints'        => $endpoints,
				'mode'             => Plugin::mode(),
				'scopes'           => $pending['scopes'],
				'plugin_version'   => SITE_PORTRAIT_VERSION,
				'protocol_version' => '1',
			),
			array(
				'secret' => $secret,
				'kid'    => $site_key['kid'],
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== $response['status'] ) {
			return Service_Client::error_from_response( $response, __( 'The code exchange with the service', 'site-portrait' ) );
		}

		$data = json_decode( $response['body'], true );
		if ( ! is_array( $data ) || ! isset( $data['pairing_id'] ) || ! is_string( $data['pairing_id'] ) || ! preg_match( self::PAIRING_ID_RE, $data['pairing_id'] ) ) {
			return new WP_Error( 'site_portrait_invalid_token_response', __( 'The service returned an invalid response (pairing_id).', 'site-portrait' ) );
		}

		$scopes = isset( $data['scopes'] ) ? array_values( array_intersect( $pending['scopes'], Scopes::sanitize( $data['scopes'] ) ) ) : $pending['scopes'];
		if ( empty( $scopes ) ) {
			return new WP_Error( 'site_portrait_invalid_token_response', __( 'The service returned an invalid response (scopes).', 'site-portrait' ) );
		}

		// Pin only keys that were also published in the discovery document.
		$service_keys = array();
		foreach ( Service_Client::parse_jwks( $data['jwks'] ?? null ) as $kid => $jwk ) {
			if ( isset( $discovery['keys'][ $kid ] ) ) {
				$service_keys[ $kid ] = $jwk['x'];
			}
		}
		if ( empty( $service_keys ) ) {
			return new WP_Error( 'site_portrait_invalid_token_response', __( 'The service returned keys that do not match its discovery document.', 'site-portrait' ) );
		}

		unset( $discovery['keys'], $discovery['scopes_requested'], $discovery['scope_reasons'] );
		self::save(
			array(
				'pairing_id'         => $data['pairing_id'],
				'mode'               => Plugin::mode(),
				'service'            => $discovery,
				'service_keys'       => $service_keys,
				'site_key'           => array(
					'kid'          => $site_key['kid'],
					'public'       => $site_key['public'],
					'secret'       => $site_key['secret'],
					'endorsements' => array(),
				),
				'previous_site_keys' => array(),
				'scopes'             => $scopes,
				'account_hint'       => isset( $data['account_hint'] ) && is_string( $data['account_hint'] ) ? Service_Client::text( $data['account_hint'], 100 ) : '',
				'connected_at'       => time(),
				'connected_by'       => (int) $user_id,
				'confirmed_at'       => null,
				'keys_refreshed_at'  => time(),
			)
		);
		Nonce_Store::clear();

		return true;
	}

	/**
	 * REST endpoint URLs given to the service.
	 *
	 * @return array
	 */
	public static function endpoints() {
		$blog_id   = Plugin::is_network_mode() ? get_main_site_id() : null;
		$endpoints = array(
			'status'   => get_rest_url( $blog_id, Rest_Api::NAMESPACE_V1 . '/status' ),
			'portrait' => get_rest_url( $blog_id, Rest_Api::NAMESPACE_V1 . '/portrait' ),
			'revoke'   => get_rest_url( $blog_id, Rest_Api::NAMESPACE_V1 . '/revoke' ),
		);
		if ( Plugin::is_network_mode() ) {
			$endpoints['sites'] = get_rest_url( $blog_id, Rest_Api::NAMESPACE_V1 . '/sites' );
		}
		return $endpoints;
	}

	/**
	 * Records the first successful status call (PROTOCOL.md §4.5).
	 */
	public static function mark_confirmed() {
		$pairing = self::get();
		if ( null !== $pairing && empty( $pairing['confirmed_at'] ) ) {
			$pairing['confirmed_at'] = time();
			self::save( $pairing );
		}
	}

	/**
	 * Updates the granted scopes.
	 *
	 * @param string[] $scopes Scopes.
	 * @return bool False when no pairing is active.
	 */
	public static function set_scopes( array $scopes ) {
		$pairing = self::get();
		if ( null === $pairing ) {
			return false;
		}
		$pairing['scopes'] = array_values( array_intersect( Scopes::sanitize( $scopes ), $pairing['service']['scopes_supported'] ) );
		self::save( $pairing );
		return true;
	}

	/**
	 * Returns the current site signing key.
	 *
	 * @return array{kid: string, secret: string}|null Raw secret key.
	 */
	public static function site_signer() {
		$pairing = self::get();
		if ( null === $pairing ) {
			return null;
		}
		return array(
			'kid'    => $pairing['site_key']['kid'],
			'secret' => Crypto::b64url_decode( $pairing['site_key']['secret'] ),
		);
	}

	/**
	 * Public site keys to publish in /status (current first).
	 *
	 * @return array JWKS.
	 */
	public static function site_jwks() {
		$pairing = self::get();
		if ( null === $pairing ) {
			return array( 'keys' => array() );
		}
		$current = Crypto::public_jwk( Crypto::b64url_decode( $pairing['site_key']['public'] ) );
		if ( ! empty( $pairing['site_key']['endorsements'] ) ) {
			$current['endorsements'] = $pairing['site_key']['endorsements'];
		}
		$keys = array( $current );
		foreach ( $pairing['previous_site_keys'] as $previous ) {
			if ( $previous['retired_at'] + self::KEY_GRACE_PERIOD > time() ) {
				$keys[] = Crypto::public_jwk( Crypto::b64url_decode( $previous['public'] ) );
			}
		}
		return array( 'keys' => $keys );
	}

	/**
	 * Replaces the site key by a new one endorsed by the current key (PROTOCOL.md §11.2).
	 *
	 * @return bool
	 */
	public static function rotate_site_key() {
		$pairing = self::get();
		if ( null === $pairing ) {
			return false;
		}
		$old    = $pairing['site_key'];
		$keys   = Crypto::generate_keypair();
		$kid    = Crypto::thumbprint( $keys['public'] );
		$secret = Crypto::b64url_decode( $old['secret'] );

		$pairing['previous_site_keys'] = array_values(
			array_filter(
				$pairing['previous_site_keys'],
				static function ( $previous ) {
					return $previous['retired_at'] + self::KEY_GRACE_PERIOD > time();
				}
			)
		);
		array_unshift(
			$pairing['previous_site_keys'],
			array(
				'kid'        => $old['kid'],
				'public'     => $old['public'],
				'retired_at' => time(),
			)
		);
		$pairing['site_key'] = array(
			'kid'          => $kid,
			'public'       => Crypto::b64url_encode( $keys['public'] ),
			'secret'       => Crypto::b64url_encode( $keys['secret'] ),
			'endorsements' => array( Crypto::endorse( $kid, $secret, $old['kid'] ) ),
		);
		self::save( $pairing );
		return true;
	}

	/**
	 * Returns the raw public key of a pinned service key, refreshing the
	 * pinned set from discovery when the key id is unknown (PROTOCOL.md §11.1).
	 *
	 * @param string $kid Key id.
	 * @return string|null
	 */
	public static function service_key( $kid ) {
		$pairing = self::get();
		if ( null === $pairing ) {
			return null;
		}
		if ( ! isset( $pairing['service_keys'][ $kid ] ) && self::refresh_service_keys() ) {
			$pairing = self::get();
		}
		return isset( $pairing['service_keys'][ $kid ] ) ? Crypto::b64url_decode( $pairing['service_keys'][ $kid ] ) : null;
	}

	/**
	 * Re-reads the discovery document and pins endorsed keys, at most once per hour.
	 *
	 * @return bool Whether the pinned keys changed.
	 */
	public static function refresh_service_keys() {
		$pairing = self::get();
		if ( null === $pairing || ( (int) $pairing['keys_refreshed_at'] + self::KEY_REFRESH_SPACING ) > time() ) {
			return false;
		}
		$pairing['keys_refreshed_at'] = time();
		self::save( $pairing );

		$discovery = Service_Client::discover( $pairing['service']['origin'] );
		if ( is_wp_error( $discovery ) ) {
			return false;
		}

		$trusted = array();
		foreach ( $pairing['service_keys'] as $kid => $x ) {
			$trusted[ $kid ] = Crypto::b64url_decode( $x );
		}

		$pinned = array();
		foreach ( $discovery['keys'] as $kid => $jwk ) {
			if ( isset( $trusted[ $kid ] ) || Crypto::is_endorsed( $jwk, $trusted ) ) {
				$pinned[ $kid ] = $jwk['x'];
			}
		}
		if ( empty( $pinned ) || array_keys( $pinned ) === array_keys( $pairing['service_keys'] ) ) {
			return false;
		}

		$pairing['service_keys'] = $pinned;
		self::save( $pairing );
		return true;
	}

	/**
	 * Disconnects: local revocation first, then a best-effort notice to the
	 * service (PROTOCOL.md §10.1).
	 *
	 * @param string $reason  revoked_by_site, plugin_uninstalled or key_compromised.
	 * @param int    $timeout Notice timeout in seconds.
	 * @return true|WP_Error WP_Error when the service could not be notified.
	 */
	public static function disconnect( $reason = 'revoked_by_site', $timeout = 10 ) {
		$pairing = self::get();
		if ( null === $pairing ) {
			return true;
		}
		self::forget();

		$response = Service_Client::request(
			'POST',
			$pairing['service']['revocation_endpoint'],
			array(
				'pairing_id' => $pairing['pairing_id'],
				'client_id'  => Plugin::origin( Plugin::home_url() ),
				'reason'     => $reason,
			),
			array(
				'secret' => Crypto::b64url_decode( $pairing['site_key']['secret'] ),
				'kid'    => $pairing['site_key']['kid'],
			),
			$timeout
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== $response['status'] ) {
			return Service_Client::error_from_response( $response, __( 'Notifying the service', 'site-portrait' ) );
		}
		return true;
	}

	/**
	 * Deletes the pairing locally (keys included) without notifying anyone.
	 */
	public static function forget() {
		Store::delete( Store::PAIRING );
		Nonce_Store::clear();
	}
}
