<?php
/**
 * Signed REST API (PROTOCOL.md §6).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

defined( 'ABSPATH' ) || exit;

/**
 * Registers the routes, authenticates requests and signs responses.
 */
final class Rest_Api {

	const NAMESPACE_V1       = 'site-portrait/v1';
	const DEFAULT_RATE_LIMIT = 60;
	const FAILURE_LIMIT      = 30;
	const CONTENT_TYPE       = 'application/json; charset=UTF-8';

	/**
	 * Verified signature of the current request, if any.
	 *
	 * @var array|null
	 */
	private static $auth = null;

	/**
	 * Seconds to send in Retry-After, if rate limited.
	 *
	 * @var int|null
	 */
	private static $retry_after = null;

	/**
	 * Scopes to record in the access log for the current request.
	 *
	 * @var string[]
	 */
	private static $log_scopes = array();

	/**
	 * Signing key kept for the response after a service-initiated revocation.
	 *
	 * @var array|null
	 */
	private static $signer_override = null;

	/**
	 * Hooks into the REST API.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( self::class, 'register_routes' ) );
		add_filter( 'rest_pre_serve_request', array( self::class, 'serve' ), 10, 4 );
	}

	/**
	 * Registers routes, only while a pairing is active (and on the main site
	 * in network mode).
	 */
	public static function register_routes() {
		if ( ! Pairing::is_active() || ( Plugin::is_network_mode() && ! is_main_site() ) ) {
			return;
		}

		$permission = array( self::class, 'authenticate' );

		register_rest_route(
			self::NAMESPACE_V1,
			'/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( self::class, 'get_status' ),
				'permission_callback' => $permission,
			)
		);
		register_rest_route(
			self::NAMESPACE_V1,
			'/portrait',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( self::class, 'get_portrait' ),
				'permission_callback' => $permission,
			)
		);
		register_rest_route(
			self::NAMESPACE_V1,
			'/revoke',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( self::class, 'revoke' ),
				'permission_callback' => $permission,
			)
		);
		if ( Plugin::is_network_mode() ) {
			register_rest_route(
				self::NAMESPACE_V1,
				'/sites',
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( self::class, 'get_sites' ),
					'permission_callback' => $permission,
				)
			);
		}
	}

	/**
	 * Permission callback: checks IP, HTTPS, signature, replay and rate limit.
	 *
	 * Cookie and application-password authentication are deliberately ignored.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return true|WP_Error
	 */
	public static function authenticate( WP_REST_Request $request ) {
		self::$auth = null;
		$ip         = self::client_ip();
		$allowlist  = Store::settings()['ip_allowlist'];

		if ( ! empty( $allowlist ) && ! Ip_Allowlist::matches( $ip, $allowlist ) ) {
			return self::error( 'site_portrait_ip_not_allowed', 'Source IP address not allowed.', 403 );
		}
		if ( Access_Log::count_failures_last_hour( $ip ) >= (int) apply_filters( 'site_portrait_failure_limit', self::FAILURE_LIMIT ) ) {
			self::$retry_after = HOUR_IN_SECONDS;
			return self::error( 'site_portrait_rate_limited', 'Too many failed requests.', 429 );
		}
		if ( ! is_ssl() && ! Plugin::is_dev_mode() ) {
			return self::error( 'site_portrait_https_required', 'HTTPS is required.', 403 );
		}

		$target = self::request_target();
		if ( null === $target ) {
			return self::error( 'site_portrait_signature_malformed', 'Invalid request target.', 401 );
		}

		$headers = array();
		foreach ( array( 'signature-input', 'signature', 'content-type', 'content-digest' ) as $name ) {
			$value = $request->get_header( $name );
			if ( null !== $value ) {
				$headers[ $name ] = $value;
			}
		}

		if ( 'GET' !== $request->get_method() ) {
			if ( ! isset( $headers['content-digest'] ) || ! hash_equals( Crypto::content_digest( $request->get_body() ), trim( $headers['content-digest'] ) ) ) {
				return self::error( 'site_portrait_digest_mismatch', 'Content-Digest does not match the body.', 400 );
			}
		}

		try {
			$auth = Http_Signature::verify_request(
				array(
					'method'    => $request->get_method(),
					'authority' => Plugin::expected_authority(),
					'path'      => $target['path'],
					'query'     => $target['query'],
					'headers'   => $headers,
				),
				array( Pairing::class, 'service_key' )
			);
		} catch ( Signature_Error $e ) {
			return self::error( $e->get_error_code(), $e->getMessage(), $e->get_status() );
		}

		if ( ! Nonce_Store::consume( $auth['kid'], $auth['nonce'], $auth['expires'] ) ) {
			return self::error( 'site_portrait_replay', 'Nonce already used.', 401 );
		}

		$limit = self::rate_limit();
		if ( Access_Log::count_authenticated_last_hour() >= $limit ) {
			$oldest            = Access_Log::oldest_authenticated_in_window();
			self::$retry_after = max( 1, ( null === $oldest ? time() : $oldest ) + HOUR_IN_SECONDS - time() );
			return self::error( 'site_portrait_rate_limited', 'Rate limit exceeded.', 429 );
		}

		self::$auth = $auth;
		return true;
	}

	/**
	 * GET /status (PROTOCOL.md §6.2).
	 *
	 * @return array
	 */
	public static function get_status() {
		Pairing::mark_confirmed();
		$pairing = Pairing::get();
		$limit   = self::rate_limit();

		return array(
			'protocol_version' => '1',
			'plugin_version'   => SITE_PORTRAIT_VERSION,
			'pairing_id'       => $pairing['pairing_id'],
			'mode'             => Plugin::mode(),
			'site_url'         => Plugin::origin( Plugin::home_url() ),
			'sites_count'      => is_multisite() ? (int) get_blog_count() : 1,
			'scopes_granted'   => $pairing['scopes'],
			'scopes_available' => Scopes::all(),
			'site_jwks'        => Pairing::site_jwks(),
			'rate_limit'       => array(
				'limit'     => $limit,
				'remaining' => max( 0, $limit - Access_Log::count_authenticated_last_hour() - 1 ),
				'window'    => HOUR_IN_SECONDS,
			),
			'server_time'      => time(),
		);
	}

	/**
	 * GET /portrait (PROTOCOL.md §6.3).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array|WP_Error
	 */
	public static function get_portrait( WP_REST_Request $request ) {
		$granted = Pairing::get()['scopes'];
		$raw     = $request->get_param( 'scopes' );

		if ( null === $raw || '' === $raw ) {
			$requested = $granted;
		} elseif ( ! is_string( $raw ) ) {
			return self::error( 'site_portrait_invalid_scope', 'Invalid scopes parameter.', 400 );
		} else {
			$requested = array_values( array_unique( array_map( 'trim', explode( ',', $raw ) ) ) );
			$unknown   = array_diff( $requested, Scopes::all() );
			if ( ! empty( $unknown ) ) {
				return self::error( 'site_portrait_invalid_scope', 'Unknown scope: ' . implode( ', ', array_map( 'sanitize_key', $unknown ) ) . '.', 400 );
			}
		}

		$returned = array_values( array_intersect( Scopes::all(), $requested, $granted ) );
		$denied   = array_values( array_diff( $requested, $granted ) );
		if ( empty( $returned ) ) {
			return self::error( 'site_portrait_scope_denied', 'None of the requested scopes is granted.', 403 );
		}

		$site_id = self::site_id_param( $request );
		if ( is_wp_error( $site_id ) ) {
			return $site_id;
		}

		self::$log_scopes = $returned;
		return Portrait_Builder::build( $returned, $denied, $site_id );
	}

	/**
	 * GET /sites (PROTOCOL.md §6.5).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array|WP_Error
	 */
	public static function get_sites( WP_REST_Request $request ) {
		$granted = Pairing::get()['scopes'];
		if ( ! in_array( 'core', $granted, true ) ) {
			return self::error( 'site_portrait_scope_denied', 'The core scope is required.', 403 );
		}
		$page = $request->get_param( 'page' );
		if ( null === $page ) {
			$page = 1;
		} elseif ( ! is_scalar( $page ) || ! ctype_digit( (string) $page ) || (int) $page < 1 ) {
			return self::error( 'site_portrait_invalid_param', 'Invalid page parameter.', 400 );
		}
		self::$log_scopes = array( 'core' );
		return Network_Sites::page( (int) $page, $granted );
	}

	/**
	 * POST /revoke (PROTOCOL.md §6.4).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array|WP_Error
	 */
	public static function revoke( WP_REST_Request $request ) {
		$body = json_decode( $request->get_body(), true );
		if ( ! is_array( $body ) ) {
			return self::error( 'site_portrait_invalid_body', 'Malformed JSON body.', 400 );
		}
		$pairing = Pairing::get();
		if ( ! isset( $body['pairing_id'] ) || ! is_string( $body['pairing_id'] ) || ! hash_equals( $pairing['pairing_id'], $body['pairing_id'] ) ) {
			return self::error( 'site_portrait_pairing_mismatch', 'Unknown pairing_id.', 409 );
		}
		self::$signer_override = Pairing::site_signer();
		Pairing::forget();
		return array( 'revoked' => true );
	}

	/**
	 * Serialises, signs, logs and sends responses of this namespace
	 * (PROTOCOL.md §5.2). Hooked to rest_pre_serve_request.
	 *
	 * @param bool              $served  Whether already served.
	 * @param \WP_HTTP_Response $result  Response.
	 * @param WP_REST_Request   $request Request.
	 * @param WP_REST_Server    $server  Server.
	 * @return bool
	 */
	public static function serve( $served, $result, $request, $server ) {
		if ( $served || 0 !== strpos( $request->get_route(), '/' . self::NAMESPACE_V1 . '/' ) ) {
			return $served;
		}

		$status = (int) $result->get_status();
		$data   = $server->response_to_data( $result, false );
		$body   = (string) wp_json_encode( $data, JSON_UNESCAPED_SLASHES );
		$digest = Crypto::content_digest( $body );

		header( 'Content-Type: ' . self::CONTENT_TYPE );
		header( 'Cache-Control: no-store' );
		header( 'Site-Portrait-Protocol: 1' );
		header( 'Content-Digest: ' . $digest );
		if ( null !== self::$retry_after ) {
			header( 'Retry-After: ' . (int) self::$retry_after );
		}

		$signer = null !== self::$signer_override ? self::$signer_override : Pairing::site_signer();
		if ( null !== $signer ) {
			$signature = Http_Signature::sign_response(
				$status,
				self::CONTENT_TYPE,
				$digest,
				null !== self::$auth ? self::$auth['signature'] : null,
				$signer['secret'],
				$signer['kid']
			);
			foreach ( $signature as $name => $value ) {
				header( $name . ': ' . $value );
			}
		}

		Access_Log::add(
			array(
				'ip'            => self::client_ip(),
				'method'        => $request->get_method(),
				'endpoint'      => substr( $request->get_route(), strlen( '/' . self::NAMESPACE_V1 ) ),
				'key_id'        => null !== self::$auth ? self::$auth['kid'] : '',
				'scopes'        => self::$log_scopes,
				'status'        => $status,
				'error_code'    => is_array( $data ) && isset( $data['code'] ) && is_string( $data['code'] ) ? $data['code'] : '',
				'authenticated' => null !== self::$auth,
			)
		);

		if ( 'HEAD' !== $request->get_method() ) {
			echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON response body, as WP_REST_Server does.
		}
		return true;
	}

	/**
	 * Rate limit for the current mode (PROTOCOL.md §12.1).
	 *
	 * @return int
	 */
	private static function rate_limit() {
		$limit = self::DEFAULT_RATE_LIMIT;
		if ( Plugin::is_network_mode() ) {
			$limit += 2 * (int) get_blog_count();
		}
		/**
		 * Filters the number of authenticated requests allowed per hour.
		 *
		 * @param int $limit Requests per hour.
		 */
		return max( 1, (int) apply_filters( 'site_portrait_rate_limit', $limit ) );
	}

	/**
	 * Validates the site_id parameter.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return int|null|WP_Error
	 */
	private static function site_id_param( WP_REST_Request $request ) {
		$site_id = $request->get_param( 'site_id' );
		if ( null === $site_id || '' === $site_id ) {
			return null;
		}
		if ( ! Plugin::is_network_mode() || ! is_scalar( $site_id ) || ! ctype_digit( (string) $site_id ) ) {
			return self::error( 'site_portrait_invalid_param', 'Invalid site_id parameter.', 400 );
		}
		$site = get_site( (int) $site_id );
		if ( ! $site || (int) $site->archived || (int) $site->spam || (int) $site->deleted || get_current_network_id() !== (int) $site->site_id ) {
			return self::error( 'site_portrait_unknown_site', 'Unknown site.', 404 );
		}
		return (int) $site_id;
	}

	/**
	 * Path and query of the request exactly as received.
	 *
	 * @return array{path: string, query: string}|null
	 */
	private static function request_target() {
		// The raw value is required to verify the signature; it is validated
		// as printable ASCII and never output or stored.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! is_string( $uri ) || '' === $uri || ! preg_match( '/^[\x21-\x7e]+$/', $uri ) ) {
			return null;
		}
		$parts = explode( '?', $uri, 2 );
		return array(
			'path'  => $parts[0],
			'query' => '?' . ( $parts[1] ?? '' ),
		);
	}

	/**
	 * Client IP address (REMOTE_ADDR unless filtered, PROTOCOL.md §12.2).
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		/**
		 * Filters the client IP address, e.g. behind a trusted reverse proxy.
		 *
		 * @param string $ip REMOTE_ADDR.
		 */
		$ip = (string) apply_filters( 'site_portrait_client_ip', $ip );
		return false !== filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/**
	 * Builds a protocol error.
	 *
	 * Messages are protocol diagnostics for the service, hence not translated.
	 *
	 * @param string $code    Error code.
	 * @param string $message Message.
	 * @param int    $status  HTTP status.
	 * @return WP_Error
	 */
	private static function error( $code, $message, $status ) {
		return new WP_Error( $code, $message, array( 'status' => $status ) );
	}
}
