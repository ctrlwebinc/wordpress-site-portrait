<?php
/**
 * Outbound HTTP calls to the service: discovery, code exchange and
 * revocation notice. Only ever triggered by an administrator action.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

use WP_Error;

defined( 'ABSPATH' ) || exit;

/**
 * Talks to the service chosen by the administrator.
 */
final class Service_Client {

	const DISCOVERY_PATH     = '/.well-known/site-portrait';
	const MAX_DISCOVERY_SIZE = 65536;

	/**
	 * Fetches and validates a service's discovery document (PROTOCOL.md §3).
	 *
	 * @param string $input URL or host typed by the administrator.
	 * @return array|WP_Error Normalised discovery data.
	 */
	public static function discover( $input ) {
		$input = trim( (string) $input );
		if ( '' !== $input && ! preg_match( '#^[a-z][a-z0-9+.-]*://#i', $input ) ) {
			$input = 'https://' . $input;
		}
		$origin = Plugin::origin( $input );
		if ( null === $origin || ! Plugin::is_allowed_service_url( $origin ) ) {
			return new WP_Error( 'site_portrait_invalid_service_url', __( 'Enter the HTTPS address of the service, for example https://service.example.', 'ctrlweb-site-portrait' ) );
		}

		$response = self::request( 'GET', $origin . self::DISCOVERY_PATH, null, null, 10, self::MAX_DISCOVERY_SIZE );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( 200 !== $response['status'] ) {
			return new WP_Error(
				'site_portrait_discovery_failed',
				/* translators: %d: HTTP status code. */
				sprintf( __( 'The service did not publish a Site Portrait discovery document (HTTP status %d).', 'ctrlweb-site-portrait' ), $response['status'] )
			);
		}
		$document = json_decode( $response['body'], true );
		if ( ! is_array( $document ) ) {
			return new WP_Error( 'site_portrait_discovery_invalid', __( 'The service discovery document is not valid JSON.', 'ctrlweb-site-portrait' ) );
		}
		return self::validate_discovery( $document, $origin );
	}

	/**
	 * Validates a discovery document and keeps only the expected members.
	 *
	 * @param array  $doc    Decoded document.
	 * @param string $origin Origin it was fetched from.
	 * @return array|WP_Error
	 */
	public static function validate_discovery( array $doc, $origin ) {
		$invalid = static function ( $what ) {
			return new WP_Error(
				'site_portrait_discovery_invalid',
				/* translators: %s: name of the invalid member, e.g. token_endpoint. */
				sprintf( __( 'The service discovery document is invalid (%s).', 'ctrlweb-site-portrait' ), $what )
			);
		};

		if ( ( $doc['protocol'] ?? null ) !== 'site-portrait' ) {
			return $invalid( 'protocol' );
		}
		if ( ! is_array( $doc['protocol_versions'] ?? null ) || ! in_array( '1', $doc['protocol_versions'], true ) ) {
			return new WP_Error( 'site_portrait_discovery_version', __( 'The service does not support version 1 of the Site Portrait protocol.', 'ctrlweb-site-portrait' ) );
		}

		$service = is_array( $doc['service'] ?? null ) ? $doc['service'] : array();
		$name    = isset( $service['name'] ) && is_string( $service['name'] ) ? trim( wp_strip_all_tags( $service['name'] ) ) : '';
		if ( '' === $name ) {
			return $invalid( 'service.name' );
		}

		$same_origin = static function ( $url ) use ( $origin ) {
			return is_string( $url ) && Plugin::origin( $url ) === $origin && Plugin::is_allowed_service_url( $url );
		};
		$any_url     = static function ( $url ) {
			return is_string( $url ) && Plugin::is_allowed_service_url( $url );
		};

		if ( ! $any_url( $service['privacy_policy_url'] ?? null ) ) {
			return $invalid( 'service.privacy_policy_url' );
		}
		foreach ( array( 'authorization_endpoint', 'token_endpoint', 'revocation_endpoint' ) as $endpoint ) {
			if ( ! $same_origin( $doc[ $endpoint ] ?? null ) ) {
				return $invalid( $endpoint );
			}
		}

		$keys = self::parse_jwks( $doc['jwks'] ?? null );
		if ( empty( $keys ) ) {
			return $invalid( 'jwks' );
		}

		$supported = Scopes::sanitize( $doc['scopes_supported'] ?? array() );
		if ( empty( $supported ) ) {
			return $invalid( 'scopes_supported' );
		}
		$requested = isset( $doc['scopes_requested'] ) ? Scopes::sanitize( $doc['scopes_requested'] ) : $supported;

		$reasons = array();
		if ( is_array( $doc['scope_reasons'] ?? null ) ) {
			foreach ( $supported as $scope ) {
				if ( isset( $doc['scope_reasons'][ $scope ] ) && is_string( $doc['scope_reasons'][ $scope ] ) ) {
					$reasons[ $scope ] = self::text( $doc['scope_reasons'][ $scope ], 300 );
				}
			}
		}

		$optional_url = static function ( $url ) use ( $any_url ) {
			return $any_url( $url ) ? esc_url_raw( $url ) : '';
		};

		return array(
			'origin'                 => $origin,
			'name'                   => self::text( $name, 100 ),
			'description'            => isset( $service['description'] ) ? self::text( $service['description'], 500 ) : '',
			'homepage'               => $optional_url( $service['homepage'] ?? null ),
			'privacy_policy_url'     => esc_url_raw( $service['privacy_policy_url'] ),
			'terms_url'              => $optional_url( $service['terms_url'] ?? null ),
			'contact'                => isset( $service['contact'] ) ? self::text( $service['contact'], 200 ) : '',
			'authorization_endpoint' => esc_url_raw( $doc['authorization_endpoint'] ),
			'token_endpoint'         => esc_url_raw( $doc['token_endpoint'] ),
			'revocation_endpoint'    => esc_url_raw( $doc['revocation_endpoint'] ),
			'scopes_supported'       => $supported,
			'scopes_requested'       => $requested,
			'scope_reasons'          => $reasons,
			'keys'                   => $keys,
		);
	}

	/**
	 * Parses a JWKS, keeping valid Ed25519 keys.
	 *
	 * @param mixed $jwks Decoded JWKS.
	 * @return array Map of kid => JWK (kty, crv, x, kid, and endorsements when present).
	 */
	public static function parse_jwks( $jwks ) {
		$keys = array();
		if ( ! is_array( $jwks ) || ! is_array( $jwks['keys'] ?? null ) ) {
			return $keys;
		}
		foreach ( array_slice( $jwks['keys'], 0, 10 ) as $jwk ) {
			$public = Crypto::public_key_from_jwk( $jwk );
			if ( null === $public ) {
				continue;
			}
			$clean = Crypto::public_jwk( $public );
			if ( isset( $jwk['endorsements'] ) && is_array( $jwk['endorsements'] ) ) {
				$clean['endorsements'] = $jwk['endorsements'];
			}
			$keys[ $clean['kid'] ] = $clean;
		}
		return $keys;
	}

	/**
	 * Performs an HTTP request, optionally signed (PROTOCOL.md §5.1).
	 *
	 * @param string     $method   Method.
	 * @param string     $url      URL.
	 * @param array|null $body     JSON body.
	 * @param array|null $signer   Keys: secret (raw), kid.
	 * @param int        $timeout  Timeout in seconds.
	 * @param int        $max_size Maximum response size.
	 * @return array|WP_Error Keys: status, body, headers.
	 */
	public static function request( $method, $url, $body = null, $signer = null, $timeout = 15, $max_size = 1048576 ) {
		if ( ! Plugin::is_allowed_service_url( $url ) ) {
			return new WP_Error( 'site_portrait_invalid_service_url', __( 'The service address must use HTTPS.', 'ctrlweb-site-portrait' ) );
		}

		$headers = array(
			'Accept'     => 'application/json',
			'User-Agent' => 'SitePortrait/' . SITE_PORTRAIT_VERSION . '; ' . Plugin::home_url(),
		);
		$args    = array(
			'method'              => $method,
			'timeout'             => $timeout,
			'redirection'         => 0,
			'limit_response_size' => $max_size,
			'headers'             => $headers,
		);

		if ( null !== $body ) {
			$args['body']                      = wp_json_encode( $body, JSON_UNESCAPED_SLASHES );
			$args['headers']['Content-Type']   = 'application/json';
			$args['headers']['Content-Digest'] = Crypto::content_digest( $args['body'] );
		}
		if ( null !== $signer ) {
			$args['headers'] += Http_Signature::sign_request(
				$method,
				$url,
				array_change_key_case( $args['headers'], CASE_LOWER ),
				$signer['secret'],
				$signer['kid']
			);
		}

		// Development mode targets local hosts, which wp_safe_remote_request() rejects.
		$response = Plugin::is_dev_mode() ? wp_remote_request( $url, $args ) : wp_safe_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return new WP_Error(
				'site_portrait_http_error',
				/* translators: %s: error message. */
				sprintf( __( 'Could not reach the service: %s', 'ctrlweb-site-portrait' ), $response->get_error_message() )
			);
		}

		return array(
			'status'  => (int) wp_remote_retrieve_response_code( $response ),
			'body'    => (string) wp_remote_retrieve_body( $response ),
			'headers' => wp_remote_retrieve_headers( $response ),
		);
	}

	/**
	 * Builds an error from an OAuth-style error response.
	 *
	 * @param array  $response Response from request().
	 * @param string $context  What failed, for the message.
	 * @return WP_Error
	 */
	public static function error_from_response( array $response, $context ) {
		$data   = json_decode( $response['body'], true );
		$detail = '';
		if ( is_array( $data ) && isset( $data['error'] ) && is_string( $data['error'] ) ) {
			$detail = self::text( $data['error'], 64 );
			if ( isset( $data['error_description'] ) && is_string( $data['error_description'] ) ) {
				$detail .= ': ' . self::text( $data['error_description'], 300 );
			}
		}
		return new WP_Error(
			'site_portrait_service_error',
			sprintf(
				/* translators: 1: what failed, 2: HTTP status code, 3: error details from the service. */
				__( '%1$s failed (HTTP %2$d). %3$s', 'ctrlweb-site-portrait' ),
				$context,
				$response['status'],
				$detail
			)
		);
	}

	/**
	 * Normalises untrusted plain text from the service.
	 *
	 * @param string $text   Text.
	 * @param int    $length Maximum length.
	 * @return string
	 */
	public static function text( $text, $length ) {
		$text = sanitize_text_field( (string) $text );
		return function_exists( 'mb_substr' ) ? mb_substr( $text, 0, $length ) : substr( $text, 0, $length );
	}
}
