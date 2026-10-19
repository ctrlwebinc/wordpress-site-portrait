<?php
/**
 * RFC 9421 HTTP Message Signatures with Ed25519, restricted to the profile
 * defined in PROTOCOL.md §5. Free of WordPress dependencies for unit testing.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Creates and verifies signatures.
 */
final class Http_Signature {

	const LABEL     = 'sp';
	const TAG       = 'site-portrait/1';
	const ALG       = 'ed25519';
	const MAX_SKEW  = 300;
	const MAX_TTL   = 300;
	const NONCE_RE  = '/^[A-Za-z0-9_-]{16,64}$/';
	const GET_LIST  = array( '@method', '@authority', '@path', '@query' );
	const POST_LIST = array( '@method', '@authority', '@path', '@query', 'content-type', 'content-digest' );
	const RESP_LIST = array( '@status', 'content-type', 'content-digest' );

	/**
	 * Signs an outgoing request.
	 *
	 * @param string   $method     HTTP method.
	 * @param string   $url        Absolute target URL.
	 * @param array    $headers    Lower-case header name => value; must contain
	 *                             content-type and content-digest when a body is sent.
	 * @param string   $secret_key Raw secret key.
	 * @param string   $kid        Key id.
	 * @param int|null $now        Current time (for tests).
	 * @return array Headers to add: Signature-Input and Signature.
	 */
	public static function sign_request( $method, $url, array $headers, $secret_key, $kid, $now = null ) {
		$now     = null === $now ? time() : (int) $now;
		$method  = strtoupper( $method );
		$context = self::request_context_from_url( $method, $url, $headers );
		$list    = self::has_body( $method ) ? self::POST_LIST : self::GET_LIST;

		$params = array(
			'created' => array(
				'type'  => 'integer',
				'value' => $now,
			),
			'expires' => array(
				'type'  => 'integer',
				'value' => $now + self::MAX_TTL,
			),
			'nonce'   => array(
				'type'  => 'string',
				'value' => Crypto::random_token( 24 ),
			),
			'keyid'   => array(
				'type'  => 'string',
				'value' => $kid,
			),
			'alg'     => array(
				'type'  => 'string',
				'value' => self::ALG,
			),
			'tag'     => array(
				'type'  => 'string',
				'value' => self::TAG,
			),
		);

		$items = array_map(
			array( Structured_Fields::class, 'string_item' ),
			$list
		);

		return self::sign_items( $items, $params, $context, null, $secret_key );
	}

	/**
	 * Signs a response, optionally bound to the request signature.
	 *
	 * @param int         $status            HTTP status.
	 * @param string      $content_type      Content-Type header value.
	 * @param string      $content_digest    Content-Digest header value.
	 * @param string|null $request_signature Raw request signature (label sp), or null.
	 * @param string      $secret_key        Raw secret key.
	 * @param string      $kid               Key id.
	 * @param int|null    $now               Current time (for tests).
	 * @return array Headers to add: Signature-Input and Signature.
	 */
	public static function sign_response( $status, $content_type, $content_digest, $request_signature, $secret_key, $kid, $now = null ) {
		$now     = null === $now ? time() : (int) $now;
		$context = array(
			'@status' => (string) (int) $status,
			'headers' => array(
				'content-type'   => $content_type,
				'content-digest' => $content_digest,
			),
		);
		$items   = array_map( array( Structured_Fields::class, 'string_item' ), self::RESP_LIST );

		$request_context = null;
		if ( null !== $request_signature ) {
			$items[]         = self::request_binding_item();
			$request_context = array( 'signature' => array( self::LABEL => $request_signature ) );
		}

		$params = array(
			'created' => array(
				'type'  => 'integer',
				'value' => $now,
			),
			'keyid'   => array(
				'type'  => 'string',
				'value' => $kid,
			),
			'alg'     => array(
				'type'  => 'string',
				'value' => self::ALG,
			),
			'tag'     => array(
				'type'  => 'string',
				'value' => self::TAG,
			),
		);

		return self::sign_items( $items, $params, $context, $request_context, $secret_key );
	}

	/**
	 * Verifies an incoming request signed per PROTOCOL.md §5.1.
	 *
	 * @param array    $request    Keys: method, authority, path, query (with
	 *                             leading "?"), headers (lower-case name => value).
	 * @param callable $key_lookup Receives a key id, returns a raw public key or null.
	 * @param int|null $now        Current time (for tests).
	 * @return array Keys: kid, nonce, created, expires, signature (raw bytes).
	 * @throws Signature_Error When verification fails.
	 */
	public static function verify_request( array $request, callable $key_lookup, $now = null ) {
		$now     = null === $now ? time() : (int) $now;
		$headers = $request['headers'];
		$method  = strtoupper( $request['method'] );

		if ( ! isset( $headers['signature-input'], $headers['signature'] ) ) {
			throw new Signature_Error( 'site_portrait_signature_missing', 'The request is not signed.' );
		}

		$inputs     = Structured_Fields::parse_dictionary( $headers['signature-input'] );
		$signatures = Structured_Fields::parse_dictionary( $headers['signature'] );
		if ( null === $inputs || null === $signatures ) {
			throw new Signature_Error( 'site_portrait_signature_malformed', 'The signature fields cannot be parsed.' );
		}
		if ( ! isset( $inputs[ self::LABEL ] ) || ! isset( $signatures[ self::LABEL ] ) ) {
			throw new Signature_Error( 'site_portrait_signature_missing', 'No signature labelled "sp".' );
		}

		$input     = $inputs[ self::LABEL ];
		$signature = $signatures[ self::LABEL ];
		if ( 'inner_list' !== $input['type'] || 'bytes' !== $signature['type'] ) {
			throw new Signature_Error( 'site_portrait_signature_malformed', 'Unexpected signature field types.' );
		}

		$covered = array();
		foreach ( $input['value'] as $item ) {
			if ( 'string' !== $item['type'] || ! empty( $item['params'] ) ) {
				throw new Signature_Error( 'site_portrait_signature_malformed', 'Unexpected covered component.' );
			}
			$covered[] = $item['value'];
		}
		$expected = self::has_body( $method ) ? self::POST_LIST : self::GET_LIST;
		if ( $covered !== $expected ) {
			throw new Signature_Error( 'site_portrait_signature_malformed', 'Covered components must be: ' . implode( ' ', $expected ) . '.' ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Returned in a JSON error body, never HTML.
		}

		$params = $input['params'];
		foreach ( array(
			'created' => 'integer',
			'expires' => 'integer',
			'nonce'   => 'string',
			'keyid'   => 'string',
			'alg'     => 'string',
			'tag'     => 'string',
		) as $name => $type ) {
			if ( ! isset( $params[ $name ] ) || $params[ $name ]['type'] !== $type ) {
				throw new Signature_Error( 'site_portrait_signature_malformed', sprintf( 'Signature parameter "%s" is missing or invalid.', $name ) ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Returned in a JSON error body, never HTML.
			}
		}
		if ( self::ALG !== $params['alg']['value'] || self::TAG !== $params['tag']['value'] ) {
			throw new Signature_Error( 'site_portrait_signature_malformed', 'Unsupported alg or tag.' );
		}
		if ( ! preg_match( self::NONCE_RE, $params['nonce']['value'] ) ) {
			throw new Signature_Error( 'site_portrait_signature_malformed', 'Invalid nonce.' );
		}

		$created = $params['created']['value'];
		$expires = $params['expires']['value'];
		if ( abs( $now - $created ) > self::MAX_SKEW || $expires <= $created || $expires > $created + self::MAX_TTL || $now >= $expires ) {
			throw new Signature_Error( 'site_portrait_signature_expired', 'The signature is outside its validity window.' );
		}

		$kid        = $params['keyid']['value'];
		$public_key = call_user_func( $key_lookup, $kid );
		if ( null === $public_key ) {
			throw new Signature_Error( 'site_portrait_unknown_key', 'Unknown key id.' );
		}

		$context = array(
			'@method'    => $method,
			'@authority' => $request['authority'],
			'@path'      => $request['path'],
			'@query'     => $request['query'],
			'headers'    => $headers,
		);
		$base    = self::signature_base( $input['value'], $params, $context, null );
		if ( null === $base || ! Crypto::verify( $signature['value'], $base, $public_key ) ) {
			throw new Signature_Error( 'site_portrait_signature_invalid', 'Signature verification failed.' );
		}

		return array(
			'kid'       => $kid,
			'nonce'     => $params['nonce']['value'],
			'created'   => $created,
			'expires'   => $expires,
			'signature' => $signature['value'],
		);
	}

	/**
	 * Verifies a response signature (used by clients and tests).
	 *
	 * @param int         $status            HTTP status.
	 * @param array       $headers           Lower-case header name => value.
	 * @param string      $body              Response body.
	 * @param string|null $request_signature Raw request signature, if the request was signed.
	 * @param callable    $key_lookup        Receives a key id, returns a raw public key or null.
	 * @return string Key id that signed the response.
	 * @throws Signature_Error When verification fails.
	 */
	public static function verify_response( $status, array $headers, $body, $request_signature, callable $key_lookup ) {
		$inputs     = Structured_Fields::parse_dictionary( $headers['signature-input'] ?? '' );
		$signatures = Structured_Fields::parse_dictionary( $headers['signature'] ?? '' );
		if ( empty( $inputs[ self::LABEL ] ) || empty( $signatures[ self::LABEL ] ) || 'bytes' !== $signatures[ self::LABEL ]['type'] || 'inner_list' !== $inputs[ self::LABEL ]['type'] ) {
			throw new Signature_Error( 'site_portrait_signature_missing', 'The response is not signed.' );
		}
		// A 2xx response to a signed request must be bound to it; error
		// responses to unauthenticated requests are not (PROTOCOL.md §5.2).
		$input   = $inputs[ self::LABEL ];
		$unbound = array_map( array( Structured_Fields::class, 'string_item' ), self::RESP_LIST );
		$bound   = array_merge( $unbound, array( self::request_binding_item() ) );
		if ( null === $request_signature ) {
			$allowed = array( $unbound );
		} elseif ( $status >= 200 && $status < 300 ) {
			$allowed = array( $bound );
		} else {
			$allowed = array( $bound, $unbound );
		}
		if ( ! in_array( $input['value'], $allowed, true ) ) {
			throw new Signature_Error( 'site_portrait_signature_malformed', 'Unexpected covered components in response.' );
		}
		if ( $input['value'] === $unbound ) {
			$request_signature = null;
		}
		if ( ! hash_equals( Crypto::content_digest( $body ), trim( $headers['content-digest'] ?? '' ) ) ) {
			throw new Signature_Error( 'site_portrait_digest_mismatch', 'Content-Digest does not match the body.', 400 );
		}
		$kid = $input['params']['keyid']['value'] ?? null;
		$key = is_string( $kid ) ? call_user_func( $key_lookup, $kid ) : null;
		if ( null === $key ) {
			throw new Signature_Error( 'site_portrait_unknown_key', 'Unknown response key id.' );
		}
		$context         = array(
			'@status' => (string) (int) $status,
			'headers' => $headers,
		);
		$request_context = null === $request_signature ? null : array( 'signature' => array( self::LABEL => $request_signature ) );
		$base            = self::signature_base( $input['value'], $input['params'], $context, $request_context );
		if ( null === $base || ! Crypto::verify( $signatures[ self::LABEL ]['value'], $base, $key ) ) {
			throw new Signature_Error( 'site_portrait_signature_invalid', 'Response signature verification failed.' );
		}
		return $kid;
	}

	/**
	 * Covered component binding a response to the request signature:
	 * "signature";req;key="sp".
	 *
	 * @return array
	 */
	private static function request_binding_item() {
		return Structured_Fields::string_item(
			'signature',
			array(
				'req' => array(
					'type'  => 'boolean',
					'value' => true,
				),
				'key' => array(
					'type'  => 'string',
					'value' => self::LABEL,
				),
			)
		);
	}

	/**
	 * Builds a request context from a URL.
	 *
	 * @param string $method  Method.
	 * @param string $url     URL.
	 * @param array  $headers Headers.
	 * @return array
	 */
	public static function request_context_from_url( $method, $url, array $headers ) {
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Kept free of WordPress dependencies.
		return array(
			'@method'    => strtoupper( $method ),
			'@authority' => self::authority( $parts['scheme'] ?? 'https', $parts['host'] ?? '', $parts['port'] ?? null ),
			'@path'      => isset( $parts['path'] ) && '' !== $parts['path'] ? $parts['path'] : '/',
			'@query'     => '?' . ( $parts['query'] ?? '' ),
			'headers'    => $headers,
		);
	}

	/**
	 * Normalises an authority (lower-case host, port only if not default).
	 *
	 * @param string   $scheme Scheme.
	 * @param string   $host   Host.
	 * @param int|null $port   Port.
	 * @return string
	 */
	public static function authority( $scheme, $host, $port = null ) {
		$authority = strtolower( $host );
		$default   = 'http' === strtolower( $scheme ) ? 80 : 443;
		if ( null !== $port && (int) $port !== $default ) {
			$authority .= ':' . (int) $port;
		}
		return $authority;
	}

	/**
	 * Whether requests with this method carry a body (and the POST component list).
	 *
	 * @param string $method Method.
	 * @return bool
	 */
	private static function has_body( $method ) {
		return ! in_array( strtoupper( $method ), array( 'GET', 'HEAD' ), true );
	}

	/**
	 * Signs a list of covered components.
	 *
	 * @param array      $items           Covered component items.
	 * @param array      $params          Signature parameters.
	 * @param array      $context         Message context.
	 * @param array|null $request_context Related request context (for ;req).
	 * @param string     $secret_key      Raw secret key.
	 * @return array
	 * @throws \InvalidArgumentException If a component is missing from the message.
	 */
	private static function sign_items( array $items, array $params, array $context, $request_context, $secret_key ) {
		$base = self::signature_base( $items, $params, $context, $request_context );
		if ( null === $base ) {
			throw new \InvalidArgumentException( 'A covered component is missing from the message.' );
		}
		return array(
			'Signature-Input' => self::LABEL . '=' . Structured_Fields::serialize_inner_list( $items, $params ),
			'Signature'       => self::LABEL . '=' . Structured_Fields::serialize_bare( 'bytes', Crypto::sign( $base, $secret_key ) ),
		);
	}

	/**
	 * Builds the RFC 9421 signature base.
	 *
	 * @param array      $items           Covered component items.
	 * @param array      $params          Signature parameters.
	 * @param array      $context         Message context: derived components and headers.
	 * @param array|null $request_context Related request context (for ;req components).
	 * @return string|null Null when a component is missing.
	 */
	public static function signature_base( array $items, array $params, array $context, $request_context ) {
		$lines = array();
		$seen  = array();
		foreach ( $items as $item ) {
			$identifier = Structured_Fields::serialize_bare( 'string', $item['value'] ) . Structured_Fields::serialize_params( $item['params'] ?? array() );
			if ( isset( $seen[ $identifier ] ) ) {
				return null;
			}
			$seen[ $identifier ] = true;

			$name = strtolower( $item['value'] );
			if ( isset( $item['params']['req'] ) ) {
				// Only "signature";req;key="<label>" is supported, as defined in PROTOCOL.md §5.2.
				$label = $item['params']['key']['value'] ?? null;
				if ( 'signature' !== $name || null === $request_context || ! isset( $request_context['signature'][ $label ] ) ) {
					return null;
				}
				$value = Structured_Fields::serialize_bare( 'bytes', $request_context['signature'][ $label ] );
			} elseif ( '@' === substr( $name, 0, 1 ) ) {
				if ( ! isset( $context[ $name ] ) ) {
					return null;
				}
				$value = $context[ $name ];
			} else {
				if ( ! isset( $context['headers'][ $name ] ) ) {
					return null;
				}
				$value = trim( $context['headers'][ $name ] );
			}
			$lines[] = $identifier . ': ' . $value;
		}
		$lines[] = '"@signature-params": ' . Structured_Fields::serialize_inner_list( $items, $params );
		return implode( "\n", $lines );
	}
}
