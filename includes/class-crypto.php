<?php
/**
 * Ed25519 keys, JWK helpers and key endorsements.
 *
 * Relies on PHP's sodium extension or the sodium_compat polyfill bundled with
 * WordPress. No WordPress function is used so the class can be unit tested.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Cryptographic primitives used by the protocol.
 */
final class Crypto {

	/**
	 * Prefix of the message signed to endorse a new key (PROTOCOL.md §11).
	 */
	const ENDORSEMENT_PREFIX = 'site-portrait/1 key-endorsement ';

	/**
	 * Encodes binary data as base64url without padding.
	 *
	 * @param string $data Binary data.
	 * @return string
	 */
	public static function b64url_encode( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Encoding keys and signatures, not obfuscation.
	}

	/**
	 * Decodes unpadded base64url. Returns null on invalid input.
	 *
	 * @param string $data Encoded data.
	 * @return string|null
	 */
	public static function b64url_decode( $data ) {
		if ( ! is_string( $data ) || ! preg_match( '/^[A-Za-z0-9_-]*$/', $data ) || 1 === strlen( $data ) % 4 ) {
			return null;
		}
		$decoded = base64_decode( strtr( $data, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding keys and signatures, not obfuscation.
		return false === $decoded ? null : $decoded;
	}

	/**
	 * Returns a URL-safe random token.
	 *
	 * @param int $bytes Number of random bytes.
	 * @return string
	 */
	public static function random_token( $bytes = 32 ) {
		return self::b64url_encode( random_bytes( $bytes ) );
	}

	/**
	 * Generates a new Ed25519 key pair.
	 *
	 * @return array{public: string, secret: string} Raw binary keys.
	 */
	public static function generate_keypair() {
		$pair = sodium_crypto_sign_keypair();
		return array(
			'public' => sodium_crypto_sign_publickey( $pair ),
			'secret' => sodium_crypto_sign_secretkey( $pair ),
		);
	}

	/**
	 * Computes the RFC 7638 thumbprint of an Ed25519 public key.
	 *
	 * @param string $public_key Raw 32-byte public key.
	 * @return string base64url thumbprint, used as key id.
	 */
	public static function thumbprint( $public_key ) {
		$canonical = '{"crv":"Ed25519","kty":"OKP","x":"' . self::b64url_encode( $public_key ) . '"}';
		return self::b64url_encode( hash( 'sha256', $canonical, true ) );
	}

	/**
	 * Builds the public JWK of a raw public key.
	 *
	 * @param string $public_key Raw 32-byte public key.
	 * @return array
	 */
	public static function public_jwk( $public_key ) {
		return array(
			'kty' => 'OKP',
			'crv' => 'Ed25519',
			'x'   => self::b64url_encode( $public_key ),
			'kid' => self::thumbprint( $public_key ),
		);
	}

	/**
	 * Extracts and validates the raw public key of a JWK.
	 *
	 * When the JWK has a kid it must equal the thumbprint.
	 *
	 * @param mixed $jwk Decoded JWK.
	 * @return string|null Raw public key, or null if invalid.
	 */
	public static function public_key_from_jwk( $jwk ) {
		if ( ! is_array( $jwk ) || ( $jwk['kty'] ?? null ) !== 'OKP' || ( $jwk['crv'] ?? null ) !== 'Ed25519' || ! isset( $jwk['x'] ) ) {
			return null;
		}
		$key = self::b64url_decode( $jwk['x'] );
		if ( null === $key || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $key ) ) {
			return null;
		}
		if ( isset( $jwk['kid'] ) && ! hash_equals( self::thumbprint( $key ), (string) $jwk['kid'] ) ) {
			return null;
		}
		return $key;
	}

	/**
	 * Signs a message.
	 *
	 * @param string $message    Message.
	 * @param string $secret_key Raw 64-byte secret key.
	 * @return string Raw 64-byte signature.
	 */
	public static function sign( $message, $secret_key ) {
		return sodium_crypto_sign_detached( $message, $secret_key );
	}

	/**
	 * Verifies a signature, never throwing.
	 *
	 * @param string $signature  Raw signature.
	 * @param string $message    Message.
	 * @param string $public_key Raw public key.
	 * @return bool
	 */
	public static function verify( $signature, $message, $public_key ) {
		if ( ! is_string( $signature ) || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $signature ) || ! is_string( $public_key ) || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $public_key ) ) {
			return false;
		}
		try {
			return sodium_crypto_sign_verify_detached( $signature, $message, $public_key );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Creates an endorsement of a new key by a trusted key (PROTOCOL.md §11).
	 *
	 * @param string $new_kid           Thumbprint of the endorsed key.
	 * @param string $signer_secret_key Raw secret key of the trusted key.
	 * @param string $signer_kid        Thumbprint of the trusted key.
	 * @return array{kid: string, sig: string}
	 */
	public static function endorse( $new_kid, $signer_secret_key, $signer_kid ) {
		return array(
			'kid' => $signer_kid,
			'sig' => self::b64url_encode( self::sign( self::ENDORSEMENT_PREFIX . $new_kid, $signer_secret_key ) ),
		);
	}

	/**
	 * Tells whether a JWK carries a valid endorsement by one of the trusted keys.
	 *
	 * @param array $jwk          Candidate JWK (must have a valid kid).
	 * @param array $trusted_keys Map of kid => raw public key.
	 * @return bool
	 */
	public static function is_endorsed( array $jwk, array $trusted_keys ) {
		$key = self::public_key_from_jwk( $jwk );
		if ( null === $key || empty( $jwk['endorsements'] ) || ! is_array( $jwk['endorsements'] ) ) {
			return false;
		}
		$message = self::ENDORSEMENT_PREFIX . self::thumbprint( $key );
		foreach ( $jwk['endorsements'] as $endorsement ) {
			if ( ! is_array( $endorsement ) || ! isset( $endorsement['kid'], $endorsement['sig'] ) || ! is_string( $endorsement['kid'] ) ) {
				continue;
			}
			if ( ! isset( $trusted_keys[ $endorsement['kid'] ] ) ) {
				continue;
			}
			$signature = self::b64url_decode( $endorsement['sig'] );
			if ( null !== $signature && self::verify( $signature, $message, $trusted_keys[ $endorsement['kid'] ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Computes a PKCE S256 code challenge.
	 *
	 * @param string $verifier Code verifier.
	 * @return string
	 */
	public static function pkce_challenge( $verifier ) {
		return self::b64url_encode( hash( 'sha256', $verifier, true ) );
	}

	/**
	 * Computes an RFC 9530 Content-Digest header value (sha-256).
	 *
	 * @param string $body Message body.
	 * @return string
	 */
	public static function content_digest( $body ) {
		return 'sha-256=:' . base64_encode( hash( 'sha256', $body, true ) ) . ':'; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 9530 digest.
	}
}
