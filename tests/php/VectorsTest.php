<?php
/**
 * Checks the PHP implementation against the machine-readable test vectors
 * (docs/test-vectors.json, PROTOCOL.md §15).
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\Crypto;
use Site_Portrait\Http_Signature;
use Site_Portrait\Structured_Fields;

final class VectorsTest extends TestCase {

	/**
	 * Decoded vectors file.
	 *
	 * @var array
	 */
	private static $v;

	public static function setUpBeforeClass(): void {
		self::$v = json_decode( file_get_contents( dirname( __DIR__, 2 ) . '/docs/test-vectors.json' ), true );
	}

	private static function keypair( $name ) {
		$pair = sodium_crypto_sign_seed_keypair( hex2bin( self::$v['keys'][ $name ]['seed_hex'] ) );
		return array(
			'public' => sodium_crypto_sign_publickey( $pair ),
			'secret' => sodium_crypto_sign_secretkey( $pair ),
		);
	}

	private static function sf_bytes( $header ) {
		return Structured_Fields::parse_dictionary( $header )['sp']['value'];
	}

	public function test_keys_and_thumbprints() {
		foreach ( self::$v['keys'] as $name => $expected ) {
			$key = self::keypair( $name );
			$this->assertSame( $expected['x'], Crypto::b64url_encode( $key['public'] ), $name );
			$this->assertSame( $expected['kid'], Crypto::thumbprint( $key['public'] ), $name );
		}
	}

	public function test_pkce() {
		$this->assertSame( self::$v['pkce']['code_challenge'], Crypto::pkce_challenge( self::$v['pkce']['code_verifier'] ) );
	}

	public function test_request_vector() {
		$r   = self::$v['request'];
		$key = self::keypair( $r['key'] );
		$kid = self::$v['keys'][ $r['key'] ]['kid'];

		// The published signature base is what was signed.
		$this->assertTrue( sodium_crypto_sign_verify_detached( self::sf_bytes( $r['headers']['Signature'] ), $r['signature_base'], $key['public'] ) );

		$result = Http_Signature::verify_request(
			array(
				'method'    => $r['method'],
				'authority' => $r['authority'],
				'path'      => $r['path'],
				'query'     => $r['query'],
				'headers'   => array(
					'signature-input' => $r['headers']['Signature-Input'],
					'signature'       => $r['headers']['Signature'],
				),
			),
			function ( $k ) use ( $key, $kid ) {
				return $kid === $k ? $key['public'] : null;
			},
			$r['verify_at']
		);
		$this->assertSame( $kid, $result['kid'] );
		$this->assertSame( $r['nonce'], $result['nonce'] );
	}

	public function test_response_vector_signs_identically() {
		$r   = self::$v['response'];
		$key = self::keypair( $r['key'] );

		$this->assertTrue( sodium_crypto_sign_verify_detached( self::sf_bytes( $r['headers']['Signature'] ), $r['signature_base'], $key['public'] ) );
		$this->assertSame( $r['headers']['Content-Digest'], Crypto::content_digest( $r['body'] ) );

		$headers = Http_Signature::sign_response(
			$r['status'],
			$r['content_type'],
			Crypto::content_digest( $r['body'] ),
			self::sf_bytes( self::$v['request']['headers']['Signature'] ),
			$key['secret'],
			self::$v['keys'][ $r['key'] ]['kid'],
			$r['created']
		);
		$this->assertSame( $r['headers']['Signature-Input'], $headers['Signature-Input'] );
		$this->assertSame( $r['headers']['Signature'], $headers['Signature'] );
	}

	public function test_endorsement_vector() {
		$e       = self::$v['endorsement'];
		$signer  = self::keypair( $e['signer'] );
		$new     = self::keypair( $e['endorsed'] );
		$new_kid = Crypto::thumbprint( $new['public'] );
		$s_kid   = self::$v['keys'][ $e['signer'] ]['kid'];

		$this->assertSame( $e['message'], 'site-portrait/1 key-endorsement ' . $new_kid );
		$endorsement = Crypto::endorse( $new_kid, $signer['secret'], $s_kid );
		$this->assertSame( $e['sig'], $endorsement['sig'] );

		$jwk                 = Crypto::public_jwk( $new['public'] );
		$jwk['endorsements'] = array( $endorsement );
		$this->assertTrue( Crypto::is_endorsed( $jwk, array( $s_kid => $signer['public'] ) ) );
		$this->assertFalse( Crypto::is_endorsed( $jwk, array( 'other' => $signer['public'] ) ) );
	}
}
