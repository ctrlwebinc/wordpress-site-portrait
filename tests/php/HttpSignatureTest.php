<?php
/**
 * Request and response signature round trips and failure cases.
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\Crypto;
use Site_Portrait\Http_Signature;
use Site_Portrait\Signature_Error;
use Site_Portrait\Structured_Fields;

final class HttpSignatureTest extends TestCase {

	private $keys;
	private $kid;

	protected function setUp(): void {
		$this->keys = Crypto::generate_keypair();
		$this->kid  = Crypto::thumbprint( $this->keys['public'] );
	}

	private function lookup() {
		return function ( $kid ) {
			return $kid === $this->kid ? $this->keys['public'] : null;
		};
	}

	private function signed_get( $url, $now = 1000000 ) {
		$headers = Http_Signature::sign_request( 'GET', $url, array(), $this->keys['secret'], $this->kid, $now );
		return array(
			'signature-input' => $headers['Signature-Input'],
			'signature'       => $headers['Signature'],
		);
	}

	private function request( array $headers, $overrides = array() ) {
		return array_merge(
			array(
				'method'    => 'GET',
				'authority' => 'example.com',
				'path'      => '/wp-json/site-portrait/v1/status',
				'query'     => '?',
				'headers'   => $headers,
			),
			$overrides
		);
	}

	private function assert_error( $code, callable $fn ) {
		try {
			$fn();
			$this->fail( 'Expected ' . $code );
		} catch ( Signature_Error $e ) {
			$this->assertSame( $code, $e->get_error_code() );
		}
	}

	public function test_round_trip() {
		$headers = $this->signed_get( 'https://example.com/wp-json/site-portrait/v1/status' );
		$result  = Http_Signature::verify_request( $this->request( $headers ), $this->lookup(), 1000010 );
		$this->assertSame( $this->kid, $result['kid'] );
		$this->assertSame( 1000300, $result['expires'] );
	}

	public function test_post_round_trip_covers_digest() {
		$body    = '{"pairing_id":"abc"}';
		$base    = array(
			'content-type'   => 'application/json',
			'content-digest' => Crypto::content_digest( $body ),
		);
		$headers = Http_Signature::sign_request( 'POST', 'https://example.com/x?y=1', $base, $this->keys['secret'], $this->kid, 50 );
		$all     = $base + array(
			'signature-input' => $headers['Signature-Input'],
			'signature'       => $headers['Signature'],
		);
		$result  = Http_Signature::verify_request( $this->request( $all, array( 'method' => 'POST', 'path' => '/x', 'query' => '?y=1' ) ), $this->lookup(), 50 );
		$this->assertSame( $this->kid, $result['kid'] );

		$all['content-digest'] = Crypto::content_digest( '{}' );
		$this->assert_error(
			'site_portrait_signature_invalid',
			function () use ( $all ) {
				Http_Signature::verify_request( $this->request( $all, array( 'method' => 'POST', 'path' => '/x', 'query' => '?y=1' ) ), $this->lookup(), 50 );
			}
		);
	}

	public function test_tampered_components_fail() {
		$headers = $this->signed_get( 'https://example.com/wp-json/site-portrait/v1/portrait?scopes=core' );
		foreach ( array(
			array( 'authority' => 'other.example' ),
			array( 'path' => '/wp-json/site-portrait/v1/status' ),
			array( 'query' => '?scopes=core,database' ),
			array( 'method' => 'HEAD' ),
		) as $override ) {
			$this->assert_error(
				'site_portrait_signature_invalid',
				function () use ( $headers, $override ) {
					Http_Signature::verify_request( $this->request( $headers, array_merge( array( 'path' => '/wp-json/site-portrait/v1/portrait', 'query' => '?scopes=core' ), $override ) ), $this->lookup(), 1000000 );
				}
			);
		}
	}

	public function test_expired_and_future_signatures_fail() {
		$headers = $this->signed_get( 'https://example.com/wp-json/site-portrait/v1/status', 1000000 );
		foreach ( array( 1000300, 1000301, 999699 ) as $now ) {
			$this->assert_error(
				'site_portrait_signature_expired',
				function () use ( $headers, $now ) {
					Http_Signature::verify_request( $this->request( $headers ), $this->lookup(), $now );
				}
			);
		}
	}

	public function test_unknown_key_missing_and_malformed() {
		$headers = $this->signed_get( 'https://example.com/wp-json/site-portrait/v1/status' );
		$this->assert_error(
			'site_portrait_unknown_key',
			function () use ( $headers ) {
				Http_Signature::verify_request( $this->request( $headers ), function () {
					return null;
				}, 1000000 );
			}
		);
		$this->assert_error(
			'site_portrait_signature_missing',
			function () {
				Http_Signature::verify_request( $this->request( array() ), $this->lookup(), 1000000 );
			}
		);
		$this->assert_error(
			'site_portrait_signature_missing',
			function () use ( $headers ) {
				$other = array(
					'signature-input' => str_replace( 'sp=', 'xx=', $headers['signature-input'] ),
					'signature'       => str_replace( 'sp=', 'xx=', $headers['signature'] ),
				);
				Http_Signature::verify_request( $this->request( $other ), $this->lookup(), 1000000 );
			}
		);
		$this->assert_error(
			'site_portrait_signature_malformed',
			function () use ( $headers ) {
				$headers['signature-input'] = 'sp=("@method" "@path");created=1;expires=2;nonce="aaaaaaaaaaaaaaaaaaaa";keyid="k";alg="ed25519";tag="site-portrait/1"';
				Http_Signature::verify_request( $this->request( $headers ), $this->lookup(), 1000000 );
			}
		);
		$this->assert_error(
			'site_portrait_signature_malformed',
			function () use ( $headers ) {
				$headers['signature-input'] = str_replace( 'alg="ed25519"', 'alg="hmac-sha256"', $headers['signature-input'] );
				Http_Signature::verify_request( $this->request( $headers ), $this->lookup(), 1000000 );
			}
		);
		$this->assert_error(
			'site_portrait_signature_malformed',
			function () use ( $headers ) {
				$headers['signature'] = 'sp=:not base64:';
				Http_Signature::verify_request( $this->request( $headers ), $this->lookup(), 1000000 );
			}
		);
	}

	public function test_response_round_trip_and_binding() {
		$body     = '{"a":1}';
		$req_sig  = random_bytes( 64 );
		$digest   = Crypto::content_digest( $body );
		$signed   = Http_Signature::sign_response( 200, 'application/json; charset=UTF-8', $digest, $req_sig, $this->keys['secret'], $this->kid );
		$headers  = array(
			'content-type'    => 'application/json; charset=UTF-8',
			'content-digest'  => $digest,
			'signature-input' => $signed['Signature-Input'],
			'signature'       => $signed['Signature'],
		);
		$this->assertSame( $this->kid, Http_Signature::verify_response( 200, $headers, $body, $req_sig, $this->lookup() ) );

		$this->assert_error(
			'site_portrait_signature_invalid',
			function () use ( $headers, $body ) {
				Http_Signature::verify_response( 200, $headers, $body, random_bytes( 64 ), $this->lookup() );
			}
		);
		$this->assert_error(
			'site_portrait_signature_invalid',
			function () use ( $headers, $body, $req_sig ) {
				Http_Signature::verify_response( 403, $headers, $body, $req_sig, $this->lookup() );
			}
		);
		$this->assert_error(
			'site_portrait_digest_mismatch',
			function () use ( $headers, $req_sig ) {
				Http_Signature::verify_response( 200, $headers, '{"a":2}', $req_sig, $this->lookup() );
			}
		);
	}

	public function test_authority_normalisation() {
		$this->assertSame( 'example.com', Http_Signature::authority( 'https', 'Example.COM', 443 ) );
		$this->assertSame( 'example.com:8443', Http_Signature::authority( 'https', 'example.com', 8443 ) );
		$this->assertSame( 'localhost:9400', Http_Signature::authority( 'http', 'localhost', 9400 ) );
		$this->assertSame( 'example.com', Http_Signature::authority( 'http', 'example.com', 80 ) );
	}
}
