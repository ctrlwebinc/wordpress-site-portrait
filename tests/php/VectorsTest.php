<?php
/**
 * Checks the PHP implementation against the test vectors in PROTOCOL.md §15.
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\Crypto;
use Site_Portrait\Http_Signature;
use Site_Portrait\Structured_Fields;

final class VectorsTest extends TestCase {

	const SERVICE_X   = 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w';
	const SERVICE_KID = 'UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4';
	const SITE_X      = 'gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q';
	const SITE_KID    = 'aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU';
	const REQ_INPUT   = 'sp=("@method" "@authority" "@path" "@query");created=1792400000;expires=1792400300;nonce="bWFkZS1mb3ItdGVzdGluZw";keyid="UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4";alg="ed25519";tag="site-portrait/1"';
	const REQ_SIG     = 'sp=:BCOf82rkgP/WyuEMhL+8EJn9P9Z8Z0quKfLY2ghLzkiuICoNAMWZVBhJYbbelfkE/zEbDgzBXlqyFAwD50oNBA==:';

	private static function seed_keypair( $byte ) {
		$pair = sodium_crypto_sign_seed_keypair( str_repeat( chr( $byte ), 32 ) );
		return array(
			'public' => sodium_crypto_sign_publickey( $pair ),
			'secret' => sodium_crypto_sign_secretkey( $pair ),
		);
	}

	public function test_keys_and_thumbprints() {
		$service = self::seed_keypair( 1 );
		$site    = self::seed_keypair( 2 );
		$this->assertSame( self::SERVICE_X, Crypto::b64url_encode( $service['public'] ) );
		$this->assertSame( self::SERVICE_KID, Crypto::thumbprint( $service['public'] ) );
		$this->assertSame( self::SITE_X, Crypto::b64url_encode( $site['public'] ) );
		$this->assertSame( self::SITE_KID, Crypto::thumbprint( $site['public'] ) );
	}

	public function test_pkce() {
		$this->assertSame( 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Crypto::pkce_challenge( 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' ) );
	}

	public function test_request_vector_verifies() {
		$service = self::seed_keypair( 1 );
		$result  = Http_Signature::verify_request(
			array(
				'method'    => 'GET',
				'authority' => 'example.com',
				'path'      => '/wp-json/site-portrait/v1/portrait',
				'query'     => '?scopes=core,plugins',
				'headers'   => array(
					'signature-input' => self::REQ_INPUT,
					'signature'       => self::REQ_SIG,
				),
			),
			function ( $kid ) use ( $service ) {
				return self::SERVICE_KID === $kid ? $service['public'] : null;
			},
			1792400010
		);
		$this->assertSame( self::SERVICE_KID, $result['kid'] );
		$this->assertSame( 'bWFkZS1mb3ItdGVzdGluZw', $result['nonce'] );
	}

	public function test_response_vector_signs_identically() {
		$site    = self::seed_keypair( 2 );
		$req_sig = Structured_Fields::parse_dictionary( self::REQ_SIG )['sp']['value'];
		$headers = Http_Signature::sign_response(
			200,
			'application/json; charset=UTF-8',
			Crypto::content_digest( '{"ok":true}' ),
			$req_sig,
			$site['secret'],
			self::SITE_KID,
			1792400001
		);
		$this->assertSame( 'sp=:RB+R308P9gAS41M/lWK4oVEiAGNAuSReP3aOzmo55wNQIbGs9V7R2G10u9kagVAP8WMv2Q3vAa1UBGetZtQZDQ==:', $headers['Signature'] );
		$this->assertSame( 'sha-256=:QGLtr3UPuAdOfoPgyQKMlOMkaKi28WFHdDKO8EUVD5M=:', Crypto::content_digest( '{"ok":true}' ) );
	}

	public function test_endorsement_vector() {
		$service = self::seed_keypair( 1 );
		$new     = self::seed_keypair( 3 );
		$this->assertSame( 'nRIE2VmKdMjL1JD7tbV7fXVgXxmv0GKnMFWRUJMTf9Q', Crypto::thumbprint( $new['public'] ) );
		$endorsement = Crypto::endorse( Crypto::thumbprint( $new['public'] ), $service['secret'], self::SERVICE_KID );
		$this->assertSame( '2whhMLNOI50wh8SQIwO-ka3zfQUduDeJYsuolyt7xJfMEsjlwPwEatNVosebORX9LcMcoGiCOvfF6qI8QJQfBA', $endorsement['sig'] );

		$jwk                 = Crypto::public_jwk( $new['public'] );
		$jwk['endorsements'] = array( $endorsement );
		$this->assertTrue( Crypto::is_endorsed( $jwk, array( self::SERVICE_KID => $service['public'] ) ) );
		$this->assertFalse( Crypto::is_endorsed( $jwk, array( 'other' => $service['public'] ) ) );
	}
}
