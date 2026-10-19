<?php
/**
 * RFC 8941 dictionary parsing.
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\Structured_Fields;

final class StructuredFieldsTest extends TestCase {

	public function test_parses_signature_input() {
		$dict = Structured_Fields::parse_dictionary( 'sp=("@method" "@path");created=12;keyid="a\\"b";flag, other=:aGk=:' );
		$this->assertSame( array( 'sp', 'other' ), array_keys( $dict ) );
		$this->assertSame( 'inner_list', $dict['sp']['type'] );
		$this->assertSame( array( '@method', '@path' ), array_column( $dict['sp']['value'], 'value' ) );
		$this->assertSame( 12, $dict['sp']['params']['created']['value'] );
		$this->assertSame( 'a"b', $dict['sp']['params']['keyid']['value'] );
		$this->assertTrue( $dict['sp']['params']['flag']['value'] );
		$this->assertSame( 'hi', $dict['other']['value'] );
	}

	public function test_serialization_round_trip() {
		$input = '("@status" "signature";req;key="sp");created=5;tag="x/1"';
		$dict  = Structured_Fields::parse_dictionary( 'sp=' . $input );
		$this->assertSame( $input, Structured_Fields::serialize_inner_list( $dict['sp']['value'], $dict['sp']['params'] ) );
	}

	/**
	 * @dataProvider invalid_inputs
	 */
	public function test_rejects_invalid( $input ) {
		$this->assertNull( Structured_Fields::parse_dictionary( $input ) );
	}

	public function invalid_inputs() {
		return array(
			array( 'sp=("a" "b"' ),
			array( 'Sp=1' ),
			array( 'sp=1,' ),
			array( 'sp="unterminated' ),
			array( 'sp=:!!:' ),
			array( 'sp=("a""b")' ),
			array( "sp=\"\x01\"" ),
		);
	}
}
