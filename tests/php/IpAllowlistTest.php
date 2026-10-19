<?php
/**
 * IP allow-list.
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\Ip_Allowlist;

final class IpAllowlistTest extends TestCase {

	public function test_parse() {
		$parsed = Ip_Allowlist::parse( "203.0.113.10\n198.51.100.0/24, 2001:DB8::/32\nnope 10.0.0.0/33" );
		$this->assertSame( array( '203.0.113.10', '198.51.100.0/24', '2001:db8::/32' ), $parsed['valid'] );
		$this->assertSame( array( 'nope', '10.0.0.0/33' ), $parsed['invalid'] );
	}

	public function test_matches() {
		$list = array( '203.0.113.10', '198.51.100.0/22', '2001:db8::/32' );
		$this->assertTrue( Ip_Allowlist::matches( '203.0.113.10', $list ) );
		$this->assertFalse( Ip_Allowlist::matches( '203.0.113.11', $list ) );
		$this->assertTrue( Ip_Allowlist::matches( '198.51.103.255', $list ) );
		$this->assertFalse( Ip_Allowlist::matches( '198.51.104.0', $list ) );
		$this->assertTrue( Ip_Allowlist::matches( '2001:db8:1::5', $list ) );
		$this->assertFalse( Ip_Allowlist::matches( '2001:db9::1', $list ) );
		$this->assertFalse( Ip_Allowlist::matches( '', $list ) );
		$this->assertTrue( Ip_Allowlist::matches( '10.1.2.3', array( '0.0.0.0/0' ) ) );
	}
}
