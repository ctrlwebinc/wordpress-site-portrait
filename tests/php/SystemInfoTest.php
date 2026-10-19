<?php
/**
 * /proc and cgroup parsing with fixtures.
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\System_Info;

final class SystemInfoTest extends TestCase {

	public function test_cgroup_v2_container() {
		$info = new System_Info( __DIR__ . '/fixtures/proc-v2' );
		$cpu  = $info->cpu();
		$this->assertSame( 2, $cpu['count'] );
		$this->assertSame( 'AMD EPYC 7763 64-Core Processor', $cpu['model'] );
		$this->assertSame( 1.5, $cpu['cgroup_quota'] );

		$memory = $info->memory();
		$this->assertSame( 16303428 * 1024, $memory['total'] );
		$this->assertSame( 8000000 * 1024, $memory['available'] );
		$this->assertSame( 2097148 * 1024, $memory['swap_total'] );
		$this->assertSame( 2147483648, $memory['cgroup_limit'] );
		$this->assertTrue( $info->containerized() );
	}

	public function test_cgroup_v1_unlimited() {
		$info = new System_Info( __DIR__ . '/fixtures/proc-v1' );
		$this->assertNull( $info->cgroup_cpu_quota() );
		$this->assertNull( $info->cgroup_memory_limit() );
		$this->assertNull( $info->cpu()['count'] );
		$this->assertNull( $info->memory()['total'] );
	}

	public function test_missing_root() {
		$info = new System_Info( __DIR__ . '/fixtures/does-not-exist' );
		$this->assertNull( $info->containerized() );
	}
}
