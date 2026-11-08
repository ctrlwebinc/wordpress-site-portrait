<?php
/**
 * WordPress distribution detection (PROTOCOL.md §2.2) with fixtures.
 *
 * @package Site_Portrait
 */

use PHPUnit\Framework\TestCase;
use Site_Portrait\Platform_Detector;

final class PlatformDetectorTest extends TestCase {

	public static function cases() {
		$cases = json_decode( file_get_contents( __DIR__ . '/fixtures/platform-cases.json' ), true );
		unset( $cases['$comment'] );
		return array_map(
			static function ( $c ) {
				return array( $c['facts'], $c['expected'] );
			},
			$cases
		);
	}

	/**
	 * @dataProvider cases
	 */
	public function test_classify( array $facts, array $expected ) {
		$this->assertSame( $expected, Platform_Detector::classify( $facts ) );
	}

	public function test_layout_keeps_relative_facts_only() {
		$this->assertSame(
			array(
				'core_dir'    => 'wp',
				'content_dir' => 'app',
				'docroot'     => 'web',
				'siblings'    => true,
			),
			Platform_Detector::layout( '/srv/www/bakery/web/wp/', '/srv/www/bakery/web/app' )
		);
		$this->assertSame(
			array(
				'core_dir'    => 'html',
				'content_dir' => 'wp-content',
				'docroot'     => 'www',
				'siblings'    => false,
			),
			Platform_Detector::layout( '/var/www/html/', '/var/www/html/wp-content' )
		);
		$this->assertSame(
			array(
				'core_dir'    => 'wordpress',
				'content_dir' => 'public',
				'docroot'     => 'public',
				'siblings'    => false,
			),
			Platform_Detector::layout( 'C:\\sites\\app\\public\\wordpress\\', 'C:\\sites\\app\\public' )
		);
	}

	public function test_layout_feeds_classify() {
		$facts = array( 'layout' => Platform_Detector::layout( '/srv/app/public/wp/', '/srv/app/public/content' ) );
		$this->assertNull( Platform_Detector::classify( $facts )['distribution'], 'the Radicle layout alone is not enough' );

		$facts['packages'] = array( 'roots/acorn' => 'v5.0.1' );
		$facts['wp_env']   = true;
		$this->assertSame( 'radicle', Platform_Detector::classify( $facts )['distribution'] );
	}

	public function test_gather_never_returns_paths() {
		// The test run has Composer's runtime API loaded (vendor/autoload.php).
		$json = (string) json_encode( Platform_Detector::gather(), JSON_UNESCAPED_SLASHES );
		$this->assertStringNotContainsString( dirname( __DIR__, 2 ), $json );
		$this->assertStringNotContainsString( sys_get_temp_dir(), $json );
		$result = Platform_Detector::detect();
		$this->assertSame( array( 'distribution', 'distribution_version', 'composer_managed', 'acorn' ), array_keys( $result ) );
		$this->assertNull( $result['distribution'], 'the plugin\'s own dev dependencies are not a distribution' );
	}
}
