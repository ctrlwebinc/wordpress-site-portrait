<?php
/**
 * Class autoloader.
 *
 * Maps Site_Portrait\Foo_Bar to includes/class-foo-bar.php and
 * Site_Portrait\Sub\Foo_Bar to includes/sub/class-foo-bar.php.
 *
 * @package Site_Portrait
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	static function ( $class_name ) {
		$prefix = 'Site_Portrait\\';
		if ( 0 !== strpos( $class_name, $prefix ) ) {
			return;
		}

		$parts = explode( '\\', substr( $class_name, strlen( $prefix ) ) );
		$class = array_pop( $parts );
		$dirs  = array_map(
			static function ( $part ) {
				return strtolower( str_replace( '_', '-', $part ) ) . '/';
			},
			$parts
		);

		$file = __DIR__ . '/' . implode( '', $dirs ) . 'class-' . strtolower( str_replace( '_', '-', $class ) ) . '.php';
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);
