<?php
/**
 * Base class of scope collectors.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;

defined( 'ABSPATH' ) || exit;

/**
 * A collector returns the data of one scope (see docs/schema/portrait-v1.schema.json).
 */
abstract class Collector {

	/**
	 * Collects the scope data.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	abstract public function collect( Collect_Context $context );

	/**
	 * Converts a PHP shorthand size (128M, -1…) to bytes; null when unlimited or unknown.
	 *
	 * @param mixed $value Value.
	 * @return int|null
	 */
	protected static function bytes( $value ) {
		if ( false === $value || null === $value || '' === $value ) {
			return null;
		}
		$value = trim( (string) $value );
		if ( '-1' === $value ) {
			return null;
		}
		return max( 0, (int) wp_convert_hr_to_bytes( $value ) );
	}

	/**
	 * Reads an ini setting as a boolean; null when unknown.
	 *
	 * @param string $name Setting.
	 * @return bool|null
	 */
	protected static function ini_bool( $name ) {
		$value = ini_get( $name );
		if ( false === $value ) {
			return null;
		}
		return in_array( strtolower( (string) $value ), array( '1', 'on', 'yes', 'true', 'stdout', 'stderr' ), true );
	}

	/**
	 * Reads an ini setting as an integer; null when unknown.
	 *
	 * @param string $name Setting.
	 * @return int|null
	 */
	protected static function ini_int( $name ) {
		$value = ini_get( $name );
		return false === $value || '' === $value ? null : (int) $value;
	}

	/**
	 * Converts a Unix time to RFC 3339 UTC.
	 *
	 * @param int $time Time.
	 * @return string
	 */
	protected static function rfc3339( $time ) {
		return gmdate( 'Y-m-d\TH:i:s\Z', (int) $time );
	}
}
