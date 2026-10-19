<?php
/**
 * IP allow-list parsing and matching (IPv4 and IPv6, with CIDR).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Pure helpers, free of WordPress dependencies.
 */
final class Ip_Allowlist {

	/**
	 * Parses user input (one entry per line, or comma separated).
	 *
	 * @param string $input Raw input.
	 * @return array{valid: string[], invalid: string[]}
	 */
	public static function parse( $input ) {
		$valid   = array();
		$invalid = array();
		foreach ( preg_split( '/[\s,]+/', (string) $input, -1, PREG_SPLIT_NO_EMPTY ) as $entry ) {
			if ( self::is_valid_entry( $entry ) ) {
				$valid[] = strtolower( $entry );
			} else {
				$invalid[] = $entry;
			}
		}
		return array(
			'valid'   => array_values( array_unique( $valid ) ),
			'invalid' => $invalid,
		);
	}

	/**
	 * Whether an entry is an IP address or a CIDR range.
	 *
	 * @param string $entry Entry.
	 * @return bool
	 */
	public static function is_valid_entry( $entry ) {
		$parts = explode( '/', $entry, 2 );
		$ip    = filter_var( $parts[0], FILTER_VALIDATE_IP );
		if ( false === $ip ) {
			return false;
		}
		if ( ! isset( $parts[1] ) ) {
			return true;
		}
		$max = false !== strpos( $ip, ':' ) ? 128 : 32;
		return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max;
	}

	/**
	 * Whether an IP matches one of the entries.
	 *
	 * @param string   $ip      Client IP.
	 * @param string[] $entries Allow-list entries.
	 * @return bool
	 */
	public static function matches( $ip, array $entries ) {
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Returns false and warns on invalid input.
		if ( false === $packed ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			$parts  = explode( '/', $entry, 2 );
			$subnet = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Same as above.
			if ( false === $subnet || strlen( $subnet ) !== strlen( $packed ) ) {
				continue;
			}
			$bits = isset( $parts[1] ) ? (int) $parts[1] : strlen( $packed ) * 8;
			if ( self::prefix_equals( $packed, $subnet, $bits ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Compares the first $bits bits of two packed addresses.
	 *
	 * @param string $a    Packed address.
	 * @param string $b    Packed address.
	 * @param int    $bits Prefix length.
	 * @return bool
	 */
	private static function prefix_equals( $a, $b, $bits ) {
		$bytes = intdiv( $bits, 8 );
		if ( substr( $a, 0, $bytes ) !== substr( $b, 0, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xff << ( 8 - $rest ) ) & 0xff;
		return ( ord( $a[ $bytes ] ) & $mask ) === ( ord( $b[ $bytes ] ) & $mask );
	}
}
