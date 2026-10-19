<?php
/**
 * Option and transient storage, network-aware.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Stores plugin data in site options (single) or network options (network mode).
 */
final class Store {

	const PAIRING  = 'site_portrait_pairing';
	const SETTINGS = 'site_portrait_settings';

	/**
	 * Reads an option.
	 *
	 * @param string $name    Option name.
	 * @param mixed  $default_value Default value.
	 * @return mixed
	 */
	public static function get( $name, $default_value = null ) {
		return Plugin::is_network_mode() ? get_site_option( $name, $default_value ) : get_option( $name, $default_value );
	}

	/**
	 * Writes a non-autoloaded option.
	 *
	 * @param string $name  Option name.
	 * @param mixed  $value Value.
	 */
	public static function set( $name, $value ) {
		if ( Plugin::is_network_mode() ) {
			update_site_option( $name, $value );
		} else {
			update_option( $name, $value, false );
		}
	}

	/**
	 * Deletes an option.
	 *
	 * @param string $name Option name.
	 */
	public static function delete( $name ) {
		if ( Plugin::is_network_mode() ) {
			delete_site_option( $name );
		} else {
			delete_option( $name );
		}
	}

	/**
	 * Reads a transient.
	 *
	 * @param string $name Transient name.
	 * @return mixed False when missing.
	 */
	public static function get_transient( $name ) {
		return Plugin::is_network_mode() ? get_site_transient( $name ) : get_transient( $name );
	}

	/**
	 * Writes a transient.
	 *
	 * @param string $name       Transient name.
	 * @param mixed  $value      Value.
	 * @param int    $expiration Lifetime in seconds.
	 */
	public static function set_transient( $name, $value, $expiration ) {
		if ( Plugin::is_network_mode() ) {
			set_site_transient( $name, $value, $expiration );
		} else {
			set_transient( $name, $value, $expiration );
		}
	}

	/**
	 * Deletes a transient.
	 *
	 * @param string $name Transient name.
	 */
	public static function delete_transient( $name ) {
		if ( Plugin::is_network_mode() ) {
			delete_site_transient( $name );
		} else {
			delete_transient( $name );
		}
	}

	/**
	 * Returns the settings with defaults.
	 *
	 * @return array{ip_allowlist: string[]}
	 */
	public static function settings() {
		$settings = self::get( self::SETTINGS, array() );
		return wp_parse_args(
			is_array( $settings ) ? $settings : array(),
			array( 'ip_allowlist' => array() )
		);
	}
}
