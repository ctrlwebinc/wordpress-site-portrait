<?php
/**
 * Plugin bootstrap and environment helpers.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Wires hooks and answers questions about the deployment mode (PROTOCOL.md §2.1).
 */
final class Plugin {

	/**
	 * Forced network mode, used during uninstall when the plugin is no longer active.
	 *
	 * @var bool|null
	 */
	private static $network_mode_override = null;

	/**
	 * Registers hooks. Runs on plugins_loaded.
	 */
	public static function boot() {
		Installer::maybe_upgrade();

		if ( ! self::is_available() ) {
			if ( is_admin() ) {
				add_action( 'admin_notices', array( Admin\Settings_Page::class, 'render_network_required_notice' ) );
			}
			return;
		}

		Rest_Api::init();

		if ( is_admin() ) {
			Admin\Settings_Page::init();
		}
	}

	/**
	 * Whether the plugin runs in network mode (multisite, network-activated).
	 *
	 * @return bool
	 */
	public static function is_network_mode() {
		if ( null !== self::$network_mode_override ) {
			return self::$network_mode_override;
		}
		if ( ! is_multisite() ) {
			return false;
		}
		$network_plugins = (array) get_site_option( 'active_sitewide_plugins', array() );
		return isset( $network_plugins[ plugin_basename( SITE_PORTRAIT_FILE ) ] );
	}

	/**
	 * Forces the network mode (null restores detection).
	 *
	 * @param bool|null $network Forced value.
	 */
	public static function override_network_mode( $network ) {
		self::$network_mode_override = $network;
	}

	/**
	 * Whether pairing is possible in this installation.
	 *
	 * On multisite the plugin must be network-activated; a subsite
	 * administrator must not disclose network-wide data.
	 *
	 * @return bool
	 */
	public static function is_available() {
		return ! is_multisite() || self::is_network_mode();
	}

	/**
	 * Returns the mode name used in the protocol.
	 *
	 * @return string single|network
	 */
	public static function mode() {
		return self::is_network_mode() ? 'network' : 'single';
	}

	/**
	 * Platform member of the protocol (PROTOCOL.md §2.2): name and version of
	 * the software the site runs on, plus the detected WordPress distribution
	 * (best effort). Sent in the token request, /status and the portrait.
	 *
	 * @return array
	 */
	public static function platform() {
		return array(
			'name'    => 'wordpress',
			'version' => (string) get_bloginfo( 'version' ),
		) + Platform_Detector::detect();
	}

	/**
	 * Capability required to manage the plugin.
	 *
	 * @return string
	 */
	public static function capability() {
		return self::is_network_mode() ? 'manage_network_options' : 'manage_options';
	}

	/**
	 * Home URL of the site (main site in network mode).
	 *
	 * @return string
	 */
	public static function home_url() {
		return self::is_network_mode() ? get_home_url( get_main_site_id() ) : home_url();
	}

	/**
	 * Origin (scheme://host[:port]) of a URL.
	 *
	 * @param string $url URL.
	 * @return string|null
	 */
	public static function origin( $url ) {
		$parts = wp_parse_url( $url );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return null;
		}
		$scheme = strtolower( $parts['scheme'] );
		return $scheme . '://' . Http_Signature::authority( $scheme, $parts['host'], $parts['port'] ?? null );
	}

	/**
	 * Authority (host[:port]) the service must sign for incoming requests.
	 *
	 * @return string
	 */
	public static function expected_authority() {
		$parts = wp_parse_url( self::home_url() );
		return Http_Signature::authority( $parts['scheme'] ?? 'https', $parts['host'] ?? '', $parts['port'] ?? null );
	}

	/**
	 * Whether development mode is active (PROTOCOL.md §14.6).
	 *
	 * @return bool
	 */
	public static function is_dev_mode() {
		return defined( 'SITE_PORTRAIT_DEV_MODE' ) && true === SITE_PORTRAIT_DEV_MODE
			&& in_array( wp_get_environment_type(), array( 'local', 'development' ), true )
			&& self::is_dev_host( (string) wp_parse_url( self::home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Whether a host name is acceptable in development mode.
	 *
	 * @param string $host Host name.
	 * @return bool
	 */
	public static function is_dev_host( $host ) {
		$host = strtolower( trim( $host, '[]' ) );
		if ( in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		return (bool) preg_match( '/\.(test|localhost)$/', $host );
	}

	/**
	 * Whether a URL is acceptable for talking to a service.
	 *
	 * HTTPS is required, except for development hosts in development mode.
	 *
	 * @param string $url URL.
	 * @return bool
	 */
	public static function is_allowed_service_url( $url ) {
		$parts = wp_parse_url( $url );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return false;
		}
		if ( 'https' === strtolower( $parts['scheme'] ) ) {
			return true;
		}
		return 'http' === strtolower( $parts['scheme'] ) && self::is_dev_mode() && self::is_dev_host( $parts['host'] );
	}

	/**
	 * Returns the URL of an admin action handler.
	 *
	 * Single sites use admin-post.php, networks use network/edit.php.
	 *
	 * @param string $action Action name without the site_portrait_ prefix.
	 * @return string
	 */
	public static function action_url( $action ) {
		$action = 'site_portrait_' . $action;
		return self::is_network_mode()
			? add_query_arg( 'action', $action, network_admin_url( 'edit.php' ) )
			: add_query_arg( 'action', $action, admin_url( 'admin-post.php' ) );
	}

	/**
	 * Returns the URL of the settings page.
	 *
	 * @param array $args Extra query arguments.
	 * @return string
	 */
	public static function settings_url( array $args = array() ) {
		$base = self::is_network_mode() ? network_admin_url( 'settings.php' ) : admin_url( 'options-general.php' );
		return add_query_arg( array_merge( array( 'page' => 'ctrlweb-site-portrait' ), $args ), $base );
	}
}
