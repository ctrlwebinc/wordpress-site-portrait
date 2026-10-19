<?php
/**
 * Scope "core".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress version, languages, multisite, HTTPS, constants, cron and caches.
 */
final class Core_Collector extends Collector {

	/**
	 * Boolean constants reported by name (never secret values).
	 */
	const CONSTANTS = array(
		'WP_DEBUG',
		'WP_DEBUG_LOG',
		'WP_DEBUG_DISPLAY',
		'SCRIPT_DEBUG',
		'SAVEQUERIES',
		'WP_CACHE',
		'DISALLOW_FILE_EDIT',
		'DISALLOW_FILE_MODS',
		'AUTOMATIC_UPDATER_DISABLED',
		'CONCATENATE_SCRIPTS',
		'COMPRESS_SCRIPTS',
	);

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		$permalinks = (string) get_option( 'permalink_structure' );
		if ( '' === $permalinks ) {
			$permalink_type = 'plain';
		} elseif ( 0 === strpos( $permalinks, '/index.php' ) ) {
			$permalink_type = 'pathinfo';
		} else {
			$permalink_type = 'pretty';
		}

		$constants = array();
		foreach ( self::CONSTANTS as $name ) {
			// WP_DEBUG_LOG may be a path; only its truthiness is reported.
			$constants[ $name ] = defined( $name ) ? (bool) constant( $name ) : null;
		}

		$languages = get_available_languages();
		array_unshift( $languages, 'en_US' );

		return array(
			'wp_version'          => (string) get_bloginfo( 'version' ),
			'core_update'         => $this->core_update(),
			'core_auto_update'    => $this->core_auto_update(),
			'locale'              => get_locale(),
			'languages_installed' => array_values( array_unique( $languages ) ),
			'timezone'            => wp_timezone_string(),
			'environment_type'    => wp_get_environment_type(),
			'multisite'           => array(
				'enabled'           => is_multisite(),
				'subdomain_install' => is_multisite() ? is_subdomain_install() : null,
				'sites_count'       => is_multisite() ? (int) get_blog_count() : null,
			),
			'https'               => array(
				'home_url'        => wp_is_home_url_using_https(),
				'site_url'        => wp_is_site_url_using_https(),
				'force_ssl_admin' => force_ssl_admin(),
			),
			'permalink_structure' => $permalink_type,
			'constants'           => $constants,
			'memory_limits'       => array(
				'wp_memory_limit'     => defined( 'WP_MEMORY_LIMIT' ) ? self::bytes( WP_MEMORY_LIMIT ) : null,
				'wp_max_memory_limit' => defined( 'WP_MAX_MEMORY_LIMIT' ) ? self::bytes( WP_MAX_MEMORY_LIMIT ) : null,
			),
			'cron'                => $this->cron(),
			'cache'               => $this->cache(),
		);
	}

	/**
	 * Core update status from the update_core transient (no remote call).
	 *
	 * @return array
	 */
	private function core_update() {
		$updates = get_core_updates();
		if ( ! is_array( $updates ) || empty( $updates ) || ! is_object( $updates[0] ) ) {
			return array(
				'status'  => 'unknown',
				'version' => null,
			);
		}
		$offer  = $updates[0];
		$status = in_array( $offer->response ?? '', array( 'latest', 'upgrade', 'development' ), true ) ? $offer->response : 'unknown';
		return array(
			'status'  => $status,
			'version' => isset( $offer->current ) ? (string) $offer->current : null,
		);
	}

	/**
	 * Core auto-update policy (best effort; filters may change it).
	 *
	 * @return string|null all|minor|disabled
	 */
	private function core_auto_update() {
		if ( ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) || ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) ) {
			return 'disabled';
		}
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) ) {
			if ( false === WP_AUTO_UPDATE_CORE ) {
				return 'disabled';
			}
			return 'minor' === WP_AUTO_UPDATE_CORE ? 'minor' : 'all';
		}
		return 'enabled' === get_site_option( 'auto_update_core_major' ) ? 'all' : 'minor';
	}

	/**
	 * Cron health.
	 *
	 * @return array
	 */
	private function cron() {
		$crons  = _get_cron_array();
		$events = 0;
		$late   = 0;
		$hooks  = array();
		if ( is_array( $crons ) ) {
			foreach ( $crons as $timestamp => $cron_hooks ) {
				foreach ( (array) $cron_hooks as $hook => $instances ) {
					$hooks[ $hook ] = true;
					$count          = count( (array) $instances );
					$events        += $count;
					if ( (int) $timestamp < time() - HOUR_IN_SECONDS ) {
						$late += $count;
					}
				}
			}
		}
		return array(
			'disabled'      => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'alternate'     => defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON,
			'events_count'  => is_array( $crons ) ? $events : null,
			'overdue_count' => is_array( $crons ) ? $late : null,
			'hooks_count'   => is_array( $crons ) ? count( $hooks ) : null,
		);
	}

	/**
	 * Object and page cache detection.
	 *
	 * @return array
	 */
	private function cache() {
		$available = array();
		foreach ( array( 'redis', 'memcache', 'memcached', 'apcu' ) as $extension ) {
			if ( extension_loaded( $extension ) ) {
				$available[] = $extension;
			}
		}

		return array(
			'object_cache' => array(
				'persistent'           => (bool) wp_using_ext_object_cache(),
				'dropin'               => file_exists( WP_CONTENT_DIR . '/object-cache.php' ),
				'backend'              => $this->object_cache_backend(),
				'available_extensions' => $available,
			),
			'page_cache'   => array(
				'advanced_cache_dropin' => file_exists( WP_CONTENT_DIR . '/advanced-cache.php' ),
				'wp_cache_constant'     => defined( 'WP_CACHE' ) && WP_CACHE,
			),
		);
	}

	/**
	 * Guesses the persistent object cache backend.
	 *
	 * @return string|null
	 */
	private function object_cache_backend() {
		global $wp_object_cache;
		if ( ! wp_using_ext_object_cache() ) {
			return null;
		}
		$hint = is_object( $wp_object_cache ) ? strtolower( get_class( $wp_object_cache ) ) : '';
		$drop = get_dropins();
		if ( isset( $drop['object-cache.php']['Name'] ) ) {
			$hint .= ' ' . strtolower( $drop['object-cache.php']['Name'] );
		}
		foreach ( array( 'redis', 'memcached', 'memcache', 'apcu', 'sqlite' ) as $backend ) {
			if ( false !== strpos( $hint, $backend ) ) {
				return $backend;
			}
		}
		return 'other';
	}
}
