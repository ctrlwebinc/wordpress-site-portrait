<?php
/**
 * Scope "server".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;
use Site_Portrait\System_Info;

defined( 'ABSPATH' ) || exit;

/**
 * OS, web server, PHP, CPU, memory, disk and libraries. No host names, IPs or paths.
 */
final class Server_Collector extends Collector {

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		$system = new System_Info();
		$cpu    = $system->cpu();
		$memory = $system->memory();

		if ( null === $cpu['count'] ) {
			$context->warn( 'cpu.count', 'unavailable', '/proc/cpuinfo is not readable.' );
		}
		if ( null === $memory['total'] ) {
			$context->warn( 'memory.total', 'unavailable', '/proc/meminfo is not readable.' );
		}

		$extensions = array_map( 'strtolower', get_loaded_extensions() );
		sort( $extensions );

		$load = function_exists( 'sys_getloadavg' ) ? sys_getloadavg() : false;

		return array(
			'os'         => array(
				'family'        => PHP_OS_FAMILY,
				'architecture'  => function_exists( 'php_uname' ) ? php_uname( 'm' ) : null,
				'containerized' => $system->containerized(),
			),
			'web_server' => array(
				'software' => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : null,
				'http2'    => isset( $_SERVER['SERVER_PROTOCOL'] ) ? 0 === strpos( sanitize_text_field( wp_unslash( $_SERVER['SERVER_PROTOCOL'] ) ), 'HTTP/2' ) : null,
			),
			'php'        => array(
				'version'    => PHP_VERSION,
				'sapi'       => PHP_SAPI,
				'bits'       => PHP_INT_SIZE * 8,
				'extensions' => $extensions,
				'ini'        => $this->ini(),
				'opcache'    => $this->opcache(),
			),
			'cpu'        => array(
				'count'        => $cpu['count'],
				'model'        => $cpu['model'],
				'cgroup_quota' => $cpu['cgroup_quota'],
				'load_average' => is_array( $load ) && 3 === count( $load ) ? array_map( 'floatval', array_values( $load ) ) : null,
			),
			'memory'     => $memory,
			'disk'       => array(
				'free'  => function_exists( 'disk_free_space' ) ? $this->int_or_null( disk_free_space( WP_CONTENT_DIR ) ) : null,
				'total' => function_exists( 'disk_total_space' ) ? $this->int_or_null( disk_total_space( WP_CONTENT_DIR ) ) : null,
			),
			'libraries'  => $this->libraries(),
		);
	}

	/**
	 * PHP limits.
	 *
	 * @return array
	 */
	private function ini() {
		$disabled = trim( (string) ini_get( 'disable_functions' ) );
		return array(
			'memory_limit'             => self::bytes( ini_get( 'memory_limit' ) ),
			'max_execution_time'       => self::ini_int( 'max_execution_time' ),
			'max_input_time'           => self::ini_int( 'max_input_time' ),
			'max_input_vars'           => self::ini_int( 'max_input_vars' ),
			'post_max_size'            => self::bytes( ini_get( 'post_max_size' ) ),
			'upload_max_filesize'      => self::bytes( ini_get( 'upload_max_filesize' ) ),
			'max_file_uploads'         => self::ini_int( 'max_file_uploads' ),
			'allow_url_fopen'          => self::ini_bool( 'allow_url_fopen' ),
			'display_errors'           => self::ini_bool( 'display_errors' ),
			'disabled_functions_count' => '' === $disabled ? 0 : count( array_filter( array_map( 'trim', explode( ',', $disabled ) ) ) ),
		);
	}

	/**
	 * OPcache status, without the list of cached scripts (it contains paths).
	 *
	 * @return array
	 */
	private function opcache() {
		$enabled = extension_loaded( 'Zend OPcache' ) && self::ini_bool( 'opcache.enable' );
		$result  = array(
			'enabled'        => (bool) $enabled,
			'jit'            => null,
			'memory_size'    => self::bytes( ini_get( 'opcache.memory_consumption' ) . 'M' ),
			'memory_used'    => null,
			'hit_rate'       => null,
			'cached_scripts' => null,
		);
		if ( ! $enabled || ! function_exists( 'opcache_get_status' ) ) {
			return $result;
		}
		// opcache.restrict_api may forbid the call and emit a warning.
		$status = @opcache_get_status( false ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $status ) ) {
			return $result;
		}
		$result['jit']            = isset( $status['jit']['enabled'] ) ? (bool) $status['jit']['enabled'] : null;
		$result['memory_used']    = isset( $status['memory_usage']['used_memory'] ) ? (int) $status['memory_usage']['used_memory'] : null;
		$result['hit_rate']       = isset( $status['opcache_statistics']['opcache_hit_rate'] ) ? round( (float) $status['opcache_statistics']['opcache_hit_rate'], 2 ) : null;
		$result['cached_scripts'] = isset( $status['opcache_statistics']['num_cached_scripts'] ) ? (int) $status['opcache_statistics']['num_cached_scripts'] : null;
		return $result;
	}

	/**
	 * Library versions.
	 *
	 * @return array
	 */
	private function libraries() {
		$curl = function_exists( 'curl_version' ) ? curl_version() : null;
		$gd   = function_exists( 'gd_info' ) ? gd_info() : null;

		$imagick = null;
		if ( class_exists( 'Imagick' ) ) {
			$version = \Imagick::getVersion();
			if ( isset( $version['versionString'] ) && preg_match( '/ImageMagick\s+[\d.]+(-\d+)?/', $version['versionString'], $m ) ) {
				$imagick = $m[0];
			}
		}

		$sodium = extension_loaded( 'sodium' ) ? 'native' : null;
		if ( null === $sodium && function_exists( 'sodium_crypto_sign_detached' ) ) {
			$sodium = 'polyfill';
		}

		return array(
			'curl'    => is_array( $curl ) && isset( $curl['version'] ) ? (string) $curl['version'] : null,
			'openssl' => defined( 'OPENSSL_VERSION_TEXT' ) ? OPENSSL_VERSION_TEXT : null,
			'gd'      => is_array( $gd ) && isset( $gd['GD Version'] ) ? (string) $gd['GD Version'] : null,
			'imagick' => $imagick,
			'icu'     => defined( 'INTL_ICU_VERSION' ) ? INTL_ICU_VERSION : null,
			'sodium'  => $sodium,
		);
	}

	/**
	 * Casts a float result to int, or null on failure.
	 *
	 * @param mixed $value Value.
	 * @return int|null
	 */
	private function int_or_null( $value ) {
		return false === $value || null === $value ? null : (int) $value;
	}
}
