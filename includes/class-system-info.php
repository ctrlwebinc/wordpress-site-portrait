<?php
/**
 * Reads CPU and memory information from /proc and cgroup files when readable.
 *
 * Never executes commands. Free of WordPress dependencies for unit testing:
 * the file-system root can be replaced by a fixture directory.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Host and container resource detection (Linux).
 */
final class System_Info {

	/**
	 * File-system root, '' in production.
	 *
	 * @var string
	 */
	private $root;

	/**
	 * Constructor.
	 *
	 * @param string $root File-system root (for tests).
	 */
	public function __construct( $root = '' ) {
		$this->root = rtrim( $root, '/' );
	}

	/**
	 * CPU information.
	 *
	 * @return array{count: int|null, model: string|null, cgroup_quota: float|null}
	 */
	public function cpu() {
		$count   = null;
		$model   = null;
		$cpuinfo = $this->read( '/proc/cpuinfo' );
		if ( null !== $cpuinfo ) {
			$count = preg_match_all( '/^processor\s*:/m', $cpuinfo );
			$count = $count > 0 ? $count : null;
			if ( preg_match( '/^(?:model name|Model|cpu model)\s*:\s*(.+)$/mi', $cpuinfo, $m ) ) {
				$model = preg_replace( '/\s+/', ' ', trim( $m[1] ) );
			}
		}

		return array(
			'count'        => $count,
			'model'        => $model,
			'cgroup_quota' => $this->cgroup_cpu_quota(),
		);
	}

	/**
	 * Memory information, in bytes.
	 *
	 * @return array{total: int|null, available: int|null, swap_total: int|null, cgroup_limit: int|null}
	 */
	public function memory() {
		$info    = array();
		$meminfo = $this->read( '/proc/meminfo' );
		if ( null !== $meminfo && preg_match_all( '/^(\w+):\s+(\d+)\s*kB$/m', $meminfo, $matches, PREG_SET_ORDER ) ) {
			foreach ( $matches as $match ) {
				$info[ $match[1] ] = (int) $match[2] * 1024;
			}
		}
		return array(
			'total'        => $info['MemTotal'] ?? null,
			'available'    => $info['MemAvailable'] ?? null,
			'swap_total'   => $info['SwapTotal'] ?? null,
			'cgroup_limit' => $this->cgroup_memory_limit(),
		);
	}

	/**
	 * Whether a container or cgroup limit was detected.
	 *
	 * @return bool|null
	 */
	public function containerized() {
		if ( $this->is_readable( '/.dockerenv' ) || $this->is_readable( '/run/.containerenv' ) ) {
			return true;
		}
		if ( null !== $this->cgroup_cpu_quota() || null !== $this->cgroup_memory_limit() ) {
			return true;
		}
		return null === $this->read( '/proc/1/cgroup' ) ? null : false;
	}

	/**
	 * CPUs allowed by the cgroup (v2 cpu.max or v1 CFS quota).
	 *
	 * @return float|null Null if unlimited or unknown.
	 */
	public function cgroup_cpu_quota() {
		$max = $this->read( '/sys/fs/cgroup/cpu.max' );
		if ( null !== $max && preg_match( '/^(\d+)\s+(\d+)/', trim( $max ), $m ) && (int) $m[2] > 0 ) {
			return round( (int) $m[1] / (int) $m[2], 2 );
		}
		$quota  = $this->read( '/sys/fs/cgroup/cpu/cpu.cfs_quota_us' );
		$period = $this->read( '/sys/fs/cgroup/cpu/cpu.cfs_period_us' );
		if ( null !== $quota && null !== $period && (int) $quota > 0 && (int) $period > 0 ) {
			return round( (int) $quota / (int) $period, 2 );
		}
		return null;
	}

	/**
	 * Memory limit of the cgroup.
	 *
	 * @return int|null Null if unlimited or unknown.
	 */
	public function cgroup_memory_limit() {
		foreach ( array( '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes' ) as $file ) {
			$value = $this->read( $file );
			if ( null === $value ) {
				continue;
			}
			$value = trim( $value );
			// cgroup v1 reports "unlimited" as a value close to PHP_INT_MAX.
			if ( ctype_digit( $value ) && strlen( $value ) < 19 ) {
				return (int) $value;
			}
			return null;
		}
		return null;
	}

	/**
	 * Reads a small file if allowed, readable and not empty.
	 *
	 * @param string $path Absolute path below the root.
	 * @return string|null
	 */
	private function read( $path ) {
		if ( ! $this->is_readable( $path ) ) {
			return null;
		}
		$content = file_get_contents( $this->root . $path, false, null, 0, 1048576 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local pseudo-file; WP_Filesystem is not suited to /proc.
		return false === $content || '' === $content ? null : $content;
	}

	/**
	 * Whether a path may be read, honouring open_basedir to avoid warnings.
	 *
	 * @param string $path Absolute path below the root.
	 * @return bool
	 */
	private function is_readable( $path ) {
		$full     = $this->root . $path;
		$basedirs = (string) ini_get( 'open_basedir' );
		if ( '' !== $basedirs ) {
			$allowed = false;
			foreach ( explode( PATH_SEPARATOR, $basedirs ) as $dir ) {
				if ( '' !== $dir && 0 === strpos( $full, rtrim( $dir, '/' ) . '/' ) ) {
					$allowed = true;
					break;
				}
			}
			if ( ! $allowed ) {
				return false;
			}
		}
		return is_file( $full ) && is_readable( $full );
	}
}
