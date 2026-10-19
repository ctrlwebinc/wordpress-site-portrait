<?php
/**
 * Access log, also used as the source of truth for rate limiting
 * (PROTOCOL.md §12).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom table with a trusted name; results must not be cached.

/**
 * Reads and writes the access log table.
 */
final class Access_Log {

	const RETENTION   = 90 * DAY_IN_SECONDS;
	const MAX_ENTRIES = 10000;

	/**
	 * Adds an entry.
	 *
	 * @param array $entry Keys: ip, method, endpoint, key_id, scopes (string[]),
	 *                     status, error_code, authenticated.
	 */
	public static function add( array $entry ) {
		global $wpdb;
		$wpdb->insert(
			Installer::log_table(),
			array(
				'created_at'    => time(),
				'ip'            => substr( (string) ( $entry['ip'] ?? '' ), 0, 45 ),
				'method'        => substr( (string) ( $entry['method'] ?? '' ), 0, 8 ),
				'endpoint'      => substr( (string) ( $entry['endpoint'] ?? '' ), 0, 64 ),
				'key_id'        => substr( (string) ( $entry['key_id'] ?? '' ), 0, 64 ),
				'scopes'        => substr( implode( ',', (array) ( $entry['scopes'] ?? array() ) ), 0, 255 ),
				'status'        => (int) ( $entry['status'] ?? 0 ),
				'error_code'    => substr( (string) ( $entry['error_code'] ?? '' ), 0, 64 ),
				'authenticated' => empty( $entry['authenticated'] ) ? 0 : 1,
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);

		if ( 0 === $wpdb->insert_id % 50 ) {
			self::prune();
		}
	}

	/**
	 * Deletes entries beyond the retention period and size cap.
	 */
	public static function prune() {
		global $wpdb;
		$table = Installer::log_table();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %d", time() - self::RETENTION ) );
		$max_id = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" );
		if ( $max_id > self::MAX_ENTRIES ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", $max_id - self::MAX_ENTRIES ) );
		}
	}

	/**
	 * Number of authenticated requests in the last hour.
	 *
	 * @return int
	 */
	public static function count_authenticated_last_hour() {
		global $wpdb;
		$table = Installer::log_table();
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE authenticated = 1 AND created_at > %d", time() - HOUR_IN_SECONDS ) );
	}

	/**
	 * Creation time of the oldest authenticated request still within the window.
	 *
	 * @return int|null
	 */
	public static function oldest_authenticated_in_window() {
		global $wpdb;
		$table  = Installer::log_table();
		$oldest = $wpdb->get_var( $wpdb->prepare( "SELECT MIN(created_at) FROM {$table} WHERE authenticated = 1 AND created_at > %d", time() - HOUR_IN_SECONDS ) );
		return null === $oldest ? null : (int) $oldest;
	}

	/**
	 * Number of failed requests from an IP in the last hour.
	 *
	 * @param string $ip IP address.
	 * @return int
	 */
	public static function count_failures_last_hour( $ip ) {
		global $wpdb;
		$table = Installer::log_table();
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE ip = %s AND authenticated = 0 AND created_at > %d", $ip, time() - HOUR_IN_SECONDS ) );
	}

	/**
	 * Returns a page of entries, newest first.
	 *
	 * @param int $page     1-based page.
	 * @param int $per_page Entries per page.
	 * @return array{items: array, total: int}
	 */
	public static function page( $page, $per_page = 50 ) {
		global $wpdb;
		$table = Installer::log_table();
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		$items = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, max( 0, ( $page - 1 ) * $per_page ) ),
			ARRAY_A
		);
		return array(
			'items' => is_array( $items ) ? $items : array(),
			'total' => $total,
		);
	}

	/**
	 * Deletes every entry.
	 */
	public static function clear() {
		global $wpdb;
		$wpdb->query( 'DELETE FROM ' . Installer::log_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Trusted table name.
	}
}
