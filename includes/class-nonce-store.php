<?php
/**
 * Single-use storage of request signature nonces (PROTOCOL.md §5.4).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Records nonces atomically thanks to the table's primary key.
 */
final class Nonce_Store {

	/**
	 * Records a nonce; returns false if it was already used.
	 *
	 * @param string $kid     Key id that signed the request.
	 * @param string $nonce   Nonce.
	 * @param int    $expires Signature expiry (Unix time).
	 * @return bool True when the nonce is fresh.
	 */
	public static function consume( $kid, $nonce, $expires ) {
		global $wpdb;
		$table = Installer::nonces_table();
		$now   = time();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Custom table; caching would defeat replay protection.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE expires_at < %d", $now ) );

		$inserted = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$table} (nonce_hash, expires_at) VALUES (%s, %d)",
				hash( 'sha256', $kid . "\n" . $nonce ),
				max( $expires, $now ) + 60
			)
		);
		// phpcs:enable

		return 1 === $inserted;
	}

	/**
	 * Deletes every stored nonce.
	 */
	public static function clear() {
		global $wpdb;
		$wpdb->query( 'DELETE FROM ' . Installer::nonces_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared -- Custom table, trusted name.
	}
}
