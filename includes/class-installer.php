<?php
/**
 * Database tables, upgrades and uninstallation.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Creates and removes the plugin's tables and options.
 *
 * Tables use the network base prefix: there is at most one pairing per
 * installation, so a single nonce store and access log are shared.
 */
final class Installer {

	const DB_VERSION        = '1';
	const DB_VERSION_OPTION = 'site_portrait_db_version';

	/**
	 * Activation hook.
	 */
	public static function activate() {
		self::create_tables();
	}

	/**
	 * Creates or upgrades tables when the schema version changed.
	 */
	public static function maybe_upgrade() {
		if ( get_site_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) {
			self::create_tables();
		}
	}

	/**
	 * Name of the nonce table.
	 *
	 * @return string
	 */
	public static function nonces_table() {
		global $wpdb;
		return $wpdb->base_prefix . 'site_portrait_nonces';
	}

	/**
	 * Name of the access log table.
	 *
	 * @return string
	 */
	public static function log_table() {
		global $wpdb;
		return $wpdb->base_prefix . 'site_portrait_log';
	}

	/**
	 * Creates the tables with dbDelta.
	 */
	private static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$nonces          = self::nonces_table();
		$log             = self::log_table();

		dbDelta(
			"CREATE TABLE {$nonces} (
				nonce_hash char(64) NOT NULL,
				expires_at bigint(20) unsigned NOT NULL,
				PRIMARY KEY  (nonce_hash),
				KEY expires_at (expires_at)
			) {$charset_collate};
			CREATE TABLE {$log} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at bigint(20) unsigned NOT NULL,
				ip varchar(45) NOT NULL DEFAULT '',
				method varchar(8) NOT NULL DEFAULT '',
				endpoint varchar(64) NOT NULL DEFAULT '',
				key_id varchar(64) NOT NULL DEFAULT '',
				scopes varchar(255) NOT NULL DEFAULT '',
				status smallint(5) unsigned NOT NULL DEFAULT 0,
				error_code varchar(64) NOT NULL DEFAULT '',
				authenticated tinyint(1) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY ip_created (ip, created_at)
			) {$charset_collate};"
		);

		update_site_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Removes everything the plugin stored. Called from uninstall.php.
	 */
	public static function uninstall() {
		global $wpdb;

		Plugin::override_network_mode( is_multisite() );
		if ( Pairing::is_active() ) {
			Pairing::disconnect( 'plugin_uninstalled', 5 );
		}

		foreach ( array( Store::PAIRING, Store::SETTINGS ) as $option ) {
			delete_option( $option );
			delete_site_option( $option );
		}
		delete_site_option( self::DB_VERSION_OPTION );

		// Pending pairings and caches are transients with per-user names.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
				$wpdb->esc_like( '_transient_site_portrait_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_site_portrait_' ) . '%',
				$wpdb->esc_like( '_site_transient_site_portrait_' ) . '%',
				$wpdb->esc_like( '_site_transient_timeout_site_portrait_' ) . '%'
			)
		);
		if ( is_multisite() ) {
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
					$wpdb->esc_like( '_site_transient_site_portrait_' ) . '%',
					$wpdb->esc_like( '_site_transient_timeout_site_portrait_' ) . '%'
				)
			);
		}
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::nonces_table() . ', ' . self::log_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table names are built from the trusted base prefix.
		// phpcs:enable
	}
}
