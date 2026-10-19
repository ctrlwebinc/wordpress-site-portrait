<?php
/**
 * Scope "database".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;
use WP_Debug_Data;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Read-only metadata queries; results must be fresh.

/**
 * Engine, version, sizes, tables and options. No credentials, host or table prefix.
 */
final class Database_Collector extends Collector {

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		global $wpdb;

		$engine = $this->engine();
		$tables = 'sqlite' === $engine ? null : $this->table_stats();
		if ( null === $tables ) {
			$context->warn( 'size', 'unavailable', 'Table statistics are not available for this database engine.' );
		}

		$size = array(
			'data'  => null,
			'index' => null,
			'total' => null,
		);
		if ( null !== $tables ) {
			$size['data']  = array_sum( array_column( $tables, 'data' ) );
			$size['index'] = array_sum( array_column( $tables, 'index' ) );
			$size['total'] = $size['data'] + $size['index'];
		} elseif ( 'sqlite' === $engine && defined( 'FQDB' ) && is_readable( FQDB ) ) {
			$size['total'] = (int) filesize( FQDB );
		}

		$own_tables = null === $tables ? array() : array_values(
			array_filter(
				$tables,
				static function ( $table ) use ( $wpdb ) {
					return 0 === strpos( $table['name'], $wpdb->base_prefix );
				}
			)
		);
		usort(
			$own_tables,
			static function ( $a, $b ) {
				return ( $b['data'] + $b['index'] ) <=> ( $a['data'] + $a['index'] );
			}
		);
		$largest = array();
		foreach ( array_slice( $own_tables, 0, 10 ) as $table ) {
			$table['name'] = substr( $table['name'], strlen( $wpdb->base_prefix ) );
			$largest[]     = $table;
		}

		$variables = array();
		foreach ( array( 'max_connections', 'max_allowed_packet', 'innodb_buffer_pool_size' ) as $name ) {
			$value              = 'sqlite' === $engine ? null : WP_Debug_Data::get_mysql_var( $name );
			$variables[ $name ] = null === $value || ! is_numeric( $value ) ? null : (int) $value;
		}

		return array(
			'engine'           => $engine,
			'server_version'   => $this->server_version( $engine ),
			'client'           => 'sqlite' !== $engine && extension_loaded( 'mysqlnd' ) ? 'mysqlnd ' . phpversion( 'mysqlnd' ) : null,
			'charset'          => $wpdb->charset ? (string) $wpdb->charset : null,
			'collate'          => $wpdb->collate ? (string) $wpdb->collate : null,
			'size'             => $size,
			'tables'           => array(
				'count'      => null === $tables ? null : count( $tables ),
				'site_count' => null === $tables ? null : count( $own_tables ),
				'largest'    => $largest,
			),
			'options'          => $this->options_stats(),
			'transients_count' => $this->transients_count(),
			'variables'        => $variables,
		);
	}

	/**
	 * Detects the engine.
	 *
	 * @return string mysql|mariadb|sqlite|other
	 */
	private function engine() {
		global $wpdb;
		if ( ( defined( 'DB_ENGINE' ) && 'sqlite' === DB_ENGINE ) || is_a( $wpdb, 'WP_SQLite_DB' ) ) {
			return 'sqlite';
		}
		$info = (string) $wpdb->db_server_info();
		if ( false !== stripos( $info, 'mariadb' ) ) {
			return 'mariadb';
		}
		return '' !== $info ? 'mysql' : 'other';
	}

	/**
	 * Server version without vendor suffixes.
	 *
	 * @param string $engine Engine.
	 * @return string|null
	 */
	private function server_version( $engine ) {
		global $wpdb;
		if ( 'sqlite' === $engine ) {
			return class_exists( 'SQLite3' ) ? \SQLite3::version()['versionString'] : null;
		}
		$info = (string) $wpdb->db_server_info();
		// MariaDB may report a "5.5.5-" compatibility prefix.
		$info = preg_replace( '/^5\.5\.5-/', '', $info );
		return preg_match( '/^\d+(\.\d+){1,2}/', $info, $m ) ? $m[0] : null;
	}

	/**
	 * Statistics of every table in the schema.
	 *
	 * @return array|null List of name, engine, rows, data, index.
	 */
	private function table_stats() {
		global $wpdb;
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT TABLE_NAME AS name, ENGINE AS engine, TABLE_ROWS AS row_count, DATA_LENGTH AS data_length, INDEX_LENGTH AS index_length
				FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = %s',
				DB_NAME,
				'BASE TABLE'
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) || empty( $rows ) ) {
			return null;
		}
		$tables = array();
		foreach ( $rows as $row ) {
			$tables[] = array(
				'name'   => (string) $row['name'],
				'engine' => null !== $row['engine'] ? (string) $row['engine'] : null,
				'rows'   => null !== $row['row_count'] ? (int) $row['row_count'] : null,
				'data'   => (int) $row['data_length'],
				'index'  => (int) $row['index_length'],
			);
		}
		return $tables;
	}

	/**
	 * Option counts and autoloaded size of the current site.
	 *
	 * @return array
	 */
	private function options_stats() {
		global $wpdb;
		$autoload     = function_exists( 'wp_autoload_values_to_autoload' ) ? wp_autoload_values_to_autoload() : array( 'yes' );
		$placeholders = implode( ', ', array_fill( 0, count( $autoload ), '%s' ) );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Placeholders built above.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT COUNT(*) AS total,
					SUM(CASE WHEN autoload IN ({$placeholders}) THEN 1 ELSE 0 END) AS autoload_count,
					SUM(CASE WHEN autoload IN ({$placeholders}) THEN LENGTH(option_value) ELSE 0 END) AS autoload_size
				FROM {$wpdb->options}",
				array_merge( $autoload, $autoload )
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		return array(
			'count'          => isset( $row['total'] ) ? (int) $row['total'] : null,
			'autoload_count' => isset( $row['autoload_count'] ) ? (int) $row['autoload_count'] : null,
			'autoload_size'  => isset( $row['autoload_size'] ) ? (int) $row['autoload_size'] : null,
		);
	}

	/**
	 * Number of transients stored in the options table of the current site.
	 *
	 * @return int|null
	 */
	private function transients_count() {
		global $wpdb;
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->options} WHERE (option_name LIKE %s OR option_name LIKE %s) AND option_name NOT LIKE %s AND option_name NOT LIKE %s",
				$wpdb->esc_like( '_transient_' ) . '%',
				$wpdb->esc_like( '_site_transient_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_' ) . '%',
				$wpdb->esc_like( '_site_transient_timeout_' ) . '%'
			)
		);
		return null === $count ? null : (int) $count;
	}
}
