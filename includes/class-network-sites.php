<?php
/**
 * Paginated list of the network's sites (PROTOCOL.md §6.5).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Builds the /sites response.
 */
final class Network_Sites {

	const PER_PAGE = 100;

	/**
	 * Returns one page.
	 *
	 * @param int      $page    1-based page.
	 * @param string[] $granted Granted scopes.
	 * @return array
	 */
	public static function page( $page, array $granted ) {
		$total = (int) get_sites(
			array(
				'count'      => true,
				'network_id' => get_current_network_id(),
			)
		);
		$sites = get_sites(
			array(
				'number'     => self::PER_PAGE,
				'offset'     => ( $page - 1 ) * self::PER_PAGE,
				'orderby'    => 'id',
				'order'      => 'ASC',
				'network_id' => get_current_network_id(),
			)
		);

		$with_content = in_array( 'content', $granted, true );
		$with_plugins = in_array( 'plugins', $granted, true );
		$with_themes  = in_array( 'themes', $granted, true );
		$public_types = $with_content ? self::public_post_types() : array();
		$main_site_id = get_main_site_id();

		$items = array();
		foreach ( $sites as $site ) {
			$id      = (int) $site->blog_id;
			$items[] = array(
				'site_id'              => $id,
				'url'                  => get_home_url( $id, '/' ),
				'main'                 => $main_site_id === $id,
				'public'               => (bool) (int) $site->public,
				'archived'             => (bool) (int) $site->archived,
				'spam'                 => (bool) (int) $site->spam,
				'deleted'              => (bool) (int) $site->deleted,
				'registered'           => self::date( $site->registered ),
				'last_updated'         => self::date( $site->last_updated ),
				'active_theme'         => $with_themes ? (string) get_blog_option( $id, 'stylesheet' ) : null,
				'active_plugins_count' => $with_plugins ? count( (array) get_blog_option( $id, 'active_plugins', array() ) ) : null,
				'posts_count'          => $with_content ? self::count_posts( $id, $public_types ) : null,
				'attachments_count'    => $with_content ? self::count_posts( $id, array( 'attachment' ), 'inherit' ) : null,
			);
		}

		return array(
			'page'        => $page,
			'per_page'    => self::PER_PAGE,
			'total'       => $total,
			'total_pages' => (int) ceil( $total / self::PER_PAGE ),
			'sites'       => $items,
		);
	}

	/**
	 * Public post types registered on the current request, attachments excluded.
	 *
	 * @return string[]
	 */
	private static function public_post_types() {
		return array_values( array_diff( get_post_types( array( 'public' => true ) ), array( 'attachment' ) ) );
	}

	/**
	 * Counts posts of a site with a direct query (no blog switch needed).
	 *
	 * @param int      $site_id Site ID.
	 * @param string[] $types   Post types.
	 * @param string   $status  Post status.
	 * @return int
	 */
	private static function count_posts( $site_id, array $types, $status = 'publish' ) {
		global $wpdb;
		if ( empty( $types ) ) {
			return 0;
		}
		$table        = $wpdb->get_blog_prefix( $site_id ) . 'posts';
		$placeholders = implode( ', ', array_fill( 0, count( $types ), '%s' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Core table of another site; placeholders built above.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE post_status = %s AND post_type IN ({$placeholders})", array_merge( array( $status ), $types ) ) );
	}

	/**
	 * Converts a MySQL GMT datetime to RFC 3339.
	 *
	 * @param string $mysql_date Date.
	 * @return string|null
	 */
	private static function date( $mysql_date ) {
		if ( empty( $mysql_date ) || '0000-00-00 00:00:00' === $mysql_date ) {
			return null;
		}
		$time = strtotime( $mysql_date . ' UTC' );
		return false === $time ? null : gmdate( 'Y-m-d\TH:i:s\Z', $time );
	}
}
