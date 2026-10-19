<?php
/**
 * Scope "content".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Aggregate counts over core tables; must be fresh.

/**
 * Counts per post type and status, media, terms, comments, and folder sizes.
 * Never returns content, titles or file names.
 */
final class Content_Collector extends Collector {

	const SIZES_TRANSIENT = 'site_portrait_sizes';

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		$totals = array(
			'posts'       => array(),
			'attachments' => array(),
			'terms'       => array(),
			'comments'    => array(),
		);
		$add    = function () use ( &$totals ) {
			$this->add_site_counts( $totals );
		};
		if ( $context->network_wide ) {
			$context->each_site( null, $add );
		} else {
			$add();
		}

		$post_types = array();
		$revisions  = 0;
		foreach ( $totals['posts'] as $type => $statuses ) {
			if ( 'revision' === $type ) {
				$revisions = array_sum( $statuses );
				continue;
			}
			if ( 'attachment' === $type ) {
				continue;
			}
			$object            = get_post_type_object( $type );
			$statuses['total'] = array_sum( $statuses );
			$post_types[]      = array(
				'name'       => (string) $type,
				'registered' => null !== $object,
				'builtin'    => null !== $object && $object->_builtin,
				'public'     => null !== $object ? (bool) $object->public : null,
				'counts'     => $statuses,
			);
		}

		$taxonomies = array();
		foreach ( $totals['terms'] as $name => $count ) {
			$object       = get_taxonomy( $name );
			$taxonomies[] = array(
				'name'        => (string) $name,
				'registered'  => false !== $object,
				'builtin'     => false !== $object && $object->_builtin,
				'public'      => false !== $object ? (bool) $object->public : null,
				'terms_count' => $count,
			);
		}

		$comments = wp_parse_args(
			$totals['comments'],
			array(
				'approved' => 0,
				'pending'  => 0,
				'spam'     => 0,
				'trash'    => 0,
			)
		);
		$comments = array(
			'approved' => $comments['approved'],
			'pending'  => $comments['pending'],
			'spam'     => $comments['spam'],
			'trash'    => $comments['trash'],
			'total'    => array_sum( $totals['comments'] ),
		);

		return array(
			'post_types'      => $post_types,
			'revisions_count' => $revisions,
			'attachments'     => array(
				'total'   => array_sum( $totals['attachments'] ),
				'by_type' => (object) $totals['attachments'],
			),
			'taxonomies'      => $taxonomies,
			'comments'        => $comments,
			'sizes'           => $this->sizes( $context ),
		);
	}

	/**
	 * Adds the current site's counts to the totals.
	 *
	 * @param array $totals Totals, by reference.
	 */
	private function add_site_counts( array &$totals ) {
		global $wpdb;

		$rows = $wpdb->get_results( "SELECT post_type, post_status, COUNT(*) AS n FROM {$wpdb->posts} GROUP BY post_type, post_status", ARRAY_A );
		foreach ( (array) $rows as $row ) {
			$type   = (string) $row['post_type'];
			$status = (string) $row['post_status'];
			if ( 'auto-draft' === $status ) {
				continue;
			}
			$totals['posts'][ $type ][ $status ] = ( $totals['posts'][ $type ][ $status ] ?? 0 ) + (int) $row['n'];
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT post_mime_type, COUNT(*) AS n FROM {$wpdb->posts} WHERE post_type = %s GROUP BY post_mime_type", 'attachment' ),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$family = strtolower( strtok( (string) $row['post_mime_type'], '/' ) );
			if ( ! in_array( $family, array( 'image', 'video', 'audio', 'application', 'text' ), true ) ) {
				$family = 'other';
			}
			$totals['attachments'][ $family ] = ( $totals['attachments'][ $family ] ?? 0 ) + (int) $row['n'];
		}

		$rows = $wpdb->get_results( "SELECT taxonomy, COUNT(*) AS n FROM {$wpdb->term_taxonomy} GROUP BY taxonomy", ARRAY_A );
		foreach ( (array) $rows as $row ) {
			$name                     = (string) $row['taxonomy'];
			$totals['terms'][ $name ] = ( $totals['terms'][ $name ] ?? 0 ) + (int) $row['n'];
		}

		$map  = array(
			'1'     => 'approved',
			'0'     => 'pending',
			'spam'  => 'spam',
			'trash' => 'trash',
		);
		$rows = $wpdb->get_results( "SELECT comment_approved, COUNT(*) AS n FROM {$wpdb->comments} GROUP BY comment_approved", ARRAY_A );
		foreach ( (array) $rows as $row ) {
			$key                        = $map[ (string) $row['comment_approved'] ] ?? 'other';
			$totals['comments'][ $key ] = ( $totals['comments'][ $key ] ?? 0 ) + (int) $row['n'];
		}
	}

	/**
	 * Folder sizes, cached for an hour per site (PROTOCOL.md §8.4).
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	private function sizes( Collect_Context $context ) {
		$cache_key = self::SIZES_TRANSIENT . '_' . get_current_blog_id();
		$cached    = get_site_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		/**
		 * Filters the time budget, in seconds, for computing folder sizes.
		 *
		 * @param float $budget Seconds.
		 */
		$budget   = (float) apply_filters( 'site_portrait_size_budget', 10 );
		$deadline = microtime( true ) + $budget;

		$uploads = wp_get_upload_dir();
		$paths   = array(
			'uploads'    => $uploads['basedir'],
			'plugins'    => WP_PLUGIN_DIR,
			'themes'     => get_theme_root(),
			'wp_content' => WP_CONTENT_DIR,
		);

		$sizes    = array();
		$complete = true;
		foreach ( $paths as $name => $path ) {
			if ( ! file_exists( $path ) ) {
				// No uploads yet, for instance.
				$sizes[ $name ] = 0;
				continue;
			}
			$remaining = $deadline - microtime( true );
			if ( $remaining <= 0 ) {
				$sizes[ $name ] = null;
				$complete       = false;
				$context->warn( 'sizes.' . $name, 'timeout', 'Time budget exhausted before computing this size.' );
				continue;
			}
			// recurse_dirsize() compares elapsed time since WP_START_TIMESTAMP with this limit.
			// A fresh in-memory cache bypasses the persistent dirsize_cache, which can be stale.
			$limit = (int) ceil( microtime( true ) - WP_START_TIMESTAMP + $remaining );
			$memo  = array();
			$size  = recurse_dirsize( $path, null, $limit, $memo );
			if ( null === $size ) {
				$complete = false;
				$context->warn( 'sizes.' . $name, 'timeout', 'Size computation timed out.' );
			} elseif ( false === $size ) {
				$size = null;
				$context->warn( 'sizes.' . $name, 'permission_denied', 'Folder missing or not readable.' );
			}
			$sizes[ $name ] = null === $size ? null : (int) $size;
		}

		$sizes['computed_at'] = self::rfc3339( time() );
		if ( $complete ) {
			set_site_transient( $cache_key, $sizes, HOUR_IN_SECONDS );
		}
		return $sizes;
	}
}
