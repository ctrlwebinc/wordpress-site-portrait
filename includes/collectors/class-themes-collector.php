<?php
/**
 * Scope "themes".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;

defined( 'ABSPATH' ) || exit;

/**
 * Installed themes and active theme.
 */
final class Themes_Collector extends Collector {

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		$updates      = get_site_transient( 'update_themes' );
		$auto_updates = (array) get_site_option( 'auto_update_themes', array() );
		$auto_enabled = wp_is_auto_update_enabled_for_type( 'theme' );

		// Stylesheets and templates in use (on any site for a network-wide portrait).
		$used_as_active = array();
		$used_as_parent = array();
		$record         = static function () use ( &$used_as_active, &$used_as_parent ) {
			$used_as_active[ get_stylesheet() ] = true;
			if ( get_template() !== get_stylesheet() ) {
				$used_as_parent[ get_template() ] = true;
			}
		};
		if ( $context->network_wide ) {
			$context->each_site( 'items', $record );
		} else {
			$record();
		}

		$items   = array();
		$pending = 0;
		foreach ( wp_get_themes() as $slug => $theme ) {
			$update = null;
			if ( is_object( $updates ) ) {
				if ( isset( $updates->response[ $slug ]['new_version'] ) ) {
					$update = array(
						'available' => true,
						'version'   => (string) $updates->response[ $slug ]['new_version'],
					);
					++$pending;
				} elseif ( isset( $updates->no_update[ $slug ] ) ) {
					$update = array(
						'available' => false,
						'version'   => null,
					);
				}
			}

			$parent  = $theme->parent();
			$items[] = array(
				'slug'             => (string) $slug,
				'name'             => wp_strip_all_tags( $theme->get( 'Name' ) ),
				'version'          => (string) $theme->get( 'Version' ),
				'active'           => isset( $used_as_active[ $slug ] ),
				'parent_of_active' => isset( $used_as_parent[ $slug ] ),
				'parent_slug'      => $parent ? $parent->get_stylesheet() : null,
				'block_theme'      => method_exists( $theme, 'is_block_theme' ) ? $theme->is_block_theme() : null,
				'auto_update'      => $auto_enabled && in_array( $slug, $auto_updates, true ),
				'update'           => $update,
			);
		}

		return array(
			'active' => get_stylesheet(),
			'counts' => array(
				'total'             => count( $items ),
				'updates_available' => $pending,
			),
			'items'  => $items,
		);
	}
}
