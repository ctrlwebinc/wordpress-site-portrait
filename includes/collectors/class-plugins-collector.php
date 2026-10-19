<?php
/**
 * Scope "plugins".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;

defined( 'ABSPATH' ) || exit;

/**
 * Installed plugins, must-use plugins and drop-ins.
 */
final class Plugins_Collector extends Collector {

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		$plugins        = get_plugins();
		$updates        = get_site_transient( 'update_plugins' );
		$auto_updates   = (array) get_site_option( 'auto_update_plugins', array() );
		$auto_enabled   = wp_is_auto_update_enabled_for_type( 'plugin' );
		$network_active = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();

		// Sites on which each plugin is active (network-wide portrait), or the current site's list.
		$active_sites = array();
		if ( $context->network_wide ) {
			$context->each_site(
				'items',
				static function () use ( &$active_sites ) {
					foreach ( (array) get_option( 'active_plugins', array() ) as $file ) {
						$active_sites[ $file ] = ( $active_sites[ $file ] ?? 0 ) + 1;
					}
				}
			);
		} else {
			foreach ( (array) get_option( 'active_plugins', array() ) as $file ) {
				$active_sites[ $file ] = 1;
			}
		}

		$items  = array();
		$counts = array(
			'total'             => 0,
			'active'            => 0,
			'inactive'          => 0,
			'updates_available' => 0,
		);
		foreach ( $plugins as $file => $header ) {
			$is_network = in_array( $file, $network_active, true );
			$is_active  = $is_network || ! empty( $active_sites[ $file ] );
			$update     = $this->update_info( $updates, $file );

			$item = array(
				'file'           => $file,
				'slug'           => $this->slug( $file ),
				'name'           => wp_strip_all_tags( $header['Name'] ),
				'version'        => (string) $header['Version'],
				'active'         => $is_active,
				'network_active' => $is_network,
				'auto_update'    => $auto_enabled && in_array( $file, $auto_updates, true ),
				'update'         => $update,
				'requires_wp'    => '' !== ( $header['RequiresWP'] ?? '' ) ? (string) $header['RequiresWP'] : null,
				'requires_php'   => '' !== ( $header['RequiresPHP'] ?? '' ) ? (string) $header['RequiresPHP'] : null,
			);
			if ( $context->network_wide ) {
				$item['active_sites'] = (int) ( $active_sites[ $file ] ?? 0 );
			}
			$items[] = $item;

			++$counts['total'];
			++$counts[ $is_active ? 'active' : 'inactive' ];
			if ( null !== $update && $update['available'] ) {
				++$counts['updates_available'];
			}
		}

		$must_use = array();
		foreach ( get_mu_plugins() as $file => $header ) {
			$must_use[] = array(
				'file'    => $file,
				'name'    => wp_strip_all_tags( $header['Name'] ),
				'version' => '' !== $header['Version'] ? (string) $header['Version'] : null,
			);
		}

		$dropins = array();
		foreach ( get_dropins() as $file => $header ) {
			$dropins[] = array(
				'file' => $file,
				'name' => '' !== ( $header['Name'] ?? '' ) ? wp_strip_all_tags( $header['Name'] ) : null,
			);
		}

		$counts['must_use'] = count( $must_use );
		$counts['dropins']  = count( $dropins );

		return array(
			'counts'   => $counts,
			'items'    => $items,
			'must_use' => $must_use,
			'dropins'  => $dropins,
		);
	}

	/**
	 * Update information from the update_plugins transient.
	 *
	 * @param mixed  $updates Transient value.
	 * @param string $file    Plugin file.
	 * @return array|null
	 */
	private function update_info( $updates, $file ) {
		if ( ! is_object( $updates ) ) {
			return null;
		}
		if ( isset( $updates->response[ $file ]->new_version ) ) {
			return array(
				'available' => true,
				'version'   => (string) $updates->response[ $file ]->new_version,
			);
		}
		if ( isset( $updates->no_update[ $file ] ) ) {
			return array(
				'available' => false,
				'version'   => null,
			);
		}
		return null;
	}

	/**
	 * Directory slug of a plugin file.
	 *
	 * @param string $file Plugin file.
	 * @return string
	 */
	private function slug( $file ) {
		$dir = dirname( $file );
		return '.' === $dir ? basename( $file, '.php' ) : $dir;
	}
}
