<?php
/**
 * Builds the portrait document (PROTOCOL.md §8).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Runs the collectors of the requested scopes and wraps their output.
 */
final class Portrait_Builder {

	const SCHEMA_VERSION = '1.0.0';

	/**
	 * Builds the portrait.
	 *
	 * @param string[] $scopes  Scopes to return (already checked against the grant).
	 * @param string[] $denied  Requested scopes that are not granted.
	 * @param int|null $site_id Network site, or null.
	 * @return array
	 */
	public static function build( array $scopes, array $denied, $site_id ) {
		$start = microtime( true );

		self::load_admin_functions();

		/**
		 * Filters the time budget, in seconds, for loops over network sites.
		 *
		 * @param float $budget Seconds.
		 */
		$budget  = (float) apply_filters( 'site_portrait_network_budget', 15 );
		$context = new Collect_Context( $site_id, Plugin::is_network_mode() && null === $site_id, $budget );

		$switched = null !== $site_id && get_current_blog_id() !== $site_id;
		if ( $switched ) {
			switch_to_blog( $site_id );
		}

		try {
			$data = array();
			foreach ( $scopes as $scope ) {
				$data[ $scope ] = self::collect( $scope, $context );
			}
			$site = array(
				'home_url' => home_url(),
				'site_url' => site_url(),
				'name'     => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			);
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}

		return array(
			'schema_version'     => self::SCHEMA_VERSION,
			'protocol_version'   => '1',
			'generated_at'       => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'generation_time_ms' => (int) round( ( microtime( true ) - $start ) * 1000 ),
			'pairing_id'         => Pairing::get()['pairing_id'],
			'mode'               => Plugin::mode(),
			'site_id'            => $site_id,
			'site'               => $site,
			'plugin'             => array( 'version' => SITE_PORTRAIT_VERSION ),
			'scopes_returned'    => $scopes,
			'scopes_denied'      => $denied,
			'data'               => (object) $data,
			'warnings'           => $context->warnings(),
		);
	}

	/**
	 * Runs one collector, isolating failures.
	 *
	 * @param string          $scope   Scope.
	 * @param Collect_Context $context Context.
	 * @return array|null
	 */
	private static function collect( $scope, Collect_Context $context ) {
		$context->scope = $scope;
		$class          = Scopes::COLLECTORS[ $scope ];
		try {
			$result = ( new $class() )->collect( $context );
		} catch ( \Throwable $e ) {
			// The exception message may contain paths; it is not returned.
			$context->warn( null, 'collector_error', 'The collector failed.' );
			return null;
		}

		/**
		 * Lets other plugins add data to a scope, under extensions.<their-slug>.
		 *
		 * Return an array keyed by your plugin slug. Core members cannot be
		 * changed. Never add secrets or personal data.
		 *
		 * @param array           $extensions Extensions so far.
		 * @param string          $scope      Scope name.
		 * @param Collect_Context $context    Collection context.
		 */
		$extensions = apply_filters( 'site_portrait_scope_data', array(), $scope, $context );
		if ( is_array( $extensions ) ) {
			$extensions = array_filter(
				$extensions,
				static function ( $value, $key ) {
					return is_string( $key ) && is_array( $value );
				},
				ARRAY_FILTER_USE_BOTH
			);
			if ( ! empty( $extensions ) ) {
				$result['extensions'] = $extensions;
			}
		}
		return $result;
	}

	/**
	 * Loads admin APIs used by collectors (get_plugins(), get_core_updates()…).
	 */
	private static function load_admin_functions() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/theme.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-debug-data.php';
	}
}
