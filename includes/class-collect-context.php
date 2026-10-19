<?php
/**
 * State shared by collectors while a portrait is built.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Carries the mode, the requested site, a time budget and warnings.
 */
final class Collect_Context {

	/**
	 * Requested site in network mode, or null.
	 *
	 * @var int|null
	 */
	public $site_id;

	/**
	 * Whether the portrait describes a whole network.
	 *
	 * @var bool
	 */
	public $network_wide;

	/**
	 * Scope being collected.
	 *
	 * @var string
	 */
	public $scope = '';

	/**
	 * Warnings (PROTOCOL.md §8.1).
	 *
	 * @var array
	 */
	private $warnings = array();

	/**
	 * Absolute deadline (microtime) for loops over network sites.
	 *
	 * @var float
	 */
	private $deadline;

	/**
	 * Constructor.
	 *
	 * @param int|null $site_id      Requested site.
	 * @param bool     $network_wide Network-wide portrait.
	 * @param float    $budget       Seconds allowed for loops over sites.
	 */
	public function __construct( $site_id, $network_wide, $budget ) {
		$this->site_id      = $site_id;
		$this->network_wide = $network_wide;
		$this->deadline     = microtime( true ) + $budget;
	}

	/**
	 * Adds a warning for the current scope.
	 *
	 * @param string|null $field   Dot path inside the scope, or null.
	 * @param string      $code    unavailable|timeout|partial|permission_denied|collector_error.
	 * @param string      $message English message for the service.
	 */
	public function warn( $field, $code, $message ) {
		$this->warnings[] = array(
			'scope'   => $this->scope,
			'field'   => $field,
			'code'    => $code,
			'message' => $message,
		);
	}

	/**
	 * Returns the warnings.
	 *
	 * @return array
	 */
	public function warnings() {
		return $this->warnings;
	}

	/**
	 * Whether the time budget for loops is exhausted.
	 *
	 * @return bool
	 */
	public function out_of_time() {
		return microtime( true ) > $this->deadline;
	}

	/**
	 * IDs of the network's sites (active ones), capped at 10 000.
	 *
	 * @return int[]
	 */
	public function network_site_ids() {
		return array_map(
			'intval',
			get_sites(
				array(
					'fields'     => 'ids',
					'number'     => 10000,
					'network_id' => get_current_network_id(),
					'archived'   => 0,
					'spam'       => 0,
					'deleted'    => 0,
				)
			)
		);
	}

	/**
	 * Calls $callback for each site of the network (switching blogs) until
	 * the time budget runs out; adds a "partial" warning in that case.
	 *
	 * @param string   $field    Field reported in the warning.
	 * @param callable $callback Receives the site ID.
	 */
	public function each_site( $field, callable $callback ) {
		$ids = $this->network_site_ids();
		foreach ( $ids as $index => $id ) {
			if ( $this->out_of_time() ) {
				$this->warn(
					$field,
					'partial',
					sprintf( 'Time budget exhausted after %1$d of %2$d sites.', $index, count( $ids ) )
				);
				return;
			}
			switch_to_blog( $id );
			try {
				$callback( $id );
			} finally {
				restore_current_blog();
			}
		}
	}
}
