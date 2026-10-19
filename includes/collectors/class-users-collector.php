<?php
/**
 * Scope "users_counts".
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Collectors;

use Site_Portrait\Collect_Context;

defined( 'ABSPATH' ) || exit;

/**
 * Number of users per role. Never names, logins or e-mail addresses.
 */
final class Users_Collector extends Collector {

	/**
	 * Collects.
	 *
	 * @param Collect_Context $context Context.
	 * @return array
	 */
	public function collect( Collect_Context $context ) {
		$by_role = array();
		$total   = 0;
		$add     = static function () use ( &$by_role, &$total ) {
			$counts = count_users();
			$total += (int) $counts['total_users'];
			foreach ( $counts['avail_roles'] as $role => $count ) {
				if ( $count > 0 ) {
					$by_role[ $role ] = ( $by_role[ $role ] ?? 0 ) + (int) $count;
				}
			}
		};

		if ( $context->network_wide ) {
			$context->each_site( 'by_role', $add );
			$total = (int) get_user_count();
		} else {
			$add();
		}

		return array(
			'total'         => $total,
			'by_role'       => (object) $by_role,
			'network_total' => is_multisite() ? (int) get_user_count() : null,
		);
	}
}
