<?php
/**
 * Scope definitions (PROTOCOL.md §7).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Lists scopes and their collectors.
 */
final class Scopes {

	/**
	 * Scope name => collector class.
	 */
	const COLLECTORS = array(
		'core'         => Collectors\Core_Collector::class,
		'plugins'      => Collectors\Plugins_Collector::class,
		'themes'       => Collectors\Themes_Collector::class,
		'server'       => Collectors\Server_Collector::class,
		'database'     => Collectors\Database_Collector::class,
		'content'      => Collectors\Content_Collector::class,
		'users_counts' => Collectors\Users_Collector::class,
	);

	/**
	 * All scope names, in display order.
	 *
	 * @return string[]
	 */
	public static function all() {
		return array_keys( self::COLLECTORS );
	}

	/**
	 * Keeps only known scopes, in canonical order.
	 *
	 * @param mixed $scopes Candidate list.
	 * @return string[]
	 */
	public static function sanitize( $scopes ) {
		$scopes = is_array( $scopes ) ? $scopes : array();
		return array_values( array_intersect( self::all(), $scopes ) );
	}

	/**
	 * Human-readable descriptions for the consent screen.
	 *
	 * @return array<string, array{label: string, description: string}>
	 */
	public static function descriptions() {
		return array(
			'core'         => array(
				'label'       => __( 'WordPress core', 'site-portrait' ),
				'description' => __( 'WordPress version and available update, languages, multisite summary, environment type, HTTPS, permalink type, debug flags, cron health, object and page cache detection.', 'site-portrait' ),
			),
			'plugins'      => array(
				'label'       => __( 'Plugins', 'site-portrait' ),
				'description' => __( 'Installed plugins with version, status and available update; must-use plugins and drop-ins.', 'site-portrait' ),
			),
			'themes'       => array(
				'label'       => __( 'Themes', 'site-portrait' ),
				'description' => __( 'Installed themes with version, active and parent theme, available update.', 'site-portrait' ),
			),
			'server'       => array(
				'label'       => __( 'Server', 'site-portrait' ),
				'description' => __( 'Operating system family, web server, PHP version, extensions and limits, OPcache, CPU count, memory and disk space. No host names, IP addresses or paths.', 'site-portrait' ),
			),
			'database'     => array(
				'label'       => __( 'Database', 'site-portrait' ),
				'description' => __( 'Database engine and version, total size, number of tables, largest tables, autoloaded options size. No credentials or table prefix.', 'site-portrait' ),
			),
			'content'      => array(
				'label'       => __( 'Content volumes', 'site-portrait' ),
				'description' => __( 'Number of posts per type and status, media files, taxonomy terms and comments; size of the uploads, plugins and themes folders. Counts only, never content.', 'site-portrait' ),
			),
			'users_counts' => array(
				'label'       => __( 'User counts', 'site-portrait' ),
				'description' => __( 'Number of users per role. Never names, logins or email addresses.', 'site-portrait' ),
			),
		);
	}
}
