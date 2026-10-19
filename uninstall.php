<?php
/**
 * Uninstall: notifies the service (best effort) and removes all plugin data.
 *
 * @package Site_Portrait
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

if ( ! defined( 'SITE_PORTRAIT_VERSION' ) ) {
	define( 'SITE_PORTRAIT_VERSION', '0.1.0' );
}
if ( ! defined( 'SITE_PORTRAIT_FILE' ) ) {
	define( 'SITE_PORTRAIT_FILE', __DIR__ . '/site-portrait.php' );
}

require_once __DIR__ . '/includes/autoload.php';

Site_Portrait\Installer::uninstall();
