<?php
/**
 * Plugin Name:       Site Portrait
 * Description:       Lets a service you choose securely read a technical portrait of your site (versions, server, database, content volumes) to recommend suitable hosting.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      7.4
 * Author:            Ctrlweb
 * Author URI:        https://ctrlweb.ca
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       site-portrait
 * Network:           true
 *
 * @package Site_Portrait
 */

defined( 'ABSPATH' ) || exit;

define( 'SITE_PORTRAIT_VERSION', '0.1.0' );
define( 'SITE_PORTRAIT_FILE', __FILE__ );
define( 'SITE_PORTRAIT_DIR', plugin_dir_path( __FILE__ ) );

require_once SITE_PORTRAIT_DIR . 'includes/autoload.php';

register_activation_hook( __FILE__, array( 'Site_Portrait\Installer', 'activate' ) );

add_action( 'plugins_loaded', array( 'Site_Portrait\Plugin', 'boot' ) );
