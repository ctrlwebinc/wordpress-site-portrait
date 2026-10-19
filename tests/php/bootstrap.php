<?php
/**
 * PHPUnit bootstrap for unit tests that do not need WordPress.
 *
 * @package Site_Portrait
 */

define( 'ABSPATH', __DIR__ . '/' );

require dirname( __DIR__, 2 ) . '/vendor/autoload.php';
require dirname( __DIR__, 2 ) . '/includes/autoload.php';
