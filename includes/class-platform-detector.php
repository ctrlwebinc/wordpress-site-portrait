<?php
/**
 * Best-effort detection of the WordPress distribution (PROTOCOL.md §2.2).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Detects Composer-based WordPress distributions (Bedrock, Radicle, WordPlate,
 * WP Starter) from heuristics: Composer's runtime API when it is loaded, the
 * presence of a few classes, and the relative layout of ABSPATH and
 * WP_CONTENT_DIR. It never reads .env files, makes no network request and
 * never returns a path.
 *
 * The gather() method collects facts from the running site; classify() is a
 * pure function of those facts, unit-tested with fixtures.
 */
final class Platform_Detector {

	/**
	 * Composer packages that install the WordPress core.
	 */
	const CORE_PACKAGES = array( 'roots/wordpress', 'roots/wordpress-no-content', 'roots/wordpress-full', 'johnpbloch/wordpress', 'johnpbloch/wordpress-core' );

	/**
	 * Prefix of the official core packages (wordpress/core-implementation…).
	 */
	const CORE_PREFIX = 'wordpress/core-';

	/**
	 * Other packages used as signatures. wpstarter/* on Packagist is an
	 * unrelated project: only wecodemore/wpstarter designates WP Starter.
	 */
	const SIGNATURE_PACKAGES = array( 'roots/wp-config', 'roots/bedrock', 'roots/radicle', 'roots/acorn', 'vinkla/wordplate', 'wordplate/framework', 'wecodemore/wpstarter' );

	/**
	 * Cached result for the current request.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Distribution members of the platform object, cached per request.
	 *
	 * @return array{distribution: string|null, distribution_version: string|null, composer_managed: bool, acorn: string|null}
	 */
	public static function detect() {
		if ( null === self::$cache ) {
			try {
				self::$cache = self::classify( self::gather() );
			} catch ( \Throwable $e ) {
				self::$cache = self::classify( array() );
			}
		}
		return self::$cache;
	}

	/**
	 * Classifies the installation.
	 *
	 * @param array $facts {
	 *     Facts collected by gather(); every key is optional.
	 *
	 *     @type array|null  $root            Root Composer package: name, version.
	 *     @type array       $packages        Relevant installed packages: name => pretty version or null.
	 *     @type array       $classes         wp_config, acorn: booleans.
	 *     @type bool        $wp_env          The WP_ENV constant is defined.
	 *     @type array       $layout          Output of layout().
	 *     @type bool|null   $acorn_root_boot Acorn's base path is the project root rather than a theme.
	 * }
	 * @return array
	 */
	public static function classify( array $facts ) {
		$root     = isset( $facts['root']['name'] ) ? $facts['root'] : array(
			'name'    => null,
			'version' => null,
		);
		$packages = isset( $facts['packages'] ) && is_array( $facts['packages'] ) ? $facts['packages'] : array();
		$layout   = ( isset( $facts['layout'] ) && is_array( $facts['layout'] ) ? $facts['layout'] : array() ) + array(
			'core_dir'    => null,
			'content_dir' => null,
			'docroot'     => null,
			'siblings'    => false,
		);
		$wp_env   = ! empty( $facts['wp_env'] );

		$has = static function ( $name ) use ( $root, $packages ) {
			return $root['name'] === $name || array_key_exists( $name, $packages );
		};
		$ver = static function ( $name ) use ( $root, $packages ) {
			if ( $root['name'] === $name ) {
				return isset( $root['version'] ) ? (string) $root['version'] : null;
			}
			return isset( $packages[ $name ] ) ? (string) $packages[ $name ] : null;
		};

		$core_composer = false;
		foreach ( array_keys( $packages ) as $name ) {
			if ( in_array( $name, self::CORE_PACKAGES, true ) || 0 === strpos( $name, self::CORE_PREFIX ) ) {
				$core_composer = true;
				break;
			}
		}

		$acorn_version  = $ver( 'roots/acorn' );
		$acorn_present  = null !== $acorn_version || $has( 'roots/acorn' ) || ! empty( $facts['classes']['acorn'] );
		$bedrock_config = ! empty( $facts['classes']['wp_config'] ) || $has( 'roots/wp-config' );
		$siblings       = ! empty( $layout['siblings'] );
		$bedrock_layout = $siblings && 'wp' === $layout['core_dir'] && 'app' === $layout['content_dir'] && 'web' === $layout['docroot'];
		$radicle_layout = $siblings && 'wp' === $layout['core_dir'] && 'content' === $layout['content_dir'] && 'public' === $layout['docroot'];
		$wordplate_dirs = 'public' === $layout['docroot'] && 'wordpress' === $layout['core_dir']; // phpcs:ignore WordPress.WP.CapitalPDangit.MisspelledInText -- Directory name.

		$distribution = null;
		$version      = null;
		if ( $has( 'wecodemore/wpstarter' ) ) {
			$distribution = 'wpstarter';
			$version      = $ver( 'wecodemore/wpstarter' );
		} elseif ( $has( 'vinkla/wordplate' ) || $has( 'wordplate/framework' ) || ( $core_composer && $wordplate_dirs ) ) {
			$distribution = 'wordplate';
			$version      = $has( 'vinkla/wordplate' ) ? $ver( 'vinkla/wordplate' ) : $ver( 'wordplate/framework' );
		} elseif ( $acorn_present && ( $bedrock_config || $wp_env ) && ( ! empty( $facts['acorn_root_boot'] ) || $radicle_layout ) ) {
			$distribution = 'radicle';
			$version      = $ver( 'roots/radicle' );
		} elseif ( $bedrock_config || $has( 'roots/bedrock' ) || $bedrock_layout || ( $wp_env && $core_composer ) ) {
			$distribution = 'bedrock';
			$version      = $ver( 'roots/bedrock' );
		} elseif ( $core_composer ) {
			$distribution = 'composer';
		}

		return array(
			'distribution'         => $distribution,
			'distribution_version' => $version,
			'composer_managed'     => $core_composer || null !== $distribution,
			'acorn'                => $acorn_version,
		);
	}

	/**
	 * Relative layout of the core and content directories. Only directory
	 * names and their relationship are kept, never a path.
	 *
	 * @param string $abspath     ABSPATH.
	 * @param string $content_dir WP_CONTENT_DIR.
	 * @return array{core_dir: string, content_dir: string, docroot: string, siblings: bool}
	 */
	public static function layout( $abspath, $content_dir ) {
		$core    = self::normalize( $abspath );
		$content = self::normalize( $content_dir );
		return array(
			'core_dir'    => basename( $core ),
			'content_dir' => basename( $content ),
			'docroot'     => basename( dirname( $core ) ),
			'siblings'    => dirname( $core ) === dirname( $content ),
		);
	}

	/**
	 * Collects facts from the running site.
	 *
	 * @return array
	 */
	public static function gather() {
		$facts = array(
			'root'            => null,
			'packages'        => array(),
			'classes'         => array(
				'wp_config' => class_exists( 'Roots\\WPConfig\\Config' ),
				'acorn'     => class_exists( 'Roots\\Acorn\\Application' ),
			),
			'wp_env'          => defined( 'WP_ENV' ),
			'layout'          => defined( 'WP_CONTENT_DIR' ) ? self::layout( ABSPATH, WP_CONTENT_DIR ) : array(),
			'acorn_root_boot' => self::acorn_root_boot(),
		);

		if ( class_exists( 'Composer\\InstalledVersions' ) ) {
			$root              = \Composer\InstalledVersions::getRootPackage();
			$facts['root']     = array(
				'name'    => isset( $root['name'] ) ? (string) $root['name'] : null,
				'version' => isset( $root['pretty_version'] ) ? (string) $root['pretty_version'] : null,
			);
			$facts['packages'] = self::relevant_packages( \Composer\InstalledVersions::getInstalledPackages() );
		}
		return $facts;
	}

	/**
	 * Keeps the signature packages and their versions.
	 *
	 * @param string[] $names Installed package names.
	 * @return array
	 */
	private static function relevant_packages( array $names ) {
		$packages = array();
		foreach ( array_unique( $names ) as $name ) {
			if ( in_array( $name, self::CORE_PACKAGES, true ) || in_array( $name, self::SIGNATURE_PACKAGES, true ) || 0 === strpos( $name, self::CORE_PREFIX ) ) {
				$packages[ $name ] = \Composer\InstalledVersions::getPrettyVersion( $name );
			}
		}
		return $packages;
	}

	/**
	 * Whether a booted Acorn application has the project root (the parent of
	 * the web root) as base path, as in Radicle, rather than a theme.
	 *
	 * @return bool|null Null when Acorn is not booted.
	 */
	private static function acorn_root_boot() {
		if ( ! class_exists( 'Roots\\Acorn\\Application', false ) || ! is_callable( array( 'Roots\\Acorn\\Application', 'getInstance' ) ) ) {
			return null;
		}
		$app = \Roots\Acorn\Application::getInstance();
		if ( ! is_object( $app ) || ! method_exists( $app, 'basePath' ) ) {
			return null;
		}
		$project = dirname( dirname( self::normalize( ABSPATH ) ) );
		return self::normalize( $app->basePath() ) === $project;
	}

	/**
	 * Forward slashes, no trailing slash.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	private static function normalize( $path ) {
		$path = rtrim( str_replace( '\\', '/', (string) $path ), '/' );
		return '' === $path ? '/' : $path;
	}
}
