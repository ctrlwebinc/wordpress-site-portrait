<?php
/**
 * Settings screen and admin action handlers.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait\Admin;

use Site_Portrait\Access_Log;
use Site_Portrait\Ip_Allowlist;
use Site_Portrait\Pairing;
use Site_Portrait\Plugin;
use Site_Portrait\Scopes;
use Site_Portrait\Service_Client;
use Site_Portrait\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Settings → Site Portrait (or Network Admin → Settings → Site Portrait).
 */
final class Settings_Page {

	const ACTIONS       = array( 'discover', 'connect', 'cancel', 'callback', 'save', 'rotate', 'disconnect' );
	const DISCOVERY_TTL = 15 * MINUTE_IN_SECONDS;

	/**
	 * Registers hooks.
	 */
	public static function init() {
		if ( Plugin::is_network_mode() ) {
			add_action( 'network_admin_menu', array( self::class, 'add_menu' ) );
			add_filter( 'network_admin_plugin_action_links_' . plugin_basename( SITE_PORTRAIT_FILE ), array( self::class, 'action_links' ) );
		} else {
			add_action( 'admin_menu', array( self::class, 'add_menu' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( SITE_PORTRAIT_FILE ), array( self::class, 'action_links' ) );
		}

		foreach ( self::ACTIONS as $action ) {
			$hook = Plugin::is_network_mode() ? 'network_admin_edit_site_portrait_' . $action : 'admin_post_site_portrait_' . $action;
			add_action( $hook, array( self::class, 'handle_' . $action ) );
		}
	}

	/**
	 * Adds the menu entry.
	 */
	public static function add_menu() {
		$title = __( 'ctrlweb Site Portrait', 'ctrlweb-site-portrait' );
		$menu  = __( 'Site Portrait', 'ctrlweb-site-portrait' );
		if ( Plugin::is_network_mode() ) {
			add_submenu_page( 'settings.php', $title, $menu, Plugin::capability(), 'ctrlweb-site-portrait', array( self::class, 'render' ) );
		} else {
			add_options_page( $title, $menu, Plugin::capability(), 'ctrlweb-site-portrait', array( self::class, 'render' ) );
		}
	}

	/**
	 * Adds a Settings link in the plugins list.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( Plugin::settings_url() ) . '">' . esc_html__( 'Settings', 'ctrlweb-site-portrait' ) . '</a>' );
		return $links;
	}

	/**
	 * Notice shown on multisite when the plugin is activated on a single site.
	 */
	public static function render_network_required_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'plugins' !== $screen->id || ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		esc_html_e( 'Site Portrait describes the whole server and database, so on a multisite network it must be network-activated by a super admin. It does nothing while activated on a single site; deactivate it here and network-activate it from the Network Admin.', 'ctrlweb-site-portrait' );
		echo '</p></div>';
	}

	/*
	 * ---------------------------------------------------------------------
	 * Action handlers.
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Looks up the service entered by the administrator.
	 */
	public static function handle_discover() {
		self::guard( 'site_portrait_discover' );
		$url       = isset( $_POST['service_url'] ) ? sanitize_text_field( wp_unslash( $_POST['service_url'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard().
		$discovery = Service_Client::discover( $url );
		if ( is_wp_error( $discovery ) ) {
			self::redirect_with_notice( 'error', $discovery->get_error_message() );
		}
		Store::set_transient( self::discovery_key(), $discovery, self::DISCOVERY_TTL );
		self::redirect();
	}

	/**
	 * Starts the authorization after explicit consent.
	 */
	public static function handle_connect() {
		self::guard( 'site_portrait_connect' );
		$discovery = Store::get_transient( self::discovery_key() );
		if ( ! is_array( $discovery ) ) {
			self::redirect_with_notice( 'error', __( 'The service information expired. Please look up the service again.', 'ctrlweb-site-portrait' ) );
		}
		$scopes = isset( $_POST['scopes'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['scopes'] ) ) : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard().
		$url    = Pairing::begin( $discovery, $scopes, get_current_user_id() );
		if ( is_wp_error( $url ) ) {
			self::redirect_with_notice( 'error', $url->get_error_message() );
		}
		Store::delete_transient( self::discovery_key() );

		$host = wp_parse_url( $url, PHP_URL_HOST );
		add_filter(
			'allowed_redirect_hosts',
			static function ( $hosts ) use ( $host ) {
				$hosts[] = $host;
				return $hosts;
			}
		);
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Cancels a lookup or pending pairing.
	 */
	public static function handle_cancel() {
		self::guard( 'site_portrait_cancel' );
		Store::delete_transient( self::discovery_key() );
		Pairing::cancel_pending( get_current_user_id() );
		self::redirect();
	}

	/**
	 * Browser comes back from the service (PROTOCOL.md §4.3).
	 */
	public static function handle_callback() {
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_key( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'site_portrait_callback' ) || ! current_user_can( Plugin::capability() ) ) {
			wp_die( esc_html__( 'The link you followed has expired or you are not allowed to connect this site.', 'ctrlweb-site-portrait' ), 403 );
		}
		$user_id = get_current_user_id();

		if ( isset( $_GET['error'] ) ) {
			Pairing::cancel_pending( $user_id );
			$error       = sanitize_key( wp_unslash( $_GET['error'] ) );
			$description = isset( $_GET['error_description'] ) ? Service_Client::text( wp_unslash( $_GET['error_description'] ), 300 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized by Service_Client::text().
			$message     = 'access_denied' === $error
				? __( 'The connection was declined on the service side.', 'ctrlweb-site-portrait' )
				/* translators: %s: error code returned by the service. */
				: sprintf( __( 'The service returned an error: %s', 'ctrlweb-site-portrait' ), $error );
			self::redirect_with_notice( 'error', trim( $message . ' ' . $description ) );
		}

		$code   = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$state  = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$result = Pairing::complete( $user_id, $code, $state );
		if ( is_wp_error( $result ) ) {
			self::redirect_with_notice( 'error', $result->get_error_message() );
		}
		self::redirect_with_notice( 'success', __( 'The site is now connected. The service can read the data categories you selected.', 'ctrlweb-site-portrait' ) );
	}

	/**
	 * Saves scopes and IP allow-list.
	 */
	public static function handle_save() {
		self::guard( 'site_portrait_save' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard().
		$scopes    = isset( $_POST['scopes'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['scopes'] ) ) : array();
		$allowlist = isset( $_POST['ip_allowlist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ip_allowlist'] ) ) : '';
		// phpcs:enable

		$parsed   = Ip_Allowlist::parse( $allowlist );
		$settings = Store::settings();

		$settings['ip_allowlist'] = $parsed['valid'];
		Store::set( Store::SETTINGS, $settings );
		Pairing::set_scopes( $scopes );

		if ( ! empty( $parsed['invalid'] ) ) {
			self::redirect_with_notice(
				'warning',
				/* translators: %s: comma-separated list of invalid entries. */
				sprintf( __( 'Settings saved, but these allow-list entries were ignored because they are not valid IP addresses or ranges: %s', 'ctrlweb-site-portrait' ), implode( ', ', $parsed['invalid'] ) )
			);
		}
		self::redirect_with_notice( 'success', __( 'Settings saved.', 'ctrlweb-site-portrait' ) );
	}

	/**
	 * Rotates the site key.
	 */
	public static function handle_rotate() {
		self::guard( 'site_portrait_rotate' );
		Pairing::rotate_site_key();
		self::redirect_with_notice( 'success', __( 'A new site key was generated. The service will pick it up automatically.', 'ctrlweb-site-portrait' ) );
	}

	/**
	 * Disconnects from the service.
	 */
	public static function handle_disconnect() {
		self::guard( 'site_portrait_disconnect' );
		$result = Pairing::disconnect( 'revoked_by_site' );
		if ( is_wp_error( $result ) ) {
			self::redirect_with_notice(
				'warning',
				/* translators: %s: error message. */
				sprintf( __( 'The site is disconnected and the service can no longer read any data. However the service could not be notified: %s', 'ctrlweb-site-portrait' ), $result->get_error_message() )
			);
		}
		self::redirect_with_notice( 'success', __( 'The site is disconnected and the service was notified.', 'ctrlweb-site-portrait' ) );
	}

	/*
	 * ---------------------------------------------------------------------
	 * Rendering.
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Renders the settings screen.
	 */
	public static function render() {
		if ( ! current_user_can( Plugin::capability() ) ) {
			return;
		}
		$pairing   = Pairing::get();
		$discovery = null === $pairing ? Store::get_transient( self::discovery_key() ) : false;
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'ctrlweb Site Portrait', 'ctrlweb-site-portrait' ); ?></h1>
			<?php
			self::render_notice();

			if ( Plugin::is_dev_mode() ) {
				echo '<div class="notice notice-warning"><p>' . esc_html__( 'Development mode is active (SITE_PORTRAIT_DEV_MODE): unencrypted HTTP and local addresses are accepted. Never use this on a production site.', 'ctrlweb-site-portrait' ) . '</p></div>';
			}

			if ( null !== $pairing ) {
				self::render_connected( $pairing );
			} elseif ( is_array( $discovery ) ) {
				self::render_consent( $discovery );
			} else {
				self::render_lookup();
			}

			self::render_log();
			?>
		</div>
		<?php
	}

	/**
	 * Step 1: service URL.
	 */
	private static function render_lookup() {
		?>
		<p><?php esc_html_e( 'Site Portrait lets a service you choose (for example a hosting provider) read a technical description of this site to recommend suitable hosting. It is disabled until you connect a service, and nothing is sent anywhere before you confirm.', 'ctrlweb-site-portrait' ); ?></p>
		<form method="post" action="<?php echo esc_url( Plugin::action_url( 'discover' ) ); ?>">
			<?php wp_nonce_field( 'site_portrait_discover' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="site-portrait-service-url"><?php esc_html_e( 'Service address', 'ctrlweb-site-portrait' ); ?></label></th>
					<td>
						<input type="url" class="regular-text code" id="site-portrait-service-url" name="service_url" placeholder="https://service.example" required>
						<p class="description"><?php esc_html_e( 'Provided by the service. This site will read the service description at this address and show it to you before anything else happens.', 'ctrlweb-site-portrait' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Look up service', 'ctrlweb-site-portrait' ), 'primary', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Step 2: explicit consent.
	 *
	 * @param array $discovery Normalised discovery data.
	 */
	private static function render_consent( array $discovery ) {
		$descriptions = Scopes::descriptions();
		?>
		<h2>
			<?php
			/* translators: %s: service name. */
			echo esc_html( sprintf( __( 'Connect to %s?', 'ctrlweb-site-portrait' ), $discovery['name'] ) );
			?>
		</h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Service', 'ctrlweb-site-portrait' ); ?></th>
				<td>
					<strong><?php echo esc_html( $discovery['name'] ); ?></strong> — <code><?php echo esc_html( $discovery['origin'] ); ?></code>
					<?php if ( '' !== $discovery['description'] ) : ?>
						<p><?php echo esc_html( $discovery['description'] ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Privacy', 'ctrlweb-site-portrait' ); ?></th>
				<td>
					<a href="<?php echo esc_url( $discovery['privacy_policy_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Privacy policy', 'ctrlweb-site-portrait' ); ?></a>
					<?php if ( '' !== $discovery['terms_url'] ) : ?>
						| <a href="<?php echo esc_url( $discovery['terms_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Terms of use', 'ctrlweb-site-portrait' ); ?></a>
					<?php endif; ?>
					<?php if ( '' !== $discovery['contact'] ) : ?>
						| <?php echo esc_html( $discovery['contact'] ); ?>
					<?php endif; ?>
				</td>
			</tr>
		</table>

		<form method="post" action="<?php echo esc_url( Plugin::action_url( 'connect' ) ); ?>">
			<?php wp_nonce_field( 'site_portrait_connect' ); ?>
			<h3><?php esc_html_e( 'Data the service may read', 'ctrlweb-site-portrait' ); ?></h3>
			<p><?php esc_html_e( 'The service can only read the categories you tick. It can never change anything on this site. You can change this choice or disconnect at any time.', 'ctrlweb-site-portrait' ); ?></p>
			<fieldset>
				<?php foreach ( $discovery['scopes_supported'] as $scope ) : ?>
					<p>
						<label>
							<input type="checkbox" name="scopes[]" value="<?php echo esc_attr( $scope ); ?>" <?php checked( in_array( $scope, $discovery['scopes_requested'], true ) ); ?>>
							<strong><?php echo esc_html( $descriptions[ $scope ]['label'] ); ?></strong>
						</label><br>
						<span class="description"><?php echo esc_html( $descriptions[ $scope ]['description'] ); ?></span>
						<?php if ( isset( $discovery['scope_reasons'][ $scope ] ) ) : ?>
							<br><em>
							<?php
							/* translators: %s: justification provided by the service. */
							echo esc_html( sprintf( __( 'Why the service asks: %s', 'ctrlweb-site-portrait' ), $discovery['scope_reasons'][ $scope ] ) );
							?>
							</em>
						<?php endif; ?>
					</p>
				<?php endforeach; ?>
			</fieldset>
			<?php if ( Plugin::is_network_mode() ) : ?>
				<p><?php esc_html_e( 'Network mode: the service will also be able to list the addresses of all sites of this network, and their counts for the categories you tick.', 'ctrlweb-site-portrait' ); ?></p>
			<?php endif; ?>
			<p><?php esc_html_e( 'Clicking Connect sends you to the service to sign in and approve. The service then receives this site’s address and a public key, and this site stores the service’s public key.', 'ctrlweb-site-portrait' ); ?></p>
			<?php submit_button( __( 'Connect', 'ctrlweb-site-portrait' ), 'primary', 'submit', false ); ?>
		</form>
		<form method="post" action="<?php echo esc_url( Plugin::action_url( 'cancel' ) ); ?>" style="margin-top:1em">
			<?php wp_nonce_field( 'site_portrait_cancel' ); ?>
			<?php submit_button( __( 'Cancel', 'ctrlweb-site-portrait' ), 'secondary', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Connected state: service, scopes, allow-list, keys and disconnection.
	 *
	 * @param array $pairing Pairing.
	 */
	private static function render_connected( array $pairing ) {
		$service      = $pairing['service'];
		$descriptions = Scopes::descriptions();
		$settings     = Store::settings();
		$date_format  = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		?>
		<h2><?php esc_html_e( 'Connected service', 'ctrlweb-site-portrait' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Service', 'ctrlweb-site-portrait' ); ?></th>
				<td>
					<strong><?php echo esc_html( $service['name'] ); ?></strong> — <code><?php echo esc_html( $service['origin'] ); ?></code>
					<br><a href="<?php echo esc_url( $service['privacy_policy_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Privacy policy', 'ctrlweb-site-portrait' ); ?></a>
				</td>
			</tr>
			<?php if ( '' !== $pairing['account_hint'] ) : ?>
				<tr>
					<th scope="row"><?php esc_html_e( 'Account', 'ctrlweb-site-portrait' ); ?></th>
					<td><?php echo esc_html( $pairing['account_hint'] ); ?></td>
				</tr>
			<?php endif; ?>
			<tr>
				<th scope="row"><?php esc_html_e( 'Connected on', 'ctrlweb-site-portrait' ); ?></th>
				<td>
					<?php echo esc_html( wp_date( $date_format, $pairing['connected_at'] ) ); ?>
					<?php if ( empty( $pairing['confirmed_at'] ) ) : ?>
						— <em><?php esc_html_e( 'waiting for the service to confirm', 'ctrlweb-site-portrait' ); ?></em>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Pairing ID', 'ctrlweb-site-portrait' ); ?></th>
				<td><code><?php echo esc_html( $pairing['pairing_id'] ); ?></code></td>
			</tr>
		</table>

		<form method="post" action="<?php echo esc_url( Plugin::action_url( 'save' ) ); ?>">
			<?php wp_nonce_field( 'site_portrait_save' ); ?>
			<h2><?php esc_html_e( 'Data the service may read', 'ctrlweb-site-portrait' ); ?></h2>
			<fieldset>
				<?php foreach ( $service['scopes_supported'] as $scope ) : ?>
					<p>
						<label>
							<input type="checkbox" name="scopes[]" value="<?php echo esc_attr( $scope ); ?>" <?php checked( in_array( $scope, $pairing['scopes'], true ) ); ?>>
							<strong><?php echo esc_html( $descriptions[ $scope ]['label'] ); ?></strong>
						</label><br>
						<span class="description"><?php echo esc_html( $descriptions[ $scope ]['description'] ); ?></span>
					</p>
				<?php endforeach; ?>
			</fieldset>

			<h2><?php esc_html_e( 'Allowed IP addresses', 'ctrlweb-site-portrait' ); ?></h2>
			<p>
				<label for="site-portrait-ip-allowlist"><?php esc_html_e( 'Optional. One IP address or CIDR range per line (IPv4 or IPv6). When set, requests from other addresses are refused.', 'ctrlweb-site-portrait' ); ?></label>
			</p>
			<textarea class="large-text code" rows="4" id="site-portrait-ip-allowlist" name="ip_allowlist"><?php echo esc_textarea( implode( "\n", $settings['ip_allowlist'] ) ); ?></textarea>
			<?php submit_button(); ?>
		</form>

		<h2><?php esc_html_e( 'Keys', 'ctrlweb-site-portrait' ); ?></h2>
		<p>
			<?php
			/* translators: %s: key identifier. */
			echo esc_html( sprintf( __( 'Site key: %s', 'ctrlweb-site-portrait' ), $pairing['site_key']['kid'] ) );
			?>
			<br>
			<?php
			/* translators: %s: comma-separated key identifiers. */
			echo esc_html( sprintf( __( 'Trusted service keys: %s', 'ctrlweb-site-portrait' ), implode( ', ', array_keys( $pairing['service_keys'] ) ) ) );
			?>
		</p>
		<form method="post" action="<?php echo esc_url( Plugin::action_url( 'rotate' ) ); ?>">
			<?php wp_nonce_field( 'site_portrait_rotate' ); ?>
			<?php submit_button( __( 'Generate a new site key', 'ctrlweb-site-portrait' ), 'secondary', 'submit', false ); ?>
		</form>

		<h2><?php esc_html_e( 'Disconnect', 'ctrlweb-site-portrait' ); ?></h2>
		<p><?php esc_html_e( 'Disconnecting takes effect immediately: the service can no longer read anything, and its key is deleted from this site. The service is then notified.', 'ctrlweb-site-portrait' ); ?></p>
		<form method="post" action="<?php echo esc_url( Plugin::action_url( 'disconnect' ) ); ?>" onsubmit="return window.confirm('<?php echo esc_js( __( 'Disconnect this site from the service?', 'ctrlweb-site-portrait' ) ); ?>');">
			<?php wp_nonce_field( 'site_portrait_disconnect' ); ?>
			<?php submit_button( __( 'Disconnect', 'ctrlweb-site-portrait' ), 'delete', 'submit', false ); ?>
		</form>
		<?php
	}

	/**
	 * Access log.
	 */
	private static function render_log() {
		$page = isset( $_GET['log_page'] ) ? max( 1, absint( $_GET['log_page'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only pagination.
		$log  = Access_Log::page( $page );
		if ( 0 === $log['total'] ) {
			return;
		}
		$date_format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		$pages       = (int) ceil( $log['total'] / 50 );
		?>
		<h2><?php esc_html_e( 'Access log', 'ctrlweb-site-portrait' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Requests received on the Site Portrait API during the last 90 days.', 'ctrlweb-site-portrait' ); ?></p>
		<table class="widefat striped">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Date', 'ctrlweb-site-portrait' ); ?></th>
					<th scope="col"><?php esc_html_e( 'IP address', 'ctrlweb-site-portrait' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Request', 'ctrlweb-site-portrait' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Data categories', 'ctrlweb-site-portrait' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Result', 'ctrlweb-site-portrait' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $log['items'] as $entry ) : ?>
					<tr>
						<td><?php echo esc_html( wp_date( $date_format, (int) $entry['created_at'] ) ); ?></td>
						<td><code><?php echo esc_html( $entry['ip'] ); ?></code></td>
						<td><code><?php echo esc_html( $entry['method'] . ' ' . $entry['endpoint'] ); ?></code></td>
						<td><?php echo esc_html( str_replace( ',', ', ', $entry['scopes'] ) ); ?></td>
						<td><?php echo esc_html( trim( $entry['status'] . ' ' . $entry['error_code'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo wp_kses_post(
				paginate_links(
					array(
						'base'    => add_query_arg( 'log_page', '%#%', Plugin::settings_url() ),
						'format'  => '',
						'current' => $page,
						'total'   => $pages,
					)
				)
			);
			echo '</div></div>';
		}
	}

	/**
	 * Displays and clears the pending notice.
	 */
	private static function render_notice() {
		$key    = 'site_portrait_notice_' . get_current_user_id();
		$notice = Store::get_transient( $key );
		if ( ! is_array( $notice ) ) {
			return;
		}
		Store::delete_transient( $key );
		$type = in_array( $notice['type'], array( 'success', 'warning', 'error' ), true ) ? $notice['type'] : 'info';
		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
			esc_attr( $type ),
			esc_html( $notice['message'] )
		);
	}

	/*
	 * ---------------------------------------------------------------------
	 * Helpers.
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Checks the nonce and capability of a POST action.
	 *
	 * @param string $action Nonce action.
	 */
	private static function guard( $action ) {
		if ( ! current_user_can( Plugin::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Site Portrait.', 'ctrlweb-site-portrait' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * Transient name of the current user's discovery result.
	 *
	 * @return string
	 */
	private static function discovery_key() {
		return 'site_portrait_discovery_' . get_current_user_id();
	}

	/**
	 * Redirects to the settings screen and stops.
	 */
	private static function redirect() {
		wp_safe_redirect( Plugin::settings_url() );
		exit;
	}

	/**
	 * Stores a notice, redirects to the settings screen and stops.
	 *
	 * @param string $type    success|warning|error.
	 * @param string $message Message.
	 */
	private static function redirect_with_notice( $type, $message ) {
		Store::set_transient(
			'site_portrait_notice_' . get_current_user_id(),
			array(
				'type'    => $type,
				'message' => $message,
			),
			MINUTE_IN_SECONDS * 5
		);
		self::redirect();
	}
}
