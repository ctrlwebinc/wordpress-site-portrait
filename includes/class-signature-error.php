<?php
/**
 * Exception raised when an HTTP message signature cannot be verified.
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Carries a protocol error code (PROTOCOL.md §9) and an HTTP status.
 */
final class Signature_Error extends \Exception {

	/**
	 * Protocol error code, e.g. site_portrait_signature_expired.
	 *
	 * @var string
	 */
	private $error_code;

	/**
	 * HTTP status.
	 *
	 * @var int
	 */
	private $status;

	/**
	 * Constructor.
	 *
	 * @param string $error_code Protocol error code.
	 * @param string $message    Human-readable message (English, not shown to end users).
	 * @param int    $status     HTTP status.
	 */
	public function __construct( $error_code, $message, $status = 401 ) {
		parent::__construct( $message );
		$this->error_code = $error_code;
		$this->status     = $status;
	}

	/**
	 * Returns the protocol error code.
	 *
	 * @return string
	 */
	public function get_error_code() {
		return $this->error_code;
	}

	/**
	 * Returns the HTTP status.
	 *
	 * @return int
	 */
	public function get_status() {
		return $this->status;
	}
}
