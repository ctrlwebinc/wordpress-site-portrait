<?php
/**
 * Minimal RFC 8941 (Structured Field Values) dictionary parser and serializer,
 * sufficient for the Signature-Input and Signature fields of RFC 9421.
 *
 * Items are represented as arrays: array( 'type' => string, 'value' => mixed,
 * 'params' => array ). Types are integer, decimal, string, token, bytes
 * (raw binary value), boolean and inner_list (value is a list of items).
 * Parameters map a key to an array( 'type' => string, 'value' => mixed ).
 *
 * @package Site_Portrait
 */

namespace Site_Portrait;

defined( 'ABSPATH' ) || exit;

/**
 * Structured field values.
 */
final class Structured_Fields {

	/**
	 * Input being parsed.
	 *
	 * @var string
	 */
	private $input;

	/**
	 * Current offset in the input.
	 *
	 * @var int
	 */
	private $pos = 0;

	/**
	 * Constructor.
	 *
	 * @param string $input Field value.
	 */
	private function __construct( $input ) {
		$this->input = $input;
	}

	/**
	 * Parses a dictionary field value.
	 *
	 * @param string $input Field value (multiple header lines joined with ", ").
	 * @return array|null Ordered map of key => item, or null on syntax error.
	 */
	public static function parse_dictionary( $input ) {
		if ( ! is_string( $input ) ) {
			return null;
		}
		$parser = new self( trim( $input, ' ' ) );
		try {
			return $parser->dictionary();
		} catch ( \UnexpectedValueException $e ) {
			return null;
		}
	}

	/**
	 * Serializes an inner list item (with its parameters).
	 *
	 * @param array $items  List of items.
	 * @param array $params Parameters.
	 * @return string
	 */
	public static function serialize_inner_list( array $items, array $params ) {
		$parts = array();
		foreach ( $items as $item ) {
			$parts[] = self::serialize_bare( $item['type'], $item['value'] ) . self::serialize_params( $item['params'] ?? array() );
		}
		return '(' . implode( ' ', $parts ) . ')' . self::serialize_params( $params );
	}

	/**
	 * Serializes parameters.
	 *
	 * @param array $params Map of key => array( type, value ).
	 * @return string
	 */
	public static function serialize_params( array $params ) {
		$out = '';
		foreach ( $params as $key => $param ) {
			$out .= ';' . $key;
			if ( ! ( 'boolean' === $param['type'] && true === $param['value'] ) ) {
				$out .= '=' . self::serialize_bare( $param['type'], $param['value'] );
			}
		}
		return $out;
	}

	/**
	 * Serializes a bare item.
	 *
	 * @param string $type  Item type.
	 * @param mixed  $value Item value.
	 * @return string
	 * @throws \InvalidArgumentException On unsupported type or value.
	 */
	public static function serialize_bare( $type, $value ) {
		switch ( $type ) {
			case 'integer':
				return (string) (int) $value;
			case 'decimal':
				return rtrim( rtrim( number_format( (float) $value, 3, '.', '' ), '0' ), '.' );
			case 'string':
				if ( preg_match( '/[^\x20-\x7e]/', $value ) ) {
					throw new \InvalidArgumentException( 'Invalid string item.' );
				}
				return '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $value ) . '"';
			case 'token':
				return (string) $value;
			case 'bytes':
				return ':' . base64_encode( $value ) . ':'; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- RFC 8941 byte sequence.
			case 'boolean':
				return $value ? '?1' : '?0';
		}
		throw new \InvalidArgumentException( 'Unsupported item type.' );
	}

	/**
	 * Convenience constructor for a string item without parameters.
	 *
	 * @param string $value Value.
	 * @param array  $params Parameters.
	 * @return array
	 */
	public static function string_item( $value, array $params = array() ) {
		return array(
			'type'   => 'string',
			'value'  => $value,
			'params' => $params,
		);
	}

	/**
	 * Parses a dictionary.
	 *
	 * @return array
	 */
	private function dictionary() {
		$members = array();
		while ( ! $this->eof() ) {
			$key = $this->key();
			if ( $this->peek() === '=' ) {
				++$this->pos;
				$members[ $key ] = $this->peek() === '(' ? $this->inner_list() : $this->item();
			} else {
				$members[ $key ] = array(
					'type'   => 'boolean',
					'value'  => true,
					'params' => $this->parameters(),
				);
			}
			$this->skip_ows();
			if ( $this->eof() ) {
				break;
			}
			$this->expect( ',' );
			$this->skip_ows();
			if ( $this->eof() ) {
				$this->fail();
			}
		}
		return $members;
	}

	/**
	 * Parses an inner list.
	 *
	 * @return array
	 */
	private function inner_list() {
		$this->expect( '(' );
		$items = array();
		while ( ! $this->eof() ) {
			$this->skip_sp();
			if ( $this->peek() === ')' ) {
				++$this->pos;
				return array(
					'type'   => 'inner_list',
					'value'  => $items,
					'params' => $this->parameters(),
				);
			}
			$items[] = $this->item();
			$next    = $this->peek();
			if ( ' ' !== $next && ')' !== $next ) {
				$this->fail();
			}
		}
		$this->fail();
	}

	/**
	 * Parses an item with its parameters.
	 *
	 * @return array
	 */
	private function item() {
		$bare           = $this->bare_item();
		$bare['params'] = $this->parameters();
		return $bare;
	}

	/**
	 * Parses parameters.
	 *
	 * @return array
	 */
	private function parameters() {
		$params = array();
		while ( $this->peek() === ';' ) {
			++$this->pos;
			$this->skip_sp();
			$key = $this->key();
			if ( $this->peek() === '=' ) {
				++$this->pos;
				$params[ $key ] = $this->bare_item();
			} else {
				$params[ $key ] = array(
					'type'  => 'boolean',
					'value' => true,
				);
			}
		}
		return $params;
	}

	/**
	 * Parses a key.
	 *
	 * @return string
	 */
	private function key() {
		if ( ! preg_match( '/\G[a-z*][a-z0-9_.*-]*/', $this->input, $m, 0, $this->pos ) ) {
			$this->fail();
		}
		$this->pos += strlen( $m[0] );
		return $m[0];
	}

	/**
	 * Parses a bare item.
	 *
	 * @return array
	 */
	private function bare_item() {
		$c = $this->peek();
		if ( '"' === $c ) {
			return $this->string();
		}
		if ( ':' === $c ) {
			return $this->bytes();
		}
		if ( '?' === $c ) {
			return $this->boolean();
		}
		if ( preg_match( '/\G-?[0-9]{1,15}(\.[0-9]{1,3})?/', $this->input, $m, 0, $this->pos ) ) {
			$this->pos += strlen( $m[0] );
			return isset( $m[1] )
				? array(
					'type'  => 'decimal',
					'value' => (float) $m[0],
				)
				: array(
					'type'  => 'integer',
					'value' => (int) $m[0],
				);
		}
		if ( preg_match( '/\G[A-Za-z*][!#$%&\'*+\-.^_`|~0-9A-Za-z:\/]*/', $this->input, $m, 0, $this->pos ) ) {
			$this->pos += strlen( $m[0] );
			return array(
				'type'  => 'token',
				'value' => $m[0],
			);
		}
		$this->fail();
	}

	/**
	 * Parses a string.
	 *
	 * @return array
	 */
	private function string() {
		++$this->pos;
		$out = '';
		$len = strlen( $this->input );
		while ( $this->pos < $len ) {
			$c = $this->input[ $this->pos++ ];
			if ( '\\' === $c ) {
				$next = $this->input[ $this->pos++ ] ?? '';
				if ( '\\' !== $next && '"' !== $next ) {
					$this->fail();
				}
				$out .= $next;
			} elseif ( '"' === $c ) {
				return array(
					'type'  => 'string',
					'value' => $out,
				);
			} elseif ( ord( $c ) < 0x20 || ord( $c ) > 0x7e ) {
				$this->fail();
			} else {
				$out .= $c;
			}
		}
		$this->fail();
	}

	/**
	 * Parses a byte sequence.
	 *
	 * @return array
	 */
	private function bytes() {
		if ( ! preg_match( '/\G:([A-Za-z0-9+\/=]*):/', $this->input, $m, 0, $this->pos ) ) {
			$this->fail();
		}
		$this->pos += strlen( $m[0] );
		$decoded    = base64_decode( $m[1], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- RFC 8941 byte sequence.
		if ( false === $decoded ) {
			$this->fail();
		}
		return array(
			'type'  => 'bytes',
			'value' => $decoded,
		);
	}

	/**
	 * Parses a boolean.
	 *
	 * @return array
	 */
	private function boolean() {
		$token = substr( $this->input, $this->pos, 2 );
		if ( '?1' !== $token && '?0' !== $token ) {
			$this->fail();
		}
		$this->pos += 2;
		return array(
			'type'  => 'boolean',
			'value' => '?1' === $token,
		);
	}

	/**
	 * Returns the current character, or an empty string at the end.
	 *
	 * @return string
	 */
	private function peek() {
		return $this->input[ $this->pos ] ?? '';
	}

	/**
	 * Whether the whole input was consumed.
	 *
	 * @return bool
	 */
	private function eof() {
		return $this->pos >= strlen( $this->input );
	}

	/**
	 * Consumes an expected character.
	 *
	 * @param string $char Character.
	 */
	private function expect( $char ) {
		if ( $this->peek() !== $char ) {
			$this->fail();
		}
		++$this->pos;
	}

	/**
	 * Skips spaces.
	 */
	private function skip_sp() {
		while ( $this->peek() === ' ' ) {
			++$this->pos;
		}
	}

	/**
	 * Skips optional whitespace (spaces and tabs).
	 */
	private function skip_ows() {
		while ( $this->peek() === ' ' || $this->peek() === "\t" ) {
			++$this->pos;
		}
	}

	/**
	 * Aborts parsing.
	 *
	 * @throws \UnexpectedValueException Always.
	 */
	private function fail() {
		throw new \UnexpectedValueException( 'Invalid structured field.' );
	}
}
