# ctrlweb Site Portrait

WordPress plugin implementing the open **Site Portrait** protocol. It lets a service chosen by the site administrator securely
read a technical portrait of the site (versions, server, database, content
volumes) to recommend suitable hosting. Not tied to any service: the protocol
is open and documented.

- Protocol specification: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- JSON schemas: [`docs/schema/`](docs/schema/)
- WordPress.org readme: [`readme.txt`](readme.txt)

## Layout

| Path | Content |
|---|---|
| `ctrlweb-site-portrait.php`, `uninstall.php`, `includes/` | The plugin (no runtime dependency). |
| `includes/collectors/` | One collector per scope. |
| `bin/reference-client.mjs`, `bin/lib/` | Reference implementation of the **service** side (Node ≥ 20, no dependency). |
| `tests/php/` | PHPUnit unit tests (no WordPress needed). |
| `tests/js/` | Node tests of the reference protocol library. |
| `tests/e2e/` | End-to-end tests: WordPress Playground + reference service. |

Development files are excluded from the distributed plugin through
`.gitattributes` (`export-ignore`).

## Development

```sh
composer install          # PHPCS (WordPress Coding Standards), PHPUnit, sodium_compat
npm install               # WordPress Playground CLI, ajv

composer lint             # PHPCS
composer test             # PHP unit tests
npm test                  # Node protocol tests (test vectors)
npm run test:e2e          # Playground e2e, single site and multisite (downloads WordPress on first run)
SP_PHP=7.4 npm run test:e2e   # same, on the minimum supported PHP version
bin/plugin-check.sh       # Plugin Check with the WordPress.org flags, on the built plugin
bin/build-zip.sh          # build/ctrlweb-site-portrait.zip
```

## Trying the reference service by hand

```sh
node bin/reference-client.mjs serve --port 8787            # approval page in the browser
node bin/reference-client.mjs serve --port 8787 --auto-approve
```

On a local site, define in `wp-config.php`:

```php
define( 'WP_ENVIRONMENT_TYPE', 'local' );
define( 'SITE_PORTRAIT_DEV_MODE', true ); // Allows HTTP and local hosts. Never in production.
```

then enter `http://127.0.0.1:8787` in **Settings → Site Portrait**. Once
connected:

```sh
node bin/reference-client.mjs status
node bin/reference-client.mjs portrait --scopes core,server --validate
node bin/reference-client.mjs sites            # network mode
node bin/reference-client.mjs rotate-key       # service key rotation
node bin/reference-client.mjs revoke
```

State (keys, pairings) is kept in `.reference-client/` (git-ignored).

## Licenses

| Part | License | File |
|---|---|---|
| WordPress plugin (`ctrlweb-site-portrait.php`, `uninstall.php`, `includes/`) and tests | GPL-2.0-or-later | [`LICENSE`](LICENSE) |
| Protocol specification and JSON schemas (`docs/`) | CC-BY-4.0 | [`docs/LICENSE`](docs/LICENSE) |
| Reference client and scripts (`bin/`) | Apache-2.0 | [`bin/LICENSE`](bin/LICENSE) |

The specification is under CC-BY-4.0 and the reference client under Apache-2.0
so that anyone can implement a compatible service, including proprietary ones.
