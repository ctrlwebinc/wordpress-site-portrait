=== Site Portrait ===
Contributors: ctrlwebinc
Tags: hosting, site health, system info, migration, server
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let a service you choose securely read a technical portrait of your site (versions, server, database, content volumes) to recommend hosting.

== Description ==

Choosing the right hosting means knowing your site: WordPress and PHP versions, plugins and themes, database size, number of posts and media files, server memory and CPU, caches in place… Site Portrait lets **a service that you choose** (typically a hosting provider or an agency) read that information securely, without giving it an administrator account.

* **Off by default.** Nothing happens and nothing is sent until you enter the address of a service and approve the connection.
* **Any compatible service.** The plugin is not tied to any company. The open protocol is documented in `docs/PROTOCOL.md` (included in the plugin), so anyone can build a compatible service.
* **You choose what is shared.** Seven categories (WordPress core, plugins, themes, server, database, content volumes, user counts) can be ticked or unticked at any time.
* **Read-only and minimised.** The service can never change your site. The plugin never shares passwords, keys, `wp-config.php` values, user names or email addresses, post content, file paths, the database prefix or server IP addresses.
* **No password to leak.** Instead of a password, the site and the service exchange public keys. Every request is signed (HTTP Message Signatures, RFC 9421, with Ed25519) and can only be used once. Even a copy of your database does not let anyone impersonate the service.
* **Transparent.** An access log shows every request (date, IP address, categories). Optional IP allow-list, rate limiting, one-click disconnection and key rotation.
* **Multisite ready.** On a network, a super admin connects the whole network from the Network Admin.

= How it works =

1. In **Settings → Site Portrait**, enter the address given by the service (for example `https://service.example`).
2. The plugin reads the service description (`/.well-known/site-portrait`) and shows you its name, privacy policy and the data it asks for. Tick the categories you agree to share.
3. Click **Connect**: you are sent to the service to sign in and approve, then back to your dashboard.
4. The service can now request the portrait. You can change the categories or disconnect at any time.

= For developers =

The full protocol (discovery, pairing, request signatures, endpoints, errors, JSON schemas and test vectors) is in `docs/PROTOCOL.md` and `docs/schema/`. The filter `site_portrait_scope_data` lets other plugins add data to a category.

== External services ==

This plugin connects your site to **one external service chosen and entered by the site administrator**. No service is built in, and the plugin never contacts any server until an administrator enters a service address and asks to look it up.

What is sent, to whom and when:

* **When the administrator clicks "Look up service":** the site requests `https://<service>/.well-known/site-portrait` to display the service name, privacy policy and requested data. Only a standard HTTP request is sent (it includes your site address in the User-Agent).
* **When the administrator clicks "Connect" and approves on the service:** the administrator's browser is sent to the service's authorization page with your site address, site name, the categories ticked and a public key. The site then sends the service, server to server, the authorization code, its public key, the addresses of its Site Portrait API endpoints, the plugin version and the categories granted.
* **While connected:** the service may request the portrait. The site only answers signed requests and only returns the categories you ticked (see the Description for what each contains). On a multisite network, the list of site addresses is also available to the service.
* **When the administrator clicks "Disconnect" or deletes the plugin:** the site notifies the service that the connection ended (site address and connection identifier).

The service's own terms of use and privacy policy apply to the data it receives. Their addresses are shown before you connect and on the settings page.

== Frequently Asked Questions ==

= Can the service change my site? =

No. The API is read-only. The only thing a service can do besides reading is end the connection.

= What if someone steals my database? =

The site only stores the service's public key, which cannot be used to send requests. The site's own private key is also stored; it only allows signing answers as your site and can be replaced from the settings page (Generate a new site key) or by disconnecting.

= Why not use an application password? =

An application password gives a service every permission of the user who created it, and it can be reused by anyone who obtains it. Site Portrait gives read access to the chosen categories only, with signed, single-use requests.

= My site is on localhost or uses HTTP. =

HTTPS is required. For local development only, define `SITE_PORTRAIT_DEV_MODE` as `true` with a `local` or `development` environment type and a `.test`, `.localhost` or loopback host.

= How do I build a compatible service? =

Read `docs/PROTOCOL.md`. It lists what a service must implement, with examples and test vectors.

== Changelog ==

= 0.1.0 =
* First version: discovery, pairing with PKCE and Ed25519 keys, signed REST API, seven data categories, access log, IP allow-list, rate limiting, key rotation, multisite network mode.
