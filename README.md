# px-manager
Proxy info manager

## Client setup

Prefer configuration subscriptions: use [BrowserMegaProxy](https://github.com/andre487/BrowserMegaProxy)
for Chrome and Firefox, and [AndroidMegaProxy](https://github.com/andre487/AndroidMegaProxy)
for Android. The authenticated `/doc` page contains setup instructions; importing a
MegaProxy JSON file is the fallback.

The current `~/MyProjects/ansible-inventory/mega-proxy-inventory.yml` configures:

- Primary URL: `https://pxc-ru.jethelix.ru/api/config`.
- Fallback URL: `https://pxc-kz.jethelix.ru/api/config`.
- HTTPS Basic Auth: the user's PX Manager login and password (`users.https`).
- Automatic updates every 60 minutes.

These feeds are deployed by `~/MyProjects/MegaProxyServer/`; see its
[configuration API guide](https://github.com/andre487/MegaProxyServer/blob/main/docs/ru/config-api.md).
Endpoints, ports, paths and intervals come from `hosts.*.services.config_api`.
Client preferences come from `settings.client_config` and per-user `client_config`;
`client_config.subscription` may override `intervalMinutes` and `enabled`, while the
server manages URLs and credentials. Apply inventory changes to every affected API host
(and affected proxy hosts when changing users or services). Deploy PX Manager again to
refresh its `subscription.json`. Keep the URLs in `/doc` in sync when endpoints change.

## MegaProxy export

`/api/generate/mega-proxy` first requests a MegaProxy v8 configuration from the configured
subscription URLs in order, using the logged-in user's proxy credentials as HTTPS Basic Auth.
The first JSON response is returned as formatted JSON without validating its configuration.
Requests verify TLS certificates,
reject redirects, time out after five seconds per source, and limit responses to 1 MiB.
If every source fails or returns unparsable JSON, the existing local generator is used.

Locally generated profile IDs are
deterministic and do not include the endpoint or credentials, so importing a newly generated file
updates existing profiles and adds new servers without duplicating them. Set a unique, immutable
`profile_id` on each `hosts.json` entry; its title is used as a compatibility fallback. Profiles
removed from px-manager are offered for optional removal by MegaProxy during the next import.

The deploy playbook builds `subscription.json` from enabled `hosts.*.services.config_api`
entries in the MegaProxy inventory. The first URL is the subscription source; the remaining
URLs are fallbacks (eight sources maximum). The interval comes from the first service's
`interval_minutes`, defaulting to 60 minutes. MegaProxy exports include this subscription
with the same login and password as the proxy profiles. Without configuration API hosts
or a local `subscription.json`, exports omit the subscription.

Run tests with `uv run --locked python -m unittest discover -s tests`.
The schema in `tests/schemas/megaproxy-v8.schema.json` is copied unchanged from
[MegaProxyConfig](https://github.com/andre487/MegaProxyConfig/blob/8cb2d57cb1641fd97446b4ffd18ef6dcdad618dd/schemas/megaproxy-v8.schema.json).
To update it, copy the upstream schema and update this commit reference.
