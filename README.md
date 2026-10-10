# px-manager
Proxy info manager

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
