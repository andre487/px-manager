# px-manager
Proxy info manager

## MegaProxy export

`/api/generate/mega-proxy` returns a `net.megaproxy487.config` version 8 document. Profile IDs are
deterministic and do not include the endpoint or credentials, so importing a newly generated file
updates existing profiles and adds new servers without duplicating them. Set a unique, immutable
`profile_id` on each `hosts.json` entry; its title is used as a compatibility fallback. Profiles
removed from px-manager are offered for optional removal by MegaProxy during the next import.

Run tests with `uv run --locked python -m unittest discover -s tests`.
The schema in `tests/schemas/megaproxy-v8.schema.json` is copied unchanged from
[MegaProxyConfig](https://github.com/andre487/MegaProxyConfig/blob/9427cf235d6c112cd97ae82dc34d5d9b02aa42b7/schemas/megaproxy-v8.schema.json).
To update it, copy the upstream schema and update this commit reference.
