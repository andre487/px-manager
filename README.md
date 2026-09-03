# px-manager
Proxy info manager

## MegaProxy export

`/api/generate/mega-proxy` returns a `net.megaproxy487.config` version 7 document. Profile IDs are
deterministic and do not include the endpoint or credentials, so importing a newly generated file
updates existing profiles and adds new servers without duplicating them. Set a unique, immutable
`profile_id` on each `hosts.json` entry; its title is used as a compatibility fallback. Profiles
removed from px-manager are offered for optional removal by MegaProxy during the next import.
