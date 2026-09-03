# px-manager
Proxy info manager

## MegaProxy export

`/api/generate/mega-proxy` returns a `dev.megaproxy.config` version 7 document. Profile IDs are
deterministic for the proxy endpoint and px-manager username, so importing a newly generated file
updates existing profiles and adds new servers without duplicating them. Password rotation does not
change an ID. Profiles removed from px-manager are offered for optional removal by MegaProxy during
the next import.
