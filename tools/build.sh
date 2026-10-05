#!/bin/sh
cd "`dirname "$0"`/.."
exec uv run --locked pyinstaller px-manager.spec
