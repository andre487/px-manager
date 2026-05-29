#!/bin/sh
cd "`dirname "$0"`/.."
exec uv run pyinstaller px-manager.spec
