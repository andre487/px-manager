#!/bin/sh
cd "`dirname "$0"`/.."
exec uv run pyinstaller --clean px-manager.spec
