#!/bin/sh
cd "`dirname "$0"`/.."
exec uv run pyinstaller --onefile --clean --optimize 2 --name px-manager main.py
