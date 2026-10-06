#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
fi
if [ ! -f .venv/namazu-installed ]; then
    .venv/bin/python -m pip install .
    touch .venv/namazu-installed
fi
exec .venv/bin/python -m namazu "$@"
