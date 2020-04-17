#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -d venv ]]; then
    python3 -m venv venv
fi

. ./venv/bin/activate

pip install -r sarif/requirements.txt
