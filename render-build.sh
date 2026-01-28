#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt

# Install chromium and linux deps
python -m playwright install --with-deps chromium
