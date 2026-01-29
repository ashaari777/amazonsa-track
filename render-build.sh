#!/usr/bin/env bash
set -e

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browser
python -m playwright install chromium

# Install system dependencies required by Chromium (CRITICAL for Render)
python -m playwright install-deps