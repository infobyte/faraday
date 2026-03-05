#!/bin/bash
# Install system dependencies for Faraday on Ubuntu/Debian
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential gcc g++ make \
    python3-dev python3-pip \
    libcairo2-dev libfontconfig1-dev libgdk-pixbuf2.0-dev \
    libglib2.0-dev libharfbuzz-dev libpango1.0-dev \
    libpq-dev postgresql-client \
    libsasl2-dev libldap2-dev libssl-dev \
    libmagic1 libmagic-dev \
    curl ca-certificates git rsync wget
