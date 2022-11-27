#!/usr/bin/env bash
set -euo pipefail

go install mvdan.cc/gofumpt@latest

if [ "$(gofumpt -l $(find . -name "*.go") | wc -l)" -gt 0 ]; then
    echo "Run gofumpt on the code"
    exit 1
fi
