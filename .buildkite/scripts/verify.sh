#!/bin/bash

set -euo pipefail

echo "--- Pre install"
source .buildkite/scripts/pre-install-command.sh
add_bin_path
go install mvdan.cc/gofumpt@latest
go install github.com/elastic/go-licenser@latest

echo "--- verify"
go mod verify
go-licenser -d

echo "--- gofumpt check"
if [ "$(gofumpt -l $(find . -name "*.go") | wc -l)" -gt 0 ]; then
    echo "Run gofumpt on the code"
    exit 1
fi
