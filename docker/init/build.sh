#!/bin/bash

set -e
pushd $(dirname $0)

docker build -t init -f Dockerfile.init ../..
popd