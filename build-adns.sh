#!/bin/bash

	mkdir -p bin
	pushd bin
	CGO_ENABLED=0 GOOS=linux go build github.com/Microsoft/confidential-sidecar-containers/cmd/adns
	popd 
	pushd docker/adns
	bash ./build.sh
	popd