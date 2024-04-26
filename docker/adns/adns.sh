#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container
echo Looking up IP address for this deployment
echo Fabric_NodeIPOrFQDN: $Fabric_NodeIPOrFQDN
IP_ADDRESS=`dig +short $DNS_URL`

/bin/adns -loglevel trace -adnsEndpoint $ADNS_ENDPOINT -serviceFQDN $SERVICE_FQDN -ipAddress $IP_ADDRESS
sleep 10000