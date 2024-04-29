#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container
echo Looking up IP address for this deployment
IP_ADDRESS=`dig +short $DNS_URL`

/bin/adns -loglevel trace -adnsEndpoint $ADNS_ENDPOINT -serviceFQDN $SERVICE_FQDN -ipAddress $IP_ADDRESS


# Start nginx with the provisioned certificates
mv ${SERVICE_FQDN}.crt /etc/nginx/ssl.crt
mv ${SERVICE_FQDN}.key /etc/nginx/ssl.key
envsubst '${SERVICE_PORT}' < nginx.conf.template > /etc/nginx/nginx.conf 
nginx 

sleep 100000