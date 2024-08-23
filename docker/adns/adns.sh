#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container
echo Looking up IP address for this deployment
IP_ADDRESS=`dig +short $DNS_URL`

/bin/adns -loglevel trace -adnsEndpoint $ADNS_ENDPOINT -serviceFQDN $SERVICE_FQDN -ipAddress $IP_ADDRESS -task "register"

# Start nginx with the provisioned certificates
mv ${SERVICE_FQDN}.crt /etc/nginx/ssl.crt
mv ${SERVICE_FQDN}.key /etc/nginx/ssl.key
cp /usr/local/share/ca-certificates/adns-root.crt /etc/nginx/adns_root.crt
envsubst '${SERVICE_PORT}' < nginx.conf.template > /etc/nginx/nginx.conf

sh iptables.sh

# Create the user with UID 337
useradd -u 337 -r -s /bin/false nginx_user

# Set the user in the Nginx configuration
sed -i 's/^user .*/user nginx_user nginx_user;/' /etc/nginx/nginx.conf

nginx

#sleep 5
#curl localhost
#curl -v http://test3.acidns10.attested.name

sleep 100000