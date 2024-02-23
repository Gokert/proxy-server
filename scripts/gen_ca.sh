#!/bin/sh

openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -days 365 -key certs/ca.key -out certs/ca.crt -subj "/CN=$1 proxy CA"

# Import certificates into the System Keychain 
# sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$(pwd)/certs/ca.crt" 