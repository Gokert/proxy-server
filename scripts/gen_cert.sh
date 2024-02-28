#!/bin/sh
openssl genrsa -out certs/cert.key 2048
openssl req -new -key certs/cert.key -subj "/CN=$1" -sha256 | openssl x509 -req -days 365 -CA certs/ca.crt -CAkey certs/ca.key -set_serial "0x`openssl rand -hex 8`" > certs/nck.crt
#sudo chmod 777 certs/*