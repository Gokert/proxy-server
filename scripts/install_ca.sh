#!/bin/sh

cp certs/ca.crt /usr/local/share/ca-certificates/
update-ca-certificates
