#!/bin/bash

openssl genrsa -aes256 -out client.key 1024

#//Generate Certificate signing request
openssl req -new -key client.key -out client.csr

#Sign certificate with private key
openssl x509 -req -days 3650 -in client.csr -signkey client.key -out client.crt

#Remove password requirement (needed for example)
cp client.key client.key.secure
openssl rsa -in client.key.secure -out client.key

#//Generate dhparam file
openssl dhparam -out dh1024.pem 1024
