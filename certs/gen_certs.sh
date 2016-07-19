openssl req -out ca.pem -new -x509

mkdir servers
cp ca.pem ./servers/
cd servers
openssl genrsa -out server.key 1024
openssl req -key server.key -new -out server.req
openssl x509 -req -in server.req -CA ca.pem -CAkey ../privkey.pem -CAserial ../file.srl -out server.pem

cd ..
mkdir clients
cp ca.pem ./clients/
cd clients
openssl genrsa -out servers.key 1024
openssl req -key server.key -new -out server.req
openssl x509 -req -in server.req -CA ca.pem -CAkey ../privkey.pem -CAserial ../file.srl -out server.pem

