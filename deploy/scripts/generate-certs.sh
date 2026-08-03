#!/bin/bash
set -euo pipefail

CERT_DIR="./certs"
mkdir -p "${CERT_DIR}"

echo "=== Generating CA certificate ==="
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout "${CERT_DIR}/ca-key.pem" \
  -out "${CERT_DIR}/ca-cert.pem" \
  -subj "/CN=vuln-scanner-ca"

for entity in server agent; do
  echo "=== Generating ${entity} certificate ==="
  openssl req -newkey rsa:4096 -nodes \
    -keyout "${CERT_DIR}/${entity}-key.pem" \
    -out "${CERT_DIR}/${entity}-req.pem" \
    -subj "/CN=${entity}"

  echo "subjectAltName=DNS:localhost,DNS:${entity},IP:127.0.0.1" > "${CERT_DIR}/${entity}.cnf"
  openssl x509 -req -in "${CERT_DIR}/${entity}-req.pem" \
    -days 3650 \
    -CA "${CERT_DIR}/ca-cert.pem" \
    -CAkey "${CERT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -extfile "${CERT_DIR}/${entity}.cnf" \
    -out "${CERT_DIR}/${entity}-cert.pem"
done

echo "=== Certificates generated in ${CERT_DIR}/ ==="
ls -la "${CERT_DIR}/"
