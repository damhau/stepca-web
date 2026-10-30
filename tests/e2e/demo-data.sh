#!/usr/bin/env bash
# Demo data for a stack left running by `KEEP=1 tests/e2e/run.sh`: a JWK provisioner "demo" (password demopass)
# and long-lived certificates part-way through their lifetime, some ending within 30 days, one revoked.
set -euo pipefail
cd "$(dirname "$0")"
DC="docker compose -f $PWD/compose.yml"
CA="--ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt"
ADMIN=(--admin-subject step --admin-provisioner "Admin JWK" --admin-password-file /home/step/secrets/password)

$DC exec -T step-ca sh -c 'printf demopass > /tmp/demo.pass'
$DC exec -T step-ca step ca provisioner add demo --type JWK --create --password-file /tmp/demo.pass \
  --x509-max-dur 8760h --x509-default-dur 2160h "${ADMIN[@]}" $CA >/dev/null 2>&1 || echo "(the demo provisioner exists already)"

# name, started this long ago, lifetime (--not-after counts from --not-before), extra SANs
issue() {
  local name=$1 ago=$2 lifetime=$3; shift 3
  $DC exec -T step-ca step ca certificate "$name" "/tmp/$name.crt" "/tmp/$name.key" --provisioner demo --password-file /tmp/demo.pass \
    --not-before="-$ago" --not-after="$lifetime" --san "$name" "$@" --force $CA >/dev/null 2>&1 && echo "issued $name" || echo "FAILED $name"
}
issue api.demo.example 1000h 1100h --san api-internal.demo.example
issue grafana.demo.example 800h 1000h
issue db.demo.example 2000h 2300h
issue mail.demo.example 1500h 2100h --san smtp.demo.example --san imap.demo.example
issue vpn.demo.example 500h 1000h
issue registry.demo.example 200h 1800h
issue intranet.demo.example 100h 1500h --san www.intranet.demo.example
issue wiki.demo.example 10h 2000h
issue old-portal.demo.example 3000h 4500h

# Revoked with its own certificate and key (step ca revoke picks no provisioner from flags)
$DC exec -T step-ca step ca revoke --cert /tmp/old-portal.demo.example.crt --key /tmp/old-portal.demo.example.key --reasonCode 5 --reason "Service retired" $CA >/dev/null 2>&1 \
  && echo "revoked old-portal.demo.example" || echo "FAILED to revoke old-portal.demo.example"
