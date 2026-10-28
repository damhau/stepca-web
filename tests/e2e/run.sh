#!/usr/bin/env bash
# End-to-end test against a real step-ca:
#   1. step-ca with remote management, its database on PostgreSQL
#   2. stepca-web connected with a read-only role, TLS pinned with the root fingerprint
#   3. pytest tests/e2e against the running app
# Usage: tests/e2e/run.sh
#   E2E_IDENTITY=admin (default)  the app is a dedicated ADMIN "stepca-web"; its key is decrypted in memory
#                                 from a password file (the recommended setup)
#   E2E_IDENTITY=super            the app is the super admin "step" with a decrypted jwk_key.json (legacy setup)
#   DOCKERFILE=Dockerfile.pip     test the pip image;  KEEP=1  leave the stack running
set -euo pipefail
cd "$(dirname "$0")"

PORT="${E2E_PORT:-15000}"
IDENTITY="${E2E_IDENTITY:-admin}"
DC="docker compose -f compose.yml"
[ "$IDENTITY" = super ] && DC="$DC -f compose.legacy-key.yml"
STEP="$DC exec -T step-ca step"
CA="--ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt"

# compose needs these files to exist before the stack is configured
mkdir -p work/secrets
echo "SECRET_KEY=placeholder" > work/app.env
echo '{}' > work/jwk_key.json
echo '{}' > work/local_users.json

cleanup() { [ "${KEEP:-}" = 1 ] || $DC down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
$DC down -v >/dev/null 2>&1 || true

echo "== Building stepca-web (${DOCKERFILE:-Dockerfile})"
$DC build -q stepca-web

echo "== Initialising step-ca with remote management"
$DC run --rm --no-deps --entrypoint sh step-ca -c '
  mkdir -p /home/step/secrets && printf testpass > /home/step/secrets/password &&
  step ca init --deployment-type standalone --name "E2E CA" --dns step-ca --dns localhost \
    --address :9000 --provisioner admin --remote-management \
    --password-file /home/step/secrets/password --provisioner-password-file /home/step/secrets/password' >/dev/null 2>&1

# Point the CA at PostgreSQL before its first start, so the first provisioner and admin are created there
$DC run --rm --no-deps --entrypoint cat step-ca /home/step/config/ca.json > work/ca.json
python3 - <<'EOF'
import json
config = json.load(open("work/ca.json"))
config["db"] = {"type": "postgresql", "dataSource": "postgresql://step-ca:test@db:5432/", "database": "step_ca_db"}
json.dump(config, open("work/ca.json", "w"), indent=2)
EOF
$DC run --rm --no-deps -T --entrypoint sh step-ca -c 'cat > /home/step/config/ca.json' < work/ca.json

$DC up -d db step-ca
for _ in $(seq 1 30); do $STEP ca health $CA >/dev/null 2>&1 && break; sleep 2; done
$STEP ca health $CA

echo "== Read-only database role for the app"
$DC exec -T db psql -q -U step-ca -d step_ca_db -c "
  CREATE ROLE stepca_web_ro LOGIN PASSWORD 'ro';
  GRANT CONNECT ON DATABASE step_ca_db TO stepca_web_ro;
  GRANT USAGE ON SCHEMA public TO stepca_web_ro;
  GRANT SELECT ON ALL TABLES IN SCHEMA public TO stepca_web_ro;
  ALTER DEFAULT PRIVILEGES FOR ROLE \"step-ca\" IN SCHEMA public GRANT SELECT ON TABLES TO stepca_web_ro;"

if [ "$IDENTITY" = super ]; then
  echo "== App identity: super admin 'step', decrypted key in jwk_key.json"
  PROVISIONER="Admin JWK"; SUBJECT=step; PASSWORD_FILE=
  $STEP ca provisioner list $CA > work/provisioners.json
  python3 -c 'import json; print(next(p["encryptedKey"] for p in json.load(open("work/provisioners.json")) if p["name"] == "Admin JWK"))' \
    | $DC exec -T step-ca step crypto jwe decrypt --password-file /home/step/secrets/password > work/jwk_key.json
else
  echo "== App identity: dedicated ADMIN 'stepca-web' (the commands from the README)"
  PROVISIONER=stepca-web; SUBJECT=stepca-web; PASSWORD_FILE=/run/secrets/ca_admin_password
  printf 'stepca-web-pass' > work/secrets/ca_admin_password
  $DC exec -T step-ca sh -c 'printf stepca-web-pass > /tmp/stepca-web.pass'
  AUTH=(--admin-subject step --admin-provisioner "Admin JWK" --admin-password-file /home/step/secrets/password)
  $STEP ca provisioner add stepca-web --type JWK --create --password-file /tmp/stepca-web.pass "${AUTH[@]}" $CA >/dev/null
  $STEP ca admin add stepca-web stepca-web "${AUTH[@]}" $CA >/dev/null
fi
HASH=$($DC run --rm --no-deps -T --entrypoint python stepca-web -c \
  "from werkzeug.security import generate_password_hash as g; print(g('testpw'))")
python3 -c 'import json, sys; json.dump({"admin": {"password_hash": sys.argv[1], "role": "admin"}}, open("work/local_users.json", "w"))' "$HASH"

cat > work/app.env <<EOF
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
DATABASE_HOST=db
DATABASE_USER=stepca_web_ro
DATABASE_PASSWORD=ro
DATABASE_NAME=step_ca_db
CA_URL=https://step-ca:9000
CA_FINGERPRINT=$($STEP certificate fingerprint /home/step/certs/root_ca.crt)
CA_ADMIN_PROVISIONER_NAME=$PROVISIONER
CA_ADMIN_SUBJECT=$SUBJECT
CA_ADMIN_PASSWORD_FILE=$PASSWORD_FILE
AUTH_BACKEND=local
EOF

echo "== Starting stepca-web"
$DC up -d stepca-web
WEB=$($DC ps -q stepca-web)
for _ in $(seq 1 30); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$WEB")" = healthy ] && break; sleep 2; done
docker inspect -f '{{.State.Health.Status}}' "$WEB" | grep -qx healthy || { $DC logs stepca-web; exit 1; }

echo "== Running the end-to-end tests"
cd ../..
E2E_BASE_URL="http://127.0.0.1:$PORT" E2E_COMPOSE="tests/e2e/compose.yml" E2E_IDENTITY="$IDENTITY" \
  uv run pytest tests/e2e -v -p no:cacheprovider
