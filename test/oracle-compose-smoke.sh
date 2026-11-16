#!/usr/bin/env bash
# Disposable CI rehearsal with a synthetic grant and two file-backed fixture keys.
set -euo pipefail
work=$(mktemp -d)
export IDENTITY_IMAGE="onesa-identity:smoke-$$"
export IDENTITY_VOLUME="$work/data"
export IDENTITY_ORIGIN=https://account.example.test
export OIDC_CLIENT_ID=ci-account
export RESOURCE_CLIENTS_JSON='{"https://api.factory.example.test":{"product":"factory","clients":["ci-factory"]}}'
export OIDC_CLIENT_SECRET_PATH="$work/client-secret" ACTION_POLICY_KEY_PATH="$work/policy-key"
export IDENTITY_HOST_PORT
IDENTITY_HOST_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
compose=(docker compose -p "onesa-identity-smoke-$$" -f deploy/compose.oracle.yaml)
cleanup() {
  "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
  docker run --rm --user 0:0 --volume "$IDENTITY_VOLUME:/data" "$IDENTITY_IMAGE" chown "$(id -u):$(id -g)" /data >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir "$IDENTITY_VOLUME"
printf '%s\n' ci-client-secret > "$OIDC_CLIENT_SECRET_PATH"
printf '%s\n' ci-only-key-for-the-synthetic-policy-test > "$ACTION_POLICY_KEY_PATH"
chmod 0444 "$OIDC_CLIENT_SECRET_PATH" "$ACTION_POLICY_KEY_PATH"
"${compose[@]}" config --quiet
docker build -t "$IDENTITY_IMAGE" .
docker run --rm --user 0:0 --volume "$IDENTITY_VOLUME:/data" "$IDENTITY_IMAGE" chown node:node /data
docker run --rm --volume "$IDENTITY_VOLUME:/data" "$IDENTITY_IMAGE" node --input-type=module -e '
  import { openStore } from "./src/store.js";
  const store = openStore("/data/identity.sqlite");
  const row = store.register("https://auth.onesa.eu/", "ci-subject", "fixture@example.test");
  store.change("ci-fixture", row.id, 1, {kind:"status",status:"active"});
  store.change("ci-fixture", row.id, 2, {kind:"grant",product:"factory",role:"user",status:"active"});
  store.db.close();
'
"${compose[@]}" up -d --wait --wait-timeout 90
base="http://127.0.0.1:$IDENTITY_HOST_PORT"
curl -fsS "$base/readyz" | python3 -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'
test "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$base/internal/decision")" = 401
decision() {
  curl -fsS -X POST "$base/internal/decision" -H "Authorization: Bearer $(cat "$ACTION_POLICY_KEY_PATH")" \
    -H 'Content-Type: application/json' --data '{"subject":"ci-subject","audience":"https://api.factory.example.test","client":"ci-factory"}'
}
before=$(decision)
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["product"]=="factory" and d["roles"]==["user"] and d["user_id"]' "$before"
"${compose[@]}" up -d --force-recreate --wait --wait-timeout 90
test "$(decision)" = "$before"
