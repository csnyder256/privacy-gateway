#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
cd "$repo_root"

image_name="${PRIVACY_GATEWAY_SMOKE_IMAGE:-privacy-gateway:smoke}"
container_name="${PRIVACY_GATEWAY_SMOKE_CONTAINER:-privacy-gateway-smoke}"
host_port="${PRIVACY_GATEWAY_SMOKE_PORT:-18787}"

if docker container inspect "$container_name" >/dev/null 2>&1; then
  echo "refusing to replace existing container: $container_name" >&2
  exit 2
fi

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build --tag "$image_name" .
master_key="$(docker run --rm "$image_name" privacy-gateway keygen)"
docker run --detach --name "$container_name" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /data:size=16m,mode=1777 \
  --tmpfs /tmp:size=16m,mode=1777 \
  -p "127.0.0.1:${host_port}:8787" \
  -e PRIVACY_GATEWAY_MASTER_KEY="$master_key" \
  "$image_name" >/dev/null

for _ in $(seq 1 30); do
  if curl --silent --show-error --fail "http://127.0.0.1:${host_port}/v1/health" \
    | grep -q '"ok":true'; then
    docker exec "$container_name" privacy-gateway verify >/dev/null
    echo "container smoke test passed"
    exit 0
  fi
  sleep 1
done

docker logs "$container_name" >&2
exit 1
