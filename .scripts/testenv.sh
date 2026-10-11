#!/usr/bin/env bash
#
# Bring up throwaway Technitium DNS servers in Docker, mint an API token on
# each, and print the environment the live test suites need.
#
#   eval "$(.scripts/testenv.sh up single)"   # one server: ns1
#   eval "$(.scripts/testenv.sh add)"         # a second beside it: ns2
#   eval "$(.scripts/testenv.sh up)"          # or both at once (up pair)
#   .scripts/testenv.sh down                  # stop and remove everything
#   .scripts/testenv.sh logs                  # what each server wrote
#
# technitium-mcp works on one server, on several, and on several that are a
# cluster, so the suites run against all three, in that order and on the same
# servers: one server, then a second started beside it, then the two made a
# cluster. The first two are this script's work. The cluster is made by the
# suites themselves, through the API, because making one is something
# technitium-mcp's own client does; this script only hands them what that
# needs and no API gives: each server's address on the network they share,
# and the administrator's password.
#
# Each server is also given the app that keeps a searchable log of its
# queries, Query Logs (Sqlite), which the log tools read: an app is installed
# from a file, which is not something technitium-mcp does. The file is the one
# the server's own app store names for its version, fetched once and kept in
# .tools/cache.
#
# The servers also lease addresses, and a lease is only made by a machine
# asking for one. So the suites are handed the network's name and range and
# the image of a small DHCP client, which they run on the network for a
# moment as a machine that asks (lib/testenv). Nothing outside that network
# hears either side of it.
#
# One server is given the way a single server is configured, with no name; two
# are named ns1 and ns2. They share a Docker network and reach each other by
# name.
#
# This script only does what technitium-mcp cannot: run the containers and mint
# the tokens. The zones and records are the test suites' job, so the client
# and the tools are exercised rather than bypassed.
#
# Neither server's DNS port is published: the suites ask each server to resolve
# through its own API, and nothing on this machine should start answering DNS.

set -euo pipefail

IMAGE="${TECHNITIUM_TEST_IMAGE:-technitium/dns-server:latest}"
# the machine that asks the servers for a lease: its udhcpc is the client
CLIENT_IMAGE="${TECHNITIUM_TEST_CLIENT_IMAGE:-busybox:latest}"
# the containers are <prefix>-ns1 and <prefix>-ns2, so two suites can each have a pair
PREFIX="${TECHNITIUM_TEST_CONTAINER:-technitium-mcp-test}"
NETWORK="${PREFIX}-net"
# ns1 answers on the port, ns2 on the one after it
PORT="${TECHNITIUM_TEST_PORT:-15380}"
# the password is a string nothing else here is called: the acceptance suite reads everything
# a tool says for it, and a password that is also the token's name is "shown" by every list of tokens
PASSWORD="an-adm1n-passw0rd-for-the-suites"
TOKEN_NAME="technitium-mcp-test"
# the app that keeps a searchable log of queries, and where its file is kept between runs
LOG_APP="Query Logs (Sqlite)"
CACHE="${TECHNITIUM_TEST_CACHE:-$(cd "$(dirname "$0")/.." && pwd)/.tools/cache}"

port_of() {
  case "$1" in
    ns1) echo "$PORT" ;;
    ns2) echo "$((PORT + 1))" ;;
  esac
}

url_of() { echo "http://127.0.0.1:$(port_of "$1")"; }

need() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null || { echo "testenv: $tool is required" >&2; exit 1; }
  done
}

is_running() {
  [ "$(docker inspect -f '{{.State.Running}}' "${PREFIX}-$1" 2>/dev/null)" = "true" ]
}

# address_of is a server's address on the network the servers share, which is
# where the other reaches it
address_of() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${PREFIX}-$1"
}

# wait_ready waits for a server's API to answer, which it does a few seconds
# after the container starts
wait_ready() {
  local name="$1" url
  url="$(url_of "$name")"
  for _ in $(seq 1 60); do
    if curl -sf "${url}/api/status" 2>/dev/null | jq -e '.status == "ok"' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "testenv: ${PREFIX}-${name} did not answer on ${url} within 60s" >&2
  docker logs --tail 40 "${PREFIX}-${name}" >&2 || true
  exit 1
}

# mint_token asks a server for an API token that does not expire, as the
# administrator the container was started with. The password travels in the
# request body, not the address.
mint_token() {
  local name="$1" answer
  answer="$(curl -sf "$(url_of "$name")/api/user/createToken" \
    --data-urlencode "user=admin" --data-urlencode "pass=${PASSWORD}" --data-urlencode "tokenName=${TOKEN_NAME}")"
  if [ "$(jq -r '.status' <<<"$answer")" != "ok" ]; then
    echo "testenv: ${PREFIX}-${name} would not mint a token: $(jq -r '.errorMessage // .status' <<<"$answer")" >&2
    exit 1
  fi
  jq -r '.token' <<<"$answer"
}

# install_log_app gives a server the app that keeps a searchable log of its
# queries, from the file its own app store names, which is fetched once and
# kept. A server that has the app already is left as it is.
install_log_app() {
  local name="$1" token="$2" url api zip answer
  api="$(url_of "$name")/api"
  if curl -sf -H "Authorization: Bearer ${token}" "${api}/apps/list" | jq -e --arg app "$LOG_APP" '.response.apps[]? | select(.name == $app)' >/dev/null; then
    return 0
  fi

  url="$(curl -sf -H "Authorization: Bearer ${token}" "${api}/apps/listStoreApps" | jq -r --arg app "$LOG_APP" '.response.storeApps[]? | select(.name == $app) | .url')"
  if [ -z "$url" ]; then
    echo "testenv: ${PREFIX}-${name}'s app store does not list ${LOG_APP}: it cannot be reached, or no longer has it" >&2
    exit 1
  fi
  zip="${CACHE}/$(basename "$url")"
  if [ ! -s "$zip" ]; then
    mkdir -p "$CACHE"
    echo "testenv: fetching ${LOG_APP} from ${url}" >&2
    curl -sfL -o "${zip}.part" "$url" || { echo "testenv: could not fetch ${url}" >&2; exit 1; }
    mv "${zip}.part" "$zip"
  fi

  # the file goes in the body, so the app's name goes in the address, written as an address takes it
  answer="$(curl -sf -H "Authorization: Bearer ${token}" -F "fileAppZip=@${zip}" "${api}/apps/install?name=$(jq -rn --arg app "$LOG_APP" '$app | @uri')")"
  if [ "$(jq -r '.status' <<<"$answer")" != "ok" ]; then
    echo "testenv: ${PREFIX}-${name} would not install ${LOG_APP}: $(jq -r '.errorMessage // .status' <<<"$answer")" >&2
    exit 1
  fi
}

# pull_image fetches an image when this machine does not have it: from
# Google's mirror of Docker Hub, which holds the same image under the same
# name and does not turn away a CI runner for what its shared address has
# pulled, and from Docker Hub itself when the mirror gives nothing - it can be
# a while behind a newly published image. An image already here is used as it
# is: docker pull it to test a newer one.
pull_image() {
  local image="$1" mirrored
  docker image inspect "$image" >/dev/null 2>&1 && return 0
  case "$image" in
    */*/*)
      # names a registry of its own: there is no mirror of it to try
      docker pull -q "$image" >/dev/null || {
        echo "testenv: could not pull ${image}" >&2
        exit 1
      }
      return 0
      ;;
    */*) mirrored="mirror.gcr.io/${image}" ;;
    # an official image, which Docker Hub and its mirror keep under library/
    *) mirrored="mirror.gcr.io/library/${image}" ;;
  esac
  if docker pull -q "$mirrored" >/dev/null 2>&1; then
    docker tag "$mirrored" "$image"
    return 0
  fi
  echo "testenv: mirror.gcr.io would not give ${image}: taking it from Docker Hub" >&2
  docker pull -q "$image" >/dev/null || {
    echo "testenv: could not pull ${image} from mirror.gcr.io or from Docker Hub" >&2
    exit 1
  }
}

# start runs one server's container, on the network the servers share
start() {
  local name="$1"
  docker run -d --name "${PREFIX}-${name}" --hostname "$name" --network "$NETWORK" --network-alias "$name" \
    -p "127.0.0.1:$(port_of "$name"):5380" \
    -e "DNS_SERVER_DOMAIN=${name}" \
    -e "DNS_SERVER_ADMIN_PASSWORD=${PASSWORD}" \
    "$IMAGE" >/dev/null
}

# print_env mints a token on each server named and prints the environment for
# them: one server as a single server is configured, with no name, and two by
# their names.
print_env() {
  local servers="" tokens="" addresses="" name token
  for name in "$@"; do
    wait_ready "$name"
    token="$(mint_token "$name")"
    install_log_app "$name" "$token"
    if [ "$#" -eq 1 ]; then
      servers="$(url_of "$name")"
      tokens="$token"
    else
      servers="${servers:+${servers},}${name}=$(url_of "$name")"
      tokens="${tokens:+${tokens},}${name}=${token}"
    fi
    addresses="${addresses:+${addresses},}${name}=$(address_of "$name")"
  done

  # everything a person reads goes to stderr: stdout is what eval takes
  echo "testenv: $* up (${IMAGE})" >&2
  echo "export TECHNITIUM_SERVER='${servers}'"
  echo "export TECHNITIUM_TOKEN='${tokens}'"
  echo "export TECHNITIUM_TEST_CONTAINER='${PREFIX}'"
  echo "export TECHNITIUM_TEST_ADDRESSES='${addresses}'"
  echo "export TECHNITIUM_TEST_PASSWORD='${PASSWORD}'"
  echo "export TECHNITIUM_TEST_NETWORK='${NETWORK}'"
  echo "export TECHNITIUM_TEST_SUBNET='$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK")'"
  echo "export TECHNITIUM_TEST_CLIENT_IMAGE='${CLIENT_IMAGE}'"
}

up() {
  local how="${1:-pair}"
  case "$how" in
    single | pair) ;;
    *)
      echo "testenv: up takes single or pair, not ${how}" >&2
      exit 1
      ;;
  esac
  need docker curl jq
  down >/dev/null 2>&1 || true
  pull_image "$IMAGE"
  pull_image "$CLIENT_IMAGE"

  docker network create "$NETWORK" >/dev/null
  start ns1
  if [ "$how" = "single" ]; then
    print_env ns1
    return 0
  fi
  start ns2
  print_env ns1 ns2
}

# add starts the second server beside a first that is already up
add() {
  need docker curl jq
  is_running ns1 || { echo "testenv: ${PREFIX}-ns1 is not running: there is nothing to add a server beside" >&2; exit 1; }
  pull_image "$CLIENT_IMAGE"
  is_running ns2 || start ns2
  print_env ns1 ns2
}

down() {
  need docker
  local name
  for name in ns1 ns2; do
    docker rm -f -v "${PREFIX}-${name}" >/dev/null 2>&1 || true
  done
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}

logs() {
  need docker
  local name
  for name in ns1 ns2; do
    is_running "$name" || continue
    echo "==> ${PREFIX}-${name}" >&2
    docker logs --tail 200 "${PREFIX}-${name}" >&2 || true
  done
}

case "${1:-up}" in
  up) up "${2:-pair}" ;;
  add) add ;;
  down) down ;;
  logs) logs ;;
  *)
    echo "usage: $0 up [single|pair] | add | down | logs" >&2
    exit 1
    ;;
esac
