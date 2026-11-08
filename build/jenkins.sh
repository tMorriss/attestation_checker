#!/usr/bin/env bash
set -euo pipefail

# GitHub push trigger の新規コミットに [skip ci] が付いている場合だけデプロイを省略する。
COMMIT_MESSAGE=$(git log -1 --pretty=%B)
if grep -qiE "\\[(skip ci|ci skip)\\]" <<< "$COMMIT_MESSAGE"; then
  if [ "${GIT_COMMIT:-}" != "${GIT_PREVIOUS_COMMIT:-}" ]; then
    echo "[INFO] Commit message contains [skip ci] and it's a new commit. Skipping deployment."
    exit 0
  fi
  echo "[INFO] Commit message contains [skip ci] but it's not a new commit. Proceeding with deployment."
fi

if [ -z "${RP_ID:-}" ]; then
  echo "[ERROR] Required environment variable RP_ID is not set."
  exit 1
fi

BUILD_TAG=$(date +%Y%m%d%H%M%S)-$(head -c 8 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 8)
echo "[INFO] Build tag: $BUILD_TAG"

echo "[INFO] Pulling base image..."
podman pull python:3.12

echo "[INFO] Building image..."
podman build \
  -t "localhost/attestation_checker:$BUILD_TAG" \
  -f build/Dockerfile .

# Jenkins 環境変数を Quadlet のコンテナ環境変数として渡す。
QUADLET_DIR="$HOME/.config/containers/systemd/attestation-checker"
echo "[INFO] Deploying Quadlet unit files to $QUADLET_DIR..."
mkdir -p "$QUADLET_DIR"
export BUILD_TAG RP_ID
envsubst '$BUILD_TAG $RP_ID' < build/quadlet/attestation-checker.pod.template > "$QUADLET_DIR/attestation-checker.pod"
envsubst '$BUILD_TAG $RP_ID' < build/quadlet/attestation-checker.container.template > "$QUADLET_DIR/attestation-checker.container"

SCRIPT_UID=$(id -u)
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$SCRIPT_UID}"
echo "[INFO] Reloading systemd user daemon and restarting Quadlet service..."
systemctl --user daemon-reload
systemctl --user restart attestation-checker-pod.service

echo "[INFO] Waiting for service to start..."
sleep 5
systemctl --user --no-pager --full status attestation-checker-pod.service

echo "[INFO] Pod status:"
podman pod ps
echo "[INFO] Container status:"
podman ps --filter pod=attestation-checker-pod

echo "[INFO] Cleaning up old attestation_checker images..."
podman images --filter "reference=localhost/attestation_checker" --format "{{.Tag}}" |
  grep -v "^$BUILD_TAG$" |
  xargs -r -I {} podman rmi "localhost/attestation_checker:{}" || true
podman image prune -f || true

echo "[INFO] done."
