#!/bin/sh
set -e

REPO="Agent-Gen-com/tesla-cli"
BINARY="teslacli"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux)  OS_NAME="unknown-linux-gnu" ;;
  Darwin) OS_NAME="apple-darwin" ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64 | amd64) ARCH_NAME="x86_64" ;;
  arm64 | aarch64) ARCH_NAME="aarch64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

TARGET="${ARCH_NAME}-${OS_NAME}"
ARCHIVE="${BINARY}-${TARGET}.tar.gz"

# Fetch latest release tag
echo "Fetching latest release..."
LATEST_TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

if [ -z "$LATEST_TAG" ]; then
  echo "Could not determine latest release tag."
  exit 1
fi

echo "Installing ${BINARY} ${LATEST_TAG} (${TARGET})..."

URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ARCHIVE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "$URL" -o "${TMP_DIR}/${ARCHIVE}"
tar xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"

# Install (try without sudo first, fall back to sudo)
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"
echo "Done!"
echo "Starting setup wizard..."
"${INSTALL_DIR}/${BINARY}" setup
