#!/bin/bash
#
# Update APT Repository
# =====================
# This script updates the apt-repo directory with the latest .deb package
# from the builds directory and regenerates the APT repository metadata.
#
# Usage: ./scripts/update-apt-repo.sh [version]
#   If version is not specified, uses the latest .deb in builds/
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APT_REPO_DIR="$PROJECT_DIR/apt-repo"
BUILDS_DIR="$PROJECT_DIR/builds"
POOL_DIR="$APT_REPO_DIR/pool/main"
DISTS_DIR="$APT_REPO_DIR/dists/stable/main/binary-all"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}!${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Find the .deb file to add
if [[ -n "${1:-}" ]]; then
    DEB_FILE="$BUILDS_DIR/printer-proxy_${1}_all.deb"
    if [[ ! -f "$DEB_FILE" ]]; then
        log_error "Package not found: $DEB_FILE"
        exit 1
    fi
else
    # Find the latest .deb file
    DEB_FILE=$(ls -t "$BUILDS_DIR"/*.deb 2>/dev/null | head -1)
    if [[ -z "$DEB_FILE" ]]; then
        log_error "No .deb files found in $BUILDS_DIR"
        exit 1
    fi
fi

VERSION=$(dpkg-deb --showformat='${Version}' --show "$DEB_FILE")
FILENAME=$(basename "$DEB_FILE")

echo "=============================================="
echo "  Updating APT Repository"
echo "=============================================="
echo ""
echo "Package: $FILENAME"
echo "Version: $VERSION"
echo ""

# Ensure directories exist
mkdir -p "$POOL_DIR" "$DISTS_DIR"

# Copy the .deb file to the pool
log_info "Copying package to pool..."
cp "$DEB_FILE" "$POOL_DIR/"

# Generate Packages file
log_info "Generating Packages file..."
cd "$APT_REPO_DIR"

# Create Packages file with package info
cat > "$DISTS_DIR/Packages" << EOF
EOF

# Add all packages in the pool
for deb in "$POOL_DIR"/*.deb; do
    if [[ -f "$deb" ]]; then
        # Get package metadata
        PKG_NAME=$(dpkg-deb --showformat='${Package}' --show "$deb")
        PKG_VERSION=$(dpkg-deb --showformat='${Version}' --show "$deb")
        PKG_ARCH=$(dpkg-deb --showformat='${Architecture}' --show "$deb")
        PKG_MAINTAINER=$(dpkg-deb --showformat='${Maintainer}' --show "$deb")
        PKG_DEPENDS=$(dpkg-deb --showformat='${Depends}' --show "$deb")
        PKG_DESCRIPTION=$(dpkg-deb --showformat='${Description}' --show "$deb")
        PKG_SECTION=$(dpkg-deb --showformat='${Section}' --show "$deb" 2>/dev/null || echo "misc")
        PKG_PRIORITY=$(dpkg-deb --showformat='${Priority}' --show "$deb" 2>/dev/null || echo "optional")
        PKG_SIZE=$(stat -c%s "$deb")
        PKG_MD5=$(md5sum "$deb" | awk '{print $1}')
        PKG_SHA256=$(sha256sum "$deb" | awk '{print $1}')
        PKG_FILENAME="pool/main/$(basename "$deb")"
        
        cat >> "$DISTS_DIR/Packages" << EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $PKG_ARCH
Maintainer: $PKG_MAINTAINER
Depends: $PKG_DEPENDS
Priority: ${PKG_PRIORITY:-optional}
Section: ${PKG_SECTION:-misc}
Filename: $PKG_FILENAME
Size: $PKG_SIZE
MD5sum: $PKG_MD5
SHA256: $PKG_SHA256
Description: $PKG_DESCRIPTION

EOF
    fi
done

# Create compressed version
log_info "Compressing Packages file..."
gzip -9 -k -f "$DISTS_DIR/Packages"

# Update Release file with checksums
log_info "Updating Release file..."
PACKAGES_SIZE=$(stat -c%s "$DISTS_DIR/Packages")
PACKAGES_GZ_SIZE=$(stat -c%s "$DISTS_DIR/Packages.gz")
PACKAGES_MD5=$(md5sum "$DISTS_DIR/Packages" | awk '{print $1}')
PACKAGES_GZ_MD5=$(md5sum "$DISTS_DIR/Packages.gz" | awk '{print $1}')
PACKAGES_SHA256=$(sha256sum "$DISTS_DIR/Packages" | awk '{print $1}')
PACKAGES_GZ_SHA256=$(sha256sum "$DISTS_DIR/Packages.gz" | awk '{print $1}')
DATE=$(date -R)

cat > "$APT_REPO_DIR/dists/stable/Release" << EOF
Origin: Printer Proxy
Label: Printer Proxy
Suite: stable
Codename: stable
Date: $DATE
Architectures: all
Components: main
Description: Printer Proxy APT Repository
MD5Sum:
 $PACKAGES_MD5 $PACKAGES_SIZE main/binary-all/Packages
 $PACKAGES_GZ_MD5 $PACKAGES_GZ_SIZE main/binary-all/Packages.gz
SHA256:
 $PACKAGES_SHA256 $PACKAGES_SIZE main/binary-all/Packages
 $PACKAGES_GZ_SHA256 $PACKAGES_GZ_SIZE main/binary-all/Packages.gz
EOF

echo ""
log_info "APT repository updated successfully!"
echo ""
echo "Files updated:"
echo "  - pool/main/$FILENAME"
echo "  - dists/stable/main/binary-all/Packages"
echo "  - dists/stable/main/binary-all/Packages.gz"
echo "  - dists/stable/Release"
echo ""
echo "Next steps:"
echo "  1. Commit and push the apt-repo directory"
echo "  2. Enable GitHub Pages for the apt-repo directory"
echo "  3. Users can install with:"
echo ""
echo '     echo "deb [trusted=yes] https://jordonh18.github.io/printer-proxy stable main" | sudo tee /etc/apt/sources.list.d/printer-proxy.list'
echo "     sudo apt update && sudo apt install printer-proxy"
echo ""
