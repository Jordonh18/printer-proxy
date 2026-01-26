#!/bin/bash
#
# Build Debian package for Continuum
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Read version from single source of truth (app/version.py)
VERSION=$(python3 -c "exec(open('$PROJECT_DIR/app/version.py').read()); print(__version__)")
if [ -z "$VERSION" ]; then
    echo "Error: Could not read version from app/version.py"
    exit 1
fi

PACKAGE_NAME="continuum"
BUILD_DIR="/tmp/${PACKAGE_NAME}-build"

echo "=============================================="
echo "  Building ${PACKAGE_NAME} v${VERSION}"
echo "=============================================="
echo ""

# Check for required tools
for cmd in dpkg-deb fakeroot node npm rsync; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd is required but not installed."
        if [ "$cmd" = "node" ] || [ "$cmd" = "npm" ]; then
            echo "Install with: sudo apt install nodejs npm"
        elif [ "$cmd" = "rsync" ]; then
            echo "Install with: sudo apt install rsync"
        else
            echo "Install with: sudo apt install dpkg-dev fakeroot"
        fi
        exit 1
    fi
done

# Build React frontend
echo "Building React frontend..."
if [ -d "$PROJECT_DIR/frontend" ]; then
    cd "$PROJECT_DIR/frontend"
    
    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        echo "Installing frontend dependencies..."
        npm install
    fi
    
    # Build production bundle
    echo "Creating production build..."
    npm run build
    
    cd "$PROJECT_DIR"
    
    if [ ! -d "$PROJECT_DIR/frontend/dist" ]; then
        echo "Error: Frontend build failed - dist directory not created"
        exit 1
    fi
    echo "Frontend build complete!"
else
    echo "Warning: frontend directory not found, skipping React build"
fi

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Create directory structure
echo "Creating package structure..."
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/opt/continuum/app"
mkdir -p "$BUILD_DIR/opt/continuum/config"
mkdir -p "$BUILD_DIR/opt/continuum/scripts"
mkdir -p "$BUILD_DIR/opt/continuum/static"
mkdir -p "$BUILD_DIR/opt/continuum/frontend/dist"
mkdir -p "$BUILD_DIR/etc/continuum"
mkdir -p "$BUILD_DIR/lib/systemd/system"
mkdir -p "$BUILD_DIR/usr/share/doc/continuum"
mkdir -p "$BUILD_DIR/usr/share/lintian/overrides"

# Copy application files
echo "Copying application files..."
# Copy app directory structure while excluding __pycache__
rsync -a --exclude='__pycache__' --exclude='*.pyc' "$PROJECT_DIR/app/" "$BUILD_DIR/opt/continuum/app/"
cp "$PROJECT_DIR/config/__init__.py" "$BUILD_DIR/opt/continuum/config/"
cp "$PROJECT_DIR/config/config.py" "$BUILD_DIR/opt/continuum/config/"
cp "$PROJECT_DIR/scripts/"*.sh "$BUILD_DIR/opt/continuum/scripts/"
cp "$PROJECT_DIR/requirements.txt" "$BUILD_DIR/opt/continuum/"
cp "$PROJECT_DIR/wsgi.py" "$BUILD_DIR/opt/continuum/"
cp "$PROJECT_DIR/run.py" "$BUILD_DIR/opt/continuum/"

# Copy static files if they exist
if [ -d "$PROJECT_DIR/static" ] && [ "$(ls -A "$PROJECT_DIR/static" 2>/dev/null)" ]; then
    cp -r "$PROJECT_DIR/static/"* "$BUILD_DIR/opt/continuum/static/" 2>/dev/null || true
fi

# Copy React frontend build
if [ -d "$PROJECT_DIR/frontend/dist" ]; then
    echo "Copying React frontend build..."
    cp -r "$PROJECT_DIR/frontend/dist/"* "$BUILD_DIR/opt/continuum/frontend/dist/"
fi

# Copy systemd service
cp "$PROJECT_DIR/debian/continuum.service" "$BUILD_DIR/lib/systemd/system/"

# Copy and compress changelog for Debian documentation
echo "Creating Debian documentation..."
gzip -9cn "$PROJECT_DIR/debian/changelog" > "$BUILD_DIR/usr/share/doc/continuum/changelog.Debian.gz"

# Copy copyright file
cp "$PROJECT_DIR/debian/copyright" "$BUILD_DIR/usr/share/doc/continuum/"

# Copy lintian overrides
cp "$PROJECT_DIR/debian/continuum.lintian-overrides" \
   "$BUILD_DIR/usr/share/lintian/overrides/continuum"

# Create DEBIAN control file
cat > "$BUILD_DIR/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-venv, python3-pip, adduser, iptables, iproute2, iputils-ping, arping, nginx, openssl
Recommends: snmp
Suggests: ufw
Maintainer: Jordon Harrison <jordonh18@users.noreply.github.com>
Homepage: https://github.com/Jordonh18/continuum
Description: Network printer traffic redirection tool with web interface
 Continuum is a web application that redirects network print traffic
 from one printer IP address to another using NAT/iptables rules. This
 allows print clients to continue using the same IP address when a printer
 fails, while traffic is transparently forwarded to a working backup printer.
 .
 Features:
  * Web-based management interface with printer discovery
  * Automatic network configuration detection
  * Password-protected access with account lockout protection
  * Full audit logging of all configuration changes
  * Support for TCP 9100 (RAW/JetDirect) printing protocol
  * Printer health monitoring with SNMP and ICMP checks
EOF

# Copy maintainer scripts
cp "$PROJECT_DIR/debian/postinst" "$BUILD_DIR/DEBIAN/"
cp "$PROJECT_DIR/debian/prerm" "$BUILD_DIR/DEBIAN/"
cp "$PROJECT_DIR/debian/postrm" "$BUILD_DIR/DEBIAN/"

# Set permissions
chmod 755 "$BUILD_DIR/DEBIAN/postinst"
chmod 755 "$BUILD_DIR/DEBIAN/prerm"
chmod 755 "$BUILD_DIR/DEBIAN/postrm"
chmod 755 "$BUILD_DIR/opt/continuum/scripts/"*.sh

# Build the package
echo "Building .deb package..."
mkdir -p "$PROJECT_DIR/builds"
OUTPUT_FILE="$PROJECT_DIR/builds/${PACKAGE_NAME}_${VERSION}_all.deb"
fakeroot dpkg-deb --build "$BUILD_DIR" "$OUTPUT_FILE"

# Generate SHA256 checksum file (for secure updates)
echo "Generating SHA256 checksum..."
CHECKSUM_FILE="$PROJECT_DIR/builds/${PACKAGE_NAME}_${VERSION}_all.deb.sha256"
(cd "$PROJECT_DIR/builds" && sha256sum "$(basename "$OUTPUT_FILE")" > "$CHECKSUM_FILE")
echo "Checksum: $(cat "$CHECKSUM_FILE")"

# Clean up
rm -rf "$BUILD_DIR"

echo ""
echo "=============================================="
echo "  Package built successfully!"
echo "=============================================="
echo ""
echo "Output files:"
echo "  Package:  $OUTPUT_FILE"
echo "  Checksum: $CHECKSUM_FILE"
echo ""
echo "Install with:"
echo "  sudo dpkg -i $OUTPUT_FILE"
echo "  sudo apt-get install -f  # Install dependencies"
echo ""
echo "Or install with apt directly:"
echo "  sudo apt install ./builds/${PACKAGE_NAME}_${VERSION}_all.deb"
echo ""
echo "For GitHub releases, upload both files:"
echo "  - ${PACKAGE_NAME}_${VERSION}_all.deb"
echo "  - ${PACKAGE_NAME}_${VERSION}_all.deb.sha256"
echo ""
echo "Optional: Sign the package with GPG:"
echo "  gpg --armor --detach-sign $OUTPUT_FILE"
echo ""
