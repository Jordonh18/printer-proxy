#!/bin/bash
#
# Bump version number and optionally rebuild
#
# Usage:
#   ./scripts/bump-version.sh patch    # 1.2.1 -> 1.2.2
#   ./scripts/bump-version.sh minor    # 1.2.1 -> 1.3.0
#   ./scripts/bump-version.sh major    # 1.2.1 -> 2.0.0
#   ./scripts/bump-version.sh 1.5.0    # Set specific version
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION_FILE="$PROJECT_DIR/app/version.py"

# Get current version
CURRENT=$(python3 -c "exec(open('$VERSION_FILE').read()); print(__version__)")
echo "Current version: $CURRENT"

if [ -z "$1" ]; then
    echo ""
    echo "Usage: $0 <patch|minor|major|X.Y.Z>"
    echo ""
    echo "  patch  - Increment patch version (1.2.1 -> 1.2.2)"
    echo "  minor  - Increment minor version (1.2.1 -> 1.3.0)"
    echo "  major  - Increment major version (1.2.1 -> 2.0.0)"
    echo "  X.Y.Z  - Set specific version"
    exit 1
fi

# Parse current version
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$1" in
    patch)
        PATCH=$((PATCH + 1))
        NEW_VERSION="$MAJOR.$MINOR.$PATCH"
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        NEW_VERSION="$MAJOR.$MINOR.$PATCH"
        ;;
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        NEW_VERSION="$MAJOR.$MINOR.$PATCH"
        ;;
    *)
        # Assume it's a specific version
        if [[ ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "Error: Invalid version format. Use X.Y.Z"
            exit 1
        fi
        NEW_VERSION="$1"
        ;;
esac

echo "New version: $NEW_VERSION"
echo ""

# Update version.py
cat > "$VERSION_FILE" << EOF
"""
Single source of truth for application version.

Update this file to change the version everywhere.
The build script and templates read from here.
"""

__version__ = "$NEW_VERSION"
__version_info__ = tuple(int(x) for x in __version__.split("."))

# For display
VERSION_STRING = f"Continuum v{__version__}"
EOF

echo "✓ Updated $VERSION_FILE"

# Prompt to rebuild
echo ""
read -p "Build package now? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    "$SCRIPT_DIR/build-deb.sh"
fi
