#!/bin/bash
#
# Create the initial admin user for Printer Proxy
#
# Usage: ./create_admin.sh <username> <password>
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <username> <password>"
    echo ""
    echo "Password requirements:"
    echo "  - Minimum 12 characters"
    echo "  - At least one uppercase letter"
    echo "  - At least one lowercase letter"
    echo "  - At least one digit"
    echo "  - At least one special character (!@#$%^&*(),.?\":{}|<>)"
    exit 1
fi

USERNAME="$1"
PASSWORD="$2"

cd "$PROJECT_DIR"

# Activate virtual environment if it exists
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
fi

python3 -c "
import sys
sys.path.insert(0, '.')
from app.models import init_db
from app.auth import create_initial_admin

init_db()
success, message = create_initial_admin('$USERNAME', '$PASSWORD')
print(message)
sys.exit(0 if success else 1)
"
