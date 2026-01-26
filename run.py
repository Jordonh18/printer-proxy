#!/usr/bin/env python3
"""
Development server runner
"""
from app import create_app

if __name__ == "__main__":
    app = create_app()
    # Enable threaded mode to handle concurrent requests
    app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)
