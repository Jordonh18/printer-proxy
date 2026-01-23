"""
Rate limiting configuration and custom handlers
"""
from flask import jsonify, request
from werkzeug.exceptions import TooManyRequests


def handle_rate_limit_exceeded(e):
    """Custom handler for rate limit errors."""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description),
        'retry_after': e.retry_after if hasattr(e, 'retry_after') else None
    }), 429


def get_ip_for_ratelimit():
    """Get client IP for rate limiting (handles proxies)."""
    # Check for X-Forwarded-For header (proxy/load balancer)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    # Check for X-Real-IP header
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    # Fall back to remote_addr
    return request.remote_addr or '127.0.0.1'


# Rate limit configurations for different endpoint types
RATE_LIMITS = {
    'login': '5 per minute',           # Strict limit to prevent brute force
    'setup': '10 per minute',          # Setup endpoint
    'mfa_verify': '10 per minute',     # MFA verification
    'api_token_create': '10 per hour', # Token creation
    'discovery': '5 per minute',       # Resource-heavy network scans
    'audit_logs': '30 per minute',     # Database-heavy queries
    'user_create': '20 per hour',      # User management
    'password_change': '5 per minute', # Password changes
    'api_default': '100 per minute',   # Default for authenticated API calls
}
