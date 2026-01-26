"""
Flask application factory and main application
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import timedelta

from flask import Flask, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress

from config.config import (
    SECRET_KEY,
    LOG_DIR,
    LOG_FORMAT,
    LOG_MAX_SIZE_MB,
    LOG_BACKUP_COUNT,
    SESSION_TIMEOUT_MINUTES,
    JWT_SECRET_KEY,
    JWT_ACCESS_TOKEN_EXPIRES_HOURS,
    JWT_REFRESH_TOKEN_EXPIRES_DAYS
)
from app.models.base import init_db
from app.utils.auth import login_manager
from app.utils.rate_limiting import get_ip_for_ratelimit, handle_rate_limit_exceeded


jwt = JWTManager()
limiter = Limiter(
    key_func=get_ip_for_ratelimit,
    default_limits=["100 per minute", "1000 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)
compress = Compress()


def create_app() -> Flask:
    """Create and configure the Flask application."""
    from app.version import __version__, VERSION_STRING
    
    # Get the base directory (parent of app/)
    base_dir = Path(__file__).resolve().parent.parent
    
    app = Flask('continuum', 
                template_folder=str(base_dir / 'templates'),
                static_folder=str(base_dir / 'static'))
    
    # Configuration
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_TIMEOUT_MINUTES * 60
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=JWT_ACCESS_TOKEN_EXPIRES_HOURS)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=JWT_REFRESH_TOKEN_EXPIRES_DAYS)
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    
    # Make version available in all templates
    app.config['VERSION'] = __version__
    app.config['VERSION_STRING'] = VERSION_STRING
    
    @app.context_processor
    def inject_version():
        return {'app_version': __version__, 'version_string': VERSION_STRING}
    
    # Initialize extensions
    login_manager.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    
    # Enable gzip compression for all responses (massive speed improvement)
    app.config['COMPRESS_MIMETYPES'] = ['text/html', 'text/css', 'text/xml', 'application/json', 'application/javascript']
    app.config['COMPRESS_LEVEL'] = 6  # Balance between speed and compression
    app.config['COMPRESS_MIN_SIZE'] = 500  # Only compress responses > 500 bytes
    compress.init_app(app)
    
    # Enable CORS for API routes (React frontend)
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
    
    # Note: CSRF is NOT initialized since we're using JWT for all API routes
    # and React handles the frontend (no form submissions need CSRF)
    
    # Initialize database
    init_db()
    
    # Sync integrations to database (ensures catalog is up-to-date)
    from app.services.integrations import get_integration_registry
    registry = get_integration_registry()
    registry.sync_to_database()
    
    # Initialize health check tables
    from app.services.health_check import init_health_check_tables, start_health_checks
    init_health_check_tables()
    
    # Start background health checks (only in production, not in reloader)
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        # Only start printer polling services if printers exist
        from app.services.printer_registry import get_registry
        registry = get_registry()
        if registry.has_printers():
            start_health_checks()
            
            # Start the job monitor for print job detection
            from app.services.job_monitor import init_job_monitor
            init_job_monitor(app, start=True)
        else:
            app.logger.info("No printers registered; deferring polling services")
        
        # Start the auto-update checker
        from app.services.updater import init_updater
        init_updater(start_background=True)
        
        # Start the weekly report scheduler
        from app.services.notification_sender import start_weekly_reports
        start_weekly_reports()

        # Start group redirect scheduler
        from app.services.schedulers.group_redirect import init_group_redirect_scheduler
        init_group_redirect_scheduler(start_background=True)

        # Start printer redirect scheduler
        from app.services.schedulers.printer_redirect import init_printer_redirect_scheduler
        init_printer_redirect_scheduler(start_background=True)
        
        # Start workflow scheduler
        from app.services.schedulers.workflow import reload_workflow_schedules
        reload_workflow_schedules()
    
    # Setup logging
    setup_logging(app)
    
    # Register API blueprint only - React handles all UI
    from app.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Register integrations blueprint
    from app.routes.integrations import integrations_bp
    app.register_blueprint(integrations_bp)
    
    # Serve React frontend
    setup_react_frontend(app, base_dir)
    
    # Error handlers
    register_error_handlers(app)
    
    app.logger.info("Continuum application started")
    
    return app


def setup_react_frontend(app: Flask, base_dir: Path):
    """Configure serving of React frontend for production."""
    from flask import send_from_directory, send_file, request
    
    # Path to the React build directory
    frontend_dist = base_dir / 'frontend' / 'dist'
    
    # Only serve React frontend if the build exists
    if not frontend_dist.exists():
        app.logger.info("React frontend not built; using legacy templates")
        app.config['USE_REACT_FRONTEND'] = False
        return
    
    app.logger.info(f"Serving React frontend from {frontend_dist}")
    app.config['USE_REACT_FRONTEND'] = True
    app.config['REACT_DIST_PATH'] = frontend_dist
    
    # Serve React static assets
    @app.route('/assets/<path:filename>')
    def react_assets(filename):
        return send_from_directory(frontend_dist / 'assets', filename)
    
    # Serve vite.svg favicon
    @app.route('/vite.svg')
    def react_vite_svg():
        return send_from_directory(frontend_dist, 'vite.svg')
    
    # Override the root route before blueprints process it
    @app.before_request
    def serve_react_for_spa_routes():
        """Intercept SPA routes and serve React app."""
        # Skip API routes
        if request.path.startswith('/api/'):
            return None
        
        # Skip static files
        if request.path.startswith('/static/'):
            return None
        
        # Skip assets (already handled)
        if request.path.startswith('/assets/'):
            return None
        
        # For all other routes, serve React index.html
        index_file = frontend_dist / 'index.html'
        if index_file.exists():
            return send_file(index_file)
        
        return None  # Fall through to normal routing


def setup_logging(app: Flask):
    """Configure application logging with JSON structured format for syslog/Splunk."""
    from pythonjsonlogger import jsonlogger
    import warnings
    import asyncio
    
    # Suppress pysnmp asyncio task warnings - this is a known issue with pysnmp library
    # where tasks aren't properly awaited before cleanup. Safe to ignore.
    warnings.filterwarnings('ignore', message='.*Task was destroyed but it is pending.*')
    warnings.filterwarnings('ignore', category=ResourceWarning, message='.*unclosed.*')
    
    # Set asyncio exception handler to suppress task destruction warnings
    def asyncio_exception_handler(loop, context):
        """Custom exception handler to suppress pysnmp task destruction warnings."""
        message = context.get('message', '')
        exception = context.get('exception')
        
        # Suppress "Task was destroyed but it is pending" messages from pysnmp
        if 'Task was destroyed but it is pending' in message:
            return
        if 'asyncio.asyncio.Task' in message and 'pending' in message:
            return
        
        # Log other asyncio exceptions normally
        if exception:
            app.logger.error(f"Asyncio exception: {message}", extra={'exception': str(exception)})
        else:
            app.logger.warning(f"Asyncio: {message}")
    
    # Apply to default event loop
    try:
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(asyncio_exception_handler)
    except RuntimeError:
        pass  # No event loop in current thread
    
    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # JSON formatter for structured logging (syslog/Splunk compatible)
    json_formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        rename_fields={'asctime': 'timestamp', 'name': 'logger', 'levelname': 'level'}
    )
    
    # Human-readable formatter for console
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Choose formatter based on configuration
    use_json = os.environ.get('LOG_STRUCTURED', 'false').lower() == 'true'
    file_formatter = json_formatter if use_json else console_formatter
    
    # File handler for application logs
    file_handler = RotatingFileHandler(
        LOG_DIR / 'app.log',
        maxBytes=LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.INFO)
    
    # Console handler for visibility (always human-readable)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)
    
    # Audit log handler (always structured JSON for parsing)
    audit_handler = RotatingFileHandler(
        LOG_DIR / 'audit.log',
        maxBytes=LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=LOG_BACKUP_COUNT
    )
    audit_handler.setFormatter(json_formatter)
    audit_handler.setLevel(logging.INFO)
    
    # Add handlers to Flask app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)
    
    # Configure the 'app' logger namespace so all app.* loggers get handlers
    app_logger = logging.getLogger('app')
    app_logger.addHandler(file_handler)
    app_logger.addHandler(console_handler)
    app_logger.setLevel(logging.INFO)
    
    # Create audit logger
    audit_logger = logging.getLogger('audit')
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    
    # Silence noisy third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('zeroconf').setLevel(logging.WARNING)
    
    app.logger.info("Logging configured", extra={
        'format': 'json' if use_json else 'text',
        'log_dir': str(LOG_DIR)
    })


def register_error_handlers(app: Flask):
    """Register error handlers that return JSON for API errors."""
    from flask import jsonify, request
    from werkzeug.exceptions import TooManyRequests
    from app.utils.rate_limiting import handle_rate_limit_exceeded
    
    # Rate limit error handler
    app.errorhandler(429)(handle_rate_limit_exceeded)
    app.errorhandler(TooManyRequests)(handle_rate_limit_exceeded)
    
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        # For non-API routes, React handles 404
        return app.send_static_file('index.html') if app.config.get('USE_REACT_FRONTEND') else (jsonify({'error': 'Not found'}), 404)
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        
        # Send critical system error to integrations
        try:
            from app.services.integrations import dispatch_event, EventType
            dispatch_event(
                EventType.SYSTEM_ERROR,
                {
                    'error': str(error),
                    'path': request.path if request else 'unknown',
                    'method': request.method if request else 'unknown',
                },
                severity='critical'
            )
        except Exception as e:
            app.logger.error(f"Failed to dispatch system error event: {e}")
        
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return jsonify({'error': 'Forbidden'}), 403
