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
from app.models import init_db
from app.auth import login_manager


jwt = JWTManager()


def create_app() -> Flask:
    """Create and configure the Flask application."""
    from app.version import __version__, VERSION_STRING
    
    # Get the base directory (parent of app/)
    base_dir = Path(__file__).resolve().parent.parent
    
    app = Flask('printer-proxy', 
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
    
    # Enable CORS for API routes (React frontend)
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
    
    # Note: CSRF is NOT initialized since we're using JWT for all API routes
    # and React handles the frontend (no form submissions need CSRF)
    
    # Initialize database
    init_db()
    
    # Initialize health check tables
    from app.health_check import init_health_check_tables, start_health_checks
    init_health_check_tables()
    
    # Start background health checks (only in production, not in reloader)
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        # Only start printer polling services if printers exist
        from app.printers import get_registry
        registry = get_registry()
        if registry.has_printers():
            start_health_checks()
            
            # Start the job monitor for print job detection
            from app.job_monitor import init_job_monitor
            init_job_monitor(app, start=True)
        else:
            app.logger.info("No printers registered; deferring polling services")
        
        # Start the auto-update checker
        from app.updater import init_updater
        init_updater(start_background=True)
        
        # Start the weekly report scheduler
        from app.notifications import start_weekly_reports
        start_weekly_reports()
    
    # Setup logging
    setup_logging(app)
    
    # Register API blueprint only - React handles all UI
    from app.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Serve React frontend
    setup_react_frontend(app, base_dir)
    
    # Error handlers
    register_error_handlers(app)
    
    app.logger.info("Printer Proxy application started")
    
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
    """Configure application logging."""
    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # File handler for application logs
    file_handler = RotatingFileHandler(
        LOG_DIR / 'app.log',
        maxBytes=LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    file_handler.setLevel(logging.INFO)
    
    # Console handler for visibility
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    console_handler.setLevel(logging.INFO)
    
    # Audit log handler
    audit_handler = RotatingFileHandler(
        LOG_DIR / 'audit.log',
        maxBytes=LOG_MAX_SIZE_MB * 1024 * 1024,
        backupCount=LOG_BACKUP_COUNT
    )
    audit_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    audit_handler.setLevel(logging.INFO)
    
    # Add handlers to Flask app logger
    app.logger.addHandler(file_handler)
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


def register_error_handlers(app: Flask):
    """Register error handlers that return JSON for API errors."""
    from flask import jsonify, request
    
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        # For non-API routes, React handles 404
        return app.send_static_file('index.html') if app.config.get('USE_REACT_FRONTEND') else (jsonify({'error': 'Not found'}), 404)
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return jsonify({'error': 'Forbidden'}), 403
