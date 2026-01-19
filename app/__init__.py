"""
Flask application factory and main application
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from config.config import (
    SECRET_KEY,
    LOG_DIR,
    LOG_FORMAT,
    LOG_MAX_SIZE_MB,
    LOG_BACKUP_COUNT,
    SESSION_TIMEOUT_MINUTES
)
from app.models import init_db
from app.auth import login_manager


csrf = CSRFProtect()


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
    
    # Make version available in all templates
    app.config['VERSION'] = __version__
    app.config['VERSION_STRING'] = VERSION_STRING
    
    @app.context_processor
    def inject_version():
        return {'app_version': __version__, 'version_string': VERSION_STRING}
    
    # Initialize extensions
    csrf.init_app(app)
    login_manager.init_app(app)
    
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
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    from app.routes import main_bp, auth_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Error handlers
    register_error_handlers(app)
    
    app.logger.info("Printer Proxy application started")
    
    return app


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
    """Register error handlers."""
    from flask import render_template
    
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403
