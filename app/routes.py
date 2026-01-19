"""
Flask routes and views
"""
from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, jsonify
)
from flask_login import login_user, logout_user, login_required, current_user

from app.models import AuditLog, ActiveRedirect
from app.auth import authenticate_user, create_initial_admin, validate_password_strength
from app.printers import get_registry, Printer
from app.network import get_network_manager
from app.discovery import get_discovery
from config.config import DEFAULT_PORT


# Blueprints
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
api_bp = Blueprint('api', __name__)


# ============================================================================
# Main Routes
# ============================================================================

@main_bp.route('/')
@login_required
def dashboard():
    """Main dashboard showing all printers and their status."""
    registry = get_registry()
    printers = registry.get_all_statuses()
    active_redirects = ActiveRedirect.get_all()
    
    return render_template('dashboard.html',
                         printers=printers,
                         active_redirects=active_redirects)


@main_bp.route('/printer/<printer_id>')
@login_required
def printer_detail(printer_id):
    """Detailed view of a specific printer."""
    from app.health_check import get_printer_health, get_printer_health_history
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        flash('Printer not found', 'error')
        return redirect(url_for('main.dashboard'))
    
    status = registry.get_printer_status(printer, use_cache=True)
    available_targets = registry.get_available_targets(exclude_printer_id=printer_id)
    audit_history = AuditLog.get_by_printer(printer_id)
    
    # Get health check status (fast - from cache)
    health_status = get_printer_health(printer_id)
    health_history = get_printer_health_history(printer_id, limit=24)
    
    # NOTE: SNMP stats are loaded asynchronously via JavaScript
    # to avoid blocking page render
    
    return render_template('printer_detail.html',
                         printer=printer,
                         status=status,
                         available_targets=available_targets,
                         audit_history=audit_history,
                         health_status=health_status,
                         health_history=health_history)


@main_bp.route('/printer/<printer_id>/queue')
@login_required
def printer_queue(printer_id):
    """Print queue for a specific printer."""
    from app.print_queue import get_print_queue
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        flash('Printer not found', 'error')
        return redirect(url_for('main.dashboard'))
    
    queue = get_print_queue(printer.ip)
    
    return render_template('printer_queue.html',
                         printer=printer,
                         queue=queue)


@main_bp.route('/printer/<printer_id>/jobs')
@login_required
def printer_jobs(printer_id):
    """Job history for a specific printer."""
    from app.models import PrintJobHistory
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        flash('Printer not found', 'error')
        return redirect(url_for('main.dashboard'))
    
    jobs = PrintJobHistory.get_for_printer(printer_id, limit=100)
    stats = PrintJobHistory.get_statistics(printer_id)
    
    return render_template('printer_jobs.html',
                         printer=printer,
                         jobs=jobs,
                         stats=stats)


@main_bp.route('/printer/<printer_id>/logs')
@login_required
def printer_logs(printer_id):
    """Logs for a specific printer."""
    from app.print_queue import get_printer_logs
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        flash('Printer not found', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Get current logs from SNMP
    logs = get_printer_logs(printer.ip)
    
    return render_template('printer_logs.html',
                         printer=printer,
                         logs=logs)


@main_bp.route('/redirect/<printer_id>', methods=['POST'])
@login_required
def create_redirect(printer_id):
    """Create a new redirect for a printer."""
    registry = get_registry()
    network = get_network_manager()
    
    source_printer = registry.get_by_id(printer_id)
    if not source_printer:
        flash('Source printer not found', 'error')
        return redirect(url_for('main.dashboard'))
    
    target_printer_id = request.form.get('target_printer_id')
    target_printer = registry.get_by_id(target_printer_id)
    
    if not target_printer:
        flash('Target printer not found', 'error')
        return redirect(url_for('main.printer_detail', printer_id=printer_id))
    
    # Safety checks
    if source_printer.ip == target_printer.ip:
        flash('Source and target printer cannot have the same IP', 'error')
        return redirect(url_for('main.printer_detail', printer_id=printer_id))
    
    # Check if source is already redirected
    existing = ActiveRedirect.get_by_source_printer(printer_id)
    if existing:
        flash('This printer already has an active redirect', 'error')
        return redirect(url_for('main.printer_detail', printer_id=printer_id))
    
    # Check if target is already in use
    if ActiveRedirect.is_target_in_use(target_printer_id):
        flash('Target printer is already being used as a redirect target', 'error')
        return redirect(url_for('main.printer_detail', printer_id=printer_id))
    
    # Check if source printer is still reachable (should be offline)
    if registry.check_tcp_reachability(source_printer.ip):
        flash('Warning: Source printer appears to be online. Redirect may cause conflicts.', 'warning')
    
    # Check if target printer is reachable
    if not registry.check_tcp_reachability(target_printer.ip):
        flash('Warning: Target printer appears to be offline', 'warning')
    
    # Enable the redirect
    success, message = network.enable_redirect(
        source_ip=source_printer.ip,
        target_ip=target_printer.ip,
        port=DEFAULT_PORT
    )
    
    if success:
        # Record in database
        ActiveRedirect.create(
            source_printer_id=printer_id,
            source_ip=source_printer.ip,
            target_printer_id=target_printer_id,
            target_ip=target_printer.ip,
            protocol='raw',
            port=DEFAULT_PORT,
            enabled_by=current_user.username
        )
        
        # Audit log
        AuditLog.log(
            username=current_user.username,
            action="REDIRECT_ENABLED",
            source_printer_id=printer_id,
            source_ip=source_printer.ip,
            target_printer_id=target_printer_id,
            target_ip=target_printer.ip,
            details=f"Redirecting {source_printer.name} to {target_printer.name}",
            success=True
        )
        
        flash(f'Redirect enabled: {source_printer.name} → {target_printer.name}', 'success')
    else:
        AuditLog.log(
            username=current_user.username,
            action="REDIRECT_ENABLE_FAILED",
            source_printer_id=printer_id,
            source_ip=source_printer.ip,
            target_printer_id=target_printer_id,
            target_ip=target_printer.ip,
            success=False,
            error_message=message
        )
        flash(f'Failed to enable redirect: {message}', 'error')
    
    return redirect(url_for('main.printer_detail', printer_id=printer_id))


@main_bp.route('/redirect/<printer_id>/remove', methods=['POST'])
@login_required
def remove_redirect(printer_id):
    """Remove an active redirect."""
    registry = get_registry()
    network = get_network_manager()
    
    redirect_obj = ActiveRedirect.get_by_source_printer(printer_id)
    if not redirect_obj:
        flash('No active redirect found for this printer', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Disable the redirect
    success, message = network.disable_redirect(
        source_ip=redirect_obj.source_ip,
        target_ip=redirect_obj.target_ip,
        port=redirect_obj.port
    )
    
    source_printer = registry.get_by_id(printer_id)
    target_printer = registry.get_by_id(redirect_obj.target_printer_id)
    
    if success:
        # Remove from database and record history
        redirect_obj.delete(
            disabled_by=current_user.username,
            reason="Manual removal via web UI"
        )
        
        # Audit log
        AuditLog.log(
            username=current_user.username,
            action="REDIRECT_DISABLED",
            source_printer_id=printer_id,
            source_ip=redirect_obj.source_ip,
            target_printer_id=redirect_obj.target_printer_id,
            target_ip=redirect_obj.target_ip,
            details=f"Removed redirect from {source_printer.name if source_printer else printer_id}",
            success=True
        )
        
        flash('Redirect removed successfully', 'success')
    else:
        AuditLog.log(
            username=current_user.username,
            action="REDIRECT_DISABLE_FAILED",
            source_printer_id=printer_id,
            source_ip=redirect_obj.source_ip,
            target_printer_id=redirect_obj.target_printer_id,
            target_ip=redirect_obj.target_ip,
            success=False,
            error_message=message
        )
        flash(f'Failed to remove redirect: {message}', 'error')
    
    return redirect(url_for('main.dashboard'))


@main_bp.route('/audit')
@login_required
def audit_log():
    """View audit log."""
    logs = AuditLog.get_recent(limit=200)
    return render_template('audit_log.html', logs=logs)


@main_bp.route('/statistics')
@login_required
def statistics():
    """View redirect statistics."""
    from app.models import RedirectHistory
    
    stats = RedirectHistory.get_statistics()
    history = RedirectHistory.get_all(limit=50)
    
    return render_template('statistics.html', stats=stats, history=history)


# ============================================================================
# Printer Management Routes
# ============================================================================

@main_bp.route('/printers/manage')
@login_required
def manage_printers():
    """Printer management page."""
    registry = get_registry()
    printers = registry.get_all_statuses(use_cache=True)
    return render_template('manage_printers.html', printers=printers)


@main_bp.route('/printers/add', methods=['GET', 'POST'])
@login_required
def add_printer():
    """Add a new printer."""
    registry = get_registry()
    
    if request.method == 'POST':
        printer_id = request.form.get('printer_id', '').strip().lower().replace(' ', '-')
        name = request.form.get('name', '').strip()
        ip = request.form.get('ip', '').strip()
        location = request.form.get('location', '').strip()
        model = request.form.get('model', '').strip()
        department = request.form.get('department', '').strip()
        notes = request.form.get('notes', '').strip()
        
        # Validation
        errors = []
        if not printer_id:
            errors.append('Printer ID is required')
        elif registry.id_exists(printer_id):
            errors.append('Printer ID already exists')
        
        if not name:
            errors.append('Printer name is required')
        
        if not ip:
            errors.append('IP address is required')
        else:
            # Validate IP format
            import ipaddress
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append('Invalid IP address format')
            
            if registry.ip_exists(ip):
                errors.append('IP address already in use by another printer')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('printer_form.html', 
                                 mode='add',
                                 printer={'id': printer_id, 'name': name, 'ip': ip, 
                                         'location': location, 'model': model,
                                         'department': department, 'notes': notes})
        
        # Create printer
        printer = Printer(
            id=printer_id,
            name=name,
            ip=ip,
            protocols=['raw'],
            location=location,
            model=model,
            department=department,
            notes=notes
        )
        
        if registry.add_printer(printer):
            AuditLog.log(
                username=current_user.username,
                action="PRINTER_ADDED",
                source_printer_id=printer_id,
                source_ip=ip,
                details=f"Added printer: {name}",
                success=True
            )
            flash(f'Printer "{name}" added successfully', 'success')
            return redirect(url_for('main.manage_printers'))
        else:
            flash('Failed to add printer', 'error')
    
    return render_template('printer_form.html', mode='add', printer=None)


@main_bp.route('/printers/<printer_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_printer(printer_id):
    """Edit an existing printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        flash('Printer not found', 'error')
        return redirect(url_for('main.manage_printers'))
    
    # Check for active redirects
    has_redirect = ActiveRedirect.get_by_source_printer(printer_id) is not None
    is_target = ActiveRedirect.is_target_in_use(printer_id)
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        ip = request.form.get('ip', '').strip()
        location = request.form.get('location', '').strip()
        model = request.form.get('model', '').strip()
        department = request.form.get('department', '').strip()
        notes = request.form.get('notes', '').strip()
        
        # Validation
        errors = []
        if not name:
            errors.append('Printer name is required')
        
        if not ip:
            errors.append('IP address is required')
        else:
            import ipaddress
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append('Invalid IP address format')
            
            if registry.ip_exists(ip, exclude_id=printer_id):
                errors.append('IP address already in use by another printer')
        
        # Prevent IP change if redirect is active
        if (has_redirect or is_target) and ip != printer.ip:
            errors.append('Cannot change IP while redirect is active')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('printer_form.html',
                                 mode='edit',
                                 printer={'id': printer_id, 'name': name, 'ip': ip,
                                         'location': location, 'model': model,
                                         'department': department, 'notes': notes},
                                 has_redirect=has_redirect,
                                 is_target=is_target)
        
        old_ip = printer.ip
        
        # Update printer
        updated_printer = Printer(
            id=printer_id,
            name=name,
            ip=ip,
            protocols=printer.protocols,
            location=location,
            model=model,
            department=department,
            notes=notes
        )
        
        if registry.update_printer(updated_printer):
            AuditLog.log(
                username=current_user.username,
                action="PRINTER_UPDATED",
                source_printer_id=printer_id,
                source_ip=ip,
                details=f"Updated printer: {name}" + (f" (IP changed: {old_ip} -> {ip})" if old_ip != ip else ""),
                success=True
            )
            flash(f'Printer "{name}" updated successfully', 'success')
            return redirect(url_for('main.manage_printers'))
        else:
            flash('Failed to update printer', 'error')
    
    return render_template('printer_form.html',
                         mode='edit',
                         printer=printer.to_dict(),
                         has_redirect=has_redirect,
                         is_target=is_target)


@main_bp.route('/printers/<printer_id>/delete', methods=['POST'])
@login_required
def delete_printer(printer_id):
    """Delete a printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        flash('Printer not found', 'error')
        return redirect(url_for('main.manage_printers'))
    
    # Check for active redirects
    if ActiveRedirect.get_by_source_printer(printer_id):
        flash('Cannot delete printer with active redirect', 'error')
        return redirect(url_for('main.manage_printers'))
    
    if ActiveRedirect.is_target_in_use(printer_id):
        flash('Cannot delete printer that is a redirect target', 'error')
        return redirect(url_for('main.manage_printers'))
    
    printer_name = printer.name
    printer_ip = printer.ip
    
    if registry.delete_printer(printer_id):
        AuditLog.log(
            username=current_user.username,
            action="PRINTER_DELETED",
            source_printer_id=printer_id,
            source_ip=printer_ip,
            details=f"Deleted printer: {printer_name}",
            success=True
        )
        flash(f'Printer "{printer_name}" deleted successfully', 'success')
    else:
        flash('Failed to delete printer', 'error')
    
    return redirect(url_for('main.manage_printers'))


@main_bp.route('/printers/discover', methods=['GET', 'POST'])
@login_required
def discover_printers():
    """Discover printers on the network."""
    if request.method == 'POST':
        network = request.form.get('network', '').strip() or None
        single_ip = request.form.get('single_ip', '').strip() or None
        
        discovery = get_discovery()
        
        if single_ip:
            # Scan single IP
            discovered = discovery.scan_single_ip(single_ip)
        else:
            # Full network scan
            discovered = discovery.discover_all(network_cidr=network, timeout=15)
        
        # Filter out already registered printers
        registry = get_registry()
        existing_ips = {p.ip for p in registry.get_all()}
        new_printers = [p for p in discovered if p.ip not in existing_ips]
        
        return render_template('discover_printers.html',
                             discovered=new_printers,
                             existing_count=len(discovered) - len(new_printers),
                             network=network)
    
    return render_template('discover_printers.html', discovered=None)


@main_bp.route('/printers/import', methods=['POST'])
@login_required
def import_discovered_printer():
    """Import a discovered printer."""
    registry = get_registry()
    
    ip = request.form.get('ip', '').strip()
    name = request.form.get('name', '').strip() or f"Printer at {ip}"
    model = request.form.get('model', '').strip()
    location = request.form.get('location', '').strip()
    
    if not ip:
        flash('IP address is required', 'error')
        return redirect(url_for('main.discover_printers'))
    
    # Generate printer ID from name
    import re
    printer_id = re.sub(r'[^a-z0-9-]', '-', name.lower())
    printer_id = re.sub(r'-+', '-', printer_id).strip('-')
    
    # Ensure unique ID
    base_id = printer_id
    counter = 1
    while registry.id_exists(printer_id):
        printer_id = f"{base_id}-{counter}"
        counter += 1
    
    if registry.ip_exists(ip):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': False, 'message': 'Printer with this IP already exists'}, 400
        flash('Printer with this IP already exists', 'error')
        return redirect(url_for('main.discover_printers'))
    
    printer = Printer(
        id=printer_id,
        name=name,
        ip=ip,
        protocols=['raw'],
        location=location,
        model=model,
        department='',
        notes='Imported via auto-discovery'
    )
    
    if registry.add_printer(printer):
        AuditLog.log(
            username=current_user.username,
            action="PRINTER_IMPORTED",
            source_printer_id=printer_id,
            source_ip=ip,
            details=f"Imported discovered printer: {name}",
            success=True
        )
        # Return JSON for AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': True, 'message': f'Printer "{name}" imported successfully', 'ip': ip}
        flash(f'Printer "{name}" imported successfully', 'success')
    else:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': False, 'message': 'Failed to import printer'}, 400
        flash('Failed to import printer', 'error')
    
    return redirect(url_for('main.discover_printers'))


# ============================================================================
# Authentication Routes
# ============================================================================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    # Redirect to setup if no users exist yet
    from app.models import get_db_connection
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    conn.close()
    
    if user_count == 0:
        return redirect(url_for('auth.initial_setup'))
    
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr
        
        user, error = authenticate_user(username, password, client_ip)
        
        if user:
            login_user(user, remember=False)
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            flash(error, 'error')
    
    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout."""
    AuditLog.log(
        username=current_user.username,
        action="LOGOUT",
        success=True
    )
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/setup', methods=['GET', 'POST'])
def initial_setup():
    """Initial setup to create admin user."""
    from app.models import get_db_connection
    
    # Check if any users exist
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    conn.close()
    
    if user_count > 0:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username:
            flash('Username is required', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            is_valid, error = validate_password_strength(password)
            if not is_valid:
                flash(error, 'error')
            else:
                success, message = create_initial_admin(username, password)
                if success:
                    flash('Admin user created. Please log in.', 'success')
                    return redirect(url_for('auth.login'))
                else:
                    flash(message, 'error')
    
    return render_template('setup.html')


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change current user's password."""
    import bcrypt
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), 
                             current_user.password_hash.encode('utf-8')):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        
        # Check new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        # Validate password strength
        is_valid, error = validate_password_strength(new_password)
        if not is_valid:
            flash(error, 'error')
            return render_template('change_password.html')
        
        # Update password
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        current_user.update_password(new_hash)
        
        AuditLog.log(
            username=current_user.username,
            action="PASSWORD_CHANGED",
            details="User changed their password",
            success=True
        )
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('change_password.html')


# ============================================================================
# API Routes
# ============================================================================

@api_bp.route('/printers')
@login_required
def api_printers():
    """Get all printers with status."""
    registry = get_registry()
    return jsonify(registry.get_all_statuses())


@api_bp.route('/printers/<printer_id>')
@login_required
def api_printer(printer_id):
    """Get a specific printer with status."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    return jsonify(registry.get_printer_status(printer))


@api_bp.route('/printers/<printer_id>/check')
@login_required
def api_check_printer(printer_id):
    """Quick reachability check for a printer."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    icmp = registry.check_icmp_reachability(printer.ip)
    tcp = registry.check_tcp_reachability(printer.ip)
    
    return jsonify({
        'printer_id': printer_id,
        'ip': printer.ip,
        'icmp_reachable': icmp,
        'tcp_reachable': tcp,
        'is_online': icmp or tcp
    })


@api_bp.route('/redirects')
@login_required
def api_redirects():
    """Get all active redirects."""
    redirects = ActiveRedirect.get_all()
    return jsonify([{
        'id': r.id,
        'source_printer_id': r.source_printer_id,
        'source_ip': r.source_ip,
        'target_printer_id': r.target_printer_id,
        'target_ip': r.target_ip,
        'protocol': r.protocol,
        'port': r.port,
        'enabled_at': str(r.enabled_at),
        'enabled_by': r.enabled_by
    } for r in redirects])


@api_bp.route('/network/status')
@login_required
def api_network_status():
    """Get current network status (secondary IPs and NAT rules)."""
    network = get_network_manager()
    
    success, ips = network.get_secondary_ips()
    success2, nat_rules = network.get_nat_rules()
    
    return jsonify({
        'secondary_ips': ips if success else [],
        'nat_rules': nat_rules if success2 else 'Unable to retrieve'
    })


# ============================================================================
# Server-Sent Events (SSE) for Live Updates
# ============================================================================

@api_bp.route('/sse/printer/<printer_id>/queue')
@login_required
def sse_printer_queue(printer_id):
    """SSE endpoint for live print queue updates."""
    from flask import Response
    from app.print_queue import get_print_queue
    import json
    import time
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    def generate():
        while True:
            try:
                queue = get_print_queue(printer.ip)
                data = {
                    'queue': [job.to_dict() for job in queue],
                    'count': len(queue),
                    'timestamp': time.time()
                }
                yield f"data: {json.dumps(data)}\n\n"
                time.sleep(5)  # Update every 5 seconds
            except GeneratorExit:
                break
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(10)
    
    return Response(generate(), mimetype='text/event-stream',
                   headers={'Cache-Control': 'no-cache',
                           'Connection': 'keep-alive'})


# ============================================================================
# Async Data Loading Endpoints (for fast UI)
# ============================================================================

@api_bp.route('/printers/<printer_id>/stats')
@login_required
def api_printer_stats(printer_id):
    """Get SNMP stats for a printer (async loading)."""
    from app.printer_stats import get_printer_stats, get_toner_levels
    
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    stats = get_printer_stats(printer.ip)
    toner = get_toner_levels(printer.ip)
    
    return jsonify({
        'stats': stats.to_dict() if stats else None,
        'toner': toner
    })


@api_bp.route('/printers/<printer_id>/health')
@login_required
def api_printer_health(printer_id):
    """Get health status for a printer (from cache)."""
    from app.health_check import get_printer_health, get_printer_health_history
    
    health = get_printer_health(printer_id)
    history = get_printer_health_history(printer_id, limit=24)
    
    return jsonify({
        'current': health,
        'history': history
    })


@api_bp.route('/printers/<printer_id>/refresh')
@login_required
def api_printer_refresh(printer_id):
    """Force a live status check for a printer (bypasses cache)."""
    registry = get_registry()
    printer = registry.get_by_id(printer_id)
    
    if not printer:
        return jsonify({'error': 'Printer not found'}), 404
    
    # Do a live check and update cache
    from app.health_check import HealthChecker
    checker = HealthChecker()
    result = checker.check_printer(printer_id, printer.ip)
    checker.save_result(result)
    
    return jsonify({
        'printer_id': printer_id,
        'ip': printer.ip,
        'icmp_reachable': result.icmp_ok,
        'tcp_reachable': result.tcp_9100_ok,
        'is_online': result.is_online,
        'response_time_ms': result.response_time_ms
    })


@api_bp.route('/dashboard/status')
@login_required
def api_dashboard_status():
    """Get all printer statuses for dashboard (fast, from cache)."""
    registry = get_registry()
    return jsonify(registry.get_all_statuses(use_cache=True))


# ============================================================================
# Update API Routes
# ============================================================================

@api_bp.route('/update/status')
def api_update_status():
    """Get current update status. No login required so updating page can poll."""
    from app.updater import get_update_manager
    manager = get_update_manager()
    return jsonify(manager.get_state())


@api_bp.route('/update/check', methods=['POST'])
@login_required
def api_update_check():
    """Force an update check."""
    from app.updater import get_update_manager
    manager = get_update_manager()
    update_available, error = manager.check_for_updates(force=True)
    
    if error:
        return jsonify({
            'success': False,
            'error': error,
            'update_available': False
        })
    
    return jsonify({
        'success': True,
        'update_available': update_available,
        **manager.get_state()
    })


@api_bp.route('/update/start', methods=['POST'])
@login_required  
def api_update_start():
    """Start the update process."""
    from app.updater import get_update_manager
    from app.models import AuditLog
    
    manager = get_update_manager()
    success, message = manager.start_update()
    
    if success:
        # Log the update action
        AuditLog.log(
            username=current_user.username if current_user.is_authenticated else 'system',
            action='UPDATE_STARTED',
            details=f"Update to version {manager._state.available_version} initiated"
        )
    
    return jsonify({
        'success': success,
        'message': message
    })


@main_bp.route('/settings')
@login_required
def settings_page():
    """Settings page for application configuration."""
    from app.settings import get_settings_manager
    settings = get_settings_manager().get_all()
    return render_template('settings.html', settings=settings)


# ============================================================================
# Settings API Routes  
# ============================================================================

@api_bp.route('/settings/notifications/smtp', methods=['GET', 'POST'])
@login_required
def api_settings_smtp():
    """Get or update SMTP notification settings."""
    from app.settings import get_settings_manager
    manager = get_settings_manager()
    
    if request.method == 'GET':
        smtp_settings = manager.get('notifications.smtp', {})
        # Don't expose the password
        smtp_settings = dict(smtp_settings)
        smtp_settings['password'] = '********' if smtp_settings.get('password') else ''
        return jsonify({'success': True, 'settings': smtp_settings})
    
    # POST - update settings
    data = request.get_json() or {}
    
    try:
        current_smtp = manager.get('notifications.smtp', {})
        
        # Update fields that were provided
        for field in ['enabled', 'host', 'port', 'username', 'from_address', 'to_addresses', 'use_tls', 'use_ssl']:
            if field in data:
                current_smtp[field] = data[field]
        
        # Only update password if a new one was provided
        if data.get('password'):
            current_smtp['password'] = data['password']
        
        # Save the updated settings
        manager.set('notifications.smtp', current_smtp)
        
        # Log the change
        AuditLog.log(
            username=current_user.username,
            action='SETTINGS_UPDATED',
            details='SMTP notification settings updated'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/notifications/smtp/test', methods=['POST'])
@login_required
def api_settings_smtp_test():
    """Send a test email using current SMTP settings."""
    from app.notifications import get_notification_manager
    
    manager = get_notification_manager()
    success, message = manager.test_channel('smtp')
    
    if success:
        AuditLog.log(
            username=current_user.username,
            action='SMTP_TEST',
            details='Test email sent successfully'
        )
    
    return jsonify({
        'success': success,
        'message': message if success else None,
        'error': message if not success else None
    })

