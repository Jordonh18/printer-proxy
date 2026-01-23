"""
Printer Redirect Scheduler

Applies and removes redirects based on printer schedules.
"""
import logging
import threading
import time
from datetime import datetime
from typing import Optional

from app.models import get_db_connection, ActiveRedirect
from app.services.printer_registry import get_registry
from app.services.network_manager import get_network_manager

logger = logging.getLogger(__name__)


class PrinterRedirectScheduler:
    def __init__(self, interval_seconds: int = 60):
        self.interval = interval_seconds
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Printer redirect scheduler started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Printer redirect scheduler stopped")

    def _run_loop(self):
        while self._running:
            try:
                self._tick()
            except Exception as exc:
                logger.error(f"Printer redirect scheduler error: {exc}")
            time.sleep(self.interval)

    def _tick(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            SELECT * FROM printer_redirect_schedules
            WHERE enabled = 1
        """)
        schedules = cursor.fetchall()

        for schedule in schedules:
            schedule_id = schedule['id']
            source_printer_id = schedule['source_printer_id']
            target_printer_id = schedule['target_printer_id']
            start_at = schedule['start_at']
            end_at = schedule['end_at']
            is_active = bool(schedule['is_active'])

            should_be_active = start_at <= now and (end_at is None or end_at >= now)

            if should_be_active and not is_active:
                self._activate_schedule(schedule_id, source_printer_id, target_printer_id)
                cursor.execute(
                    "UPDATE printer_redirect_schedules SET is_active = 1, last_activated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (schedule_id,)
                )
            elif not should_be_active and is_active:
                self._deactivate_schedule(schedule_id)
                cursor.execute(
                    "UPDATE printer_redirect_schedules SET is_active = 0, last_deactivated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (schedule_id,)
                )
            elif should_be_active and is_active:
                self._reconcile_schedule(schedule_id, source_printer_id, target_printer_id)

        conn.commit()
        conn.close()

    def _activate_schedule(self, schedule_id: int, source_printer_id: str, target_printer_id: str):
        registry = get_registry()
        network = get_network_manager()

        source_printer = registry.get_by_id(source_printer_id)
        target_printer = registry.get_by_id(target_printer_id)
        if not source_printer or not target_printer:
            logger.warning(f"Schedule {schedule_id}: printer(s) not found")
            return

        if ActiveRedirect.get_by_source_printer(source_printer_id):
            return

        if ActiveRedirect.is_target_in_use(target_printer_id):
            return

        success, _ = network.enable_redirect(
            source_ip=source_printer.ip,
            target_ip=target_printer.ip,
            port=9100
        )
        if success:
            redirect_obj = ActiveRedirect.create(
                source_printer_id=source_printer_id,
                source_ip=source_printer.ip,
                target_printer_id=target_printer_id,
                target_ip=target_printer.ip,
                protocol='raw',
                port=9100,
                enabled_by=f"schedule:{schedule_id}"
            )
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO printer_redirect_instances (schedule_id, redirect_id, source_printer_id) VALUES (?, ?, ?)",
                (schedule_id, redirect_obj.id, source_printer_id)
            )
            conn.commit()
            conn.close()

    def _deactivate_schedule(self, schedule_id: int):
        network = get_network_manager()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT redirect_id FROM printer_redirect_instances WHERE schedule_id = ?",
            (schedule_id,)
        )
        rows = cursor.fetchall()
        redirect_ids = [row['redirect_id'] for row in rows]

        for redirect_id in redirect_ids:
            redirect_obj = ActiveRedirect.get_by_id(redirect_id)
            if not redirect_obj:
                continue
            network.disable_redirect(
                source_ip=redirect_obj.source_ip,
                target_ip=redirect_obj.target_ip,
                port=redirect_obj.port
            )
            ActiveRedirect.delete(redirect_obj.id)

        cursor.execute("DELETE FROM printer_redirect_instances WHERE schedule_id = ?", (schedule_id,))
        conn.commit()
        conn.close()

    def _reconcile_schedule(self, schedule_id: int, source_printer_id: str, target_printer_id: str):
        existing_redirect = ActiveRedirect.get_by_source_printer(source_printer_id)
        if not existing_redirect:
            self._activate_schedule(schedule_id, source_printer_id, target_printer_id)
            return

        if existing_redirect.target_printer_id != target_printer_id:
            network = get_network_manager()
            network.disable_redirect(
                source_ip=existing_redirect.source_ip,
                target_ip=existing_redirect.target_ip,
                port=existing_redirect.port
            )
            ActiveRedirect.delete(existing_redirect.id)
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM printer_redirect_instances WHERE schedule_id = ?",
                (schedule_id,)
            )
            conn.commit()
            conn.close()
            self._activate_schedule(schedule_id, source_printer_id, target_printer_id)


_scheduler: Optional[PrinterRedirectScheduler] = None


def init_printer_redirect_scheduler(start_background: bool = True):
    global _scheduler
    if _scheduler is None:
        _scheduler = PrinterRedirectScheduler()
    if start_background:
        _scheduler.start()


def stop_printer_redirect_scheduler():
    if _scheduler:
        _scheduler.stop()
