"""
Workflow Scheduler Service
Manages scheduled workflow triggers using APScheduler.
"""

import logging
from typing import Optional
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
from app.models import get_db_connection
import json

logger = logging.getLogger(__name__)

class WorkflowScheduler:
    """Manages scheduled workflow executions."""
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
        logger.info("Workflow scheduler started")
    
    def schedule_workflow(self, workflow_id: str, schedule_config: dict) -> bool:
        """
        Schedule a workflow based on configuration.
        
        Args:
            workflow_id: ID of the workflow to schedule
            schedule_config: Schedule configuration from trigger.schedule node
                {
                    'schedule_type': 'cron' | 'interval' | 'once',
                    'cron': '0 9 * * *',  # For cron type
                    'interval': 60,  # For interval type (seconds)
                    'interval_unit': 'seconds' | 'minutes' | 'hours' | 'days',
                    'start_date': '2026-01-21T09:00:00'  # For once type
                }
        
        Returns:
            bool: True if scheduled successfully
        """
        try:
            job_id = f"workflow_{workflow_id}"
            
            # Remove existing job if present
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
            
            schedule_type = schedule_config.get('schedule_type', 'cron')
            
            if schedule_type == 'cron':
                # Cron-style scheduling
                cron_expr = schedule_config.get('cron', '0 0 * * *')  # Default: daily at midnight
                trigger = CronTrigger.from_crontab(cron_expr)
                
            elif schedule_type == 'interval':
                # Interval-based scheduling
                interval = int(schedule_config.get('interval', 60))
                unit = schedule_config.get('interval_unit', 'seconds')
                
                kwargs = {unit: interval}
                trigger = IntervalTrigger(**kwargs)
                
            elif schedule_type == 'once':
                # One-time execution
                start_date = schedule_config.get('start_date')
                if not start_date:
                    logger.error(f"No start_date provided for once schedule on workflow {workflow_id}")
                    return False
                
                trigger = DateTrigger(run_date=start_date)
                
            else:
                logger.error(f"Unknown schedule type: {schedule_type}")
                return False
            
            # Add the job
            self.scheduler.add_job(
                func=self._execute_scheduled_workflow,
                trigger=trigger,
                args=[workflow_id],
                id=job_id,
                name=f"Workflow {workflow_id}",
                replace_existing=True
            )
            
            logger.info(f"Scheduled workflow {workflow_id} with {schedule_type} trigger")
            return True
            
        except Exception as e:
            logger.error(f"Error scheduling workflow {workflow_id}: {e}", exc_info=True)
            return False
    
    def unschedule_workflow(self, workflow_id: str) -> bool:
        """Remove a scheduled workflow."""
        try:
            job_id = f"workflow_{workflow_id}"
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
                logger.info(f"Unscheduled workflow {workflow_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error unscheduling workflow {workflow_id}: {e}")
            return False
    
    def _execute_scheduled_workflow(self, workflow_id: str):
        """Execute a scheduled workflow."""
        try:
            from app.workflow_engine import get_workflow_engine
            
            logger.info(f"Executing scheduled workflow {workflow_id}")
            
            engine = get_workflow_engine()
            context = {
                'trigger': 'schedule',
                'workflow_id': workflow_id,
                'timestamp': datetime.now().isoformat(),
                'scheduled': True
            }
            
            engine.execute_workflow(workflow_id, context)
            
        except Exception as e:
            logger.error(f"Error executing scheduled workflow {workflow_id}: {e}", exc_info=True)
    
    def reload_all_schedules(self):
        """Load all scheduled workflows from database."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Simple schema with JSON nodes
            cursor.execute("SELECT id, nodes FROM workflows WHERE enabled = 1")
            rows = cursor.fetchall()
            conn.close()
            
            scheduled_count = 0
            
            for row in rows:
                workflow_id, nodes_json = row
                nodes = json.loads(nodes_json) if nodes_json else []
                
                # Find schedule trigger node
                schedule_node = next(
                    (n for n in nodes if n['type'] == 'trigger.schedule'),
                    None
                )
                
                if schedule_node:
                    schedule_config = schedule_node.get('properties', {})
                    if self.schedule_workflow(workflow_id, schedule_config):
                        scheduled_count += 1
            
            logger.info(f"Loaded {scheduled_count} scheduled workflows")
            
        except Exception as e:
            logger.error(f"Error reloading schedules: {e}", exc_info=True)
    
    def shutdown(self):
        """Shutdown the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Workflow scheduler stopped")


# Global scheduler instance
_workflow_scheduler: Optional[WorkflowScheduler] = None

def get_workflow_scheduler() -> WorkflowScheduler:
    """Get the global workflow scheduler instance."""
    global _workflow_scheduler
    if _workflow_scheduler is None:
        _workflow_scheduler = WorkflowScheduler()
    return _workflow_scheduler

def reload_workflow_schedules():
    """Reload all workflow schedules from database."""
    scheduler = get_workflow_scheduler()
    scheduler.reload_all_schedules()
