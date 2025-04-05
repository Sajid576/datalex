import logging
from apscheduler.schedulers.background import BackgroundScheduler
from ..routers.utils import transfer_suricata_logs

# Configure logging
logging.basicConfig(level=logging.INFO)

class SchedulerSingleton:
    _instance = None

    @staticmethod
    def get_instance():
        if SchedulerSingleton._instance is None:
            SchedulerSingleton._instance = BackgroundScheduler()
            SchedulerSingleton._instance.start()
        return SchedulerSingleton._instance

scheduler = SchedulerSingleton.get_instance()
job_id = 'transfer_suricata_logs_job'

def job_wrapper():
    logging.info("Starting transfer_suricata_logs job.")
    transfer_suricata_logs()
    logging.info("Finished transfer_suricata_logs job.")

if not scheduler.get_job(job_id):
    logging.info("-------------CRON JOB INITIATED-------")
    scheduler.add_job(job_wrapper, 'interval', minutes=1, id=job_id, max_instances=1)
else:
    logging.info("Job with ID '%s' already exists.", job_id)

def init_cron_jobs():
    # Your cron job setup code here
    pass