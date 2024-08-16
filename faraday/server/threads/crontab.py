"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import datetime
import logging
import threading
import time
from time import sleep

# Related third party imports
from croniter import croniter
import dateutil

# Local application imports
from faraday.server.extensions import socketio
from faraday.server.models import AgentsSchedule, db
from faraday.server.utils.agents import get_command_and_agent_execution

logger = logging.getLogger(__name__)


class FaradayCronTab(threading.Thread):

    def __init__(self, app=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.jobs = {}
        self.fixed_jobs = []
        self.__event = threading.Event()
        self.app = app

    def append(self, job):
        if job.valid:
            self.jobs[job.schedule_id] = job
        else:
            logger.info(f"Invalid job: {job}")

    def run_pending(self, **kwargs):
        logger.debug("Look for scheduled jobs..")
        for job in self.jobs.values():
            ret = job.run_pending(**kwargs)
            if ret:
                yield ret

    def stop(self):
        logger.info("Crontab Thread [Stopping...]")
        self.__event.set()

    def run(self):
        logger.info("Crontab Thread [Start]")
        while not self.__event.is_set():
            self.tick()
        logger.info("Crontab Thread [Stop]")

    def tick(self):
        for value in self.run_pending(now=datetime.datetime.now()):
            logger.debug(f'Running cron job {value}')
        sleep(0.1)


class CronTab(FaradayCronTab):
    def __init__(self, app=None, *args, **kwargs):
        super().__init__(name="CrontabThread", daemon=True, app=app, *args, **kwargs)
        self.refresh_schedule()

    def refresh_schedule(self):
        with self.app.app_context():
            # first we clean deleted jobs
            all_scheduled_jobs = db.session.query(AgentsSchedule).filter_by(active=True).all()
            all_scheduled_jobs_ids = {schedule.id for schedule in all_scheduled_jobs}

            for fixed_job in self.fixed_jobs:
                all_scheduled_jobs_ids.add(fixed_job)

            to_delete_job_ids = [job_id for job_id in self.jobs if job_id not in all_scheduled_jobs_ids]
            logger.debug(f"Active jobs: {all_scheduled_jobs_ids} - Delete jobs: {to_delete_job_ids}")
            for job_id in to_delete_job_ids:
                self.jobs.pop(job_id)

            for schedule in all_scheduled_jobs:
                if schedule.id in self.jobs:
                    # job already loaded
                    self.jobs[schedule.id].update(schedule)
                else:
                    logger.info(f'Loaded schedule for agent {schedule.executor.agent.id} [{schedule.crontab}]')
                    self.jobs[schedule.id] = AgentsCronItem(schedule, app=self.app)

    def tick(self, sleep_time=60):
        self.refresh_schedule()
        FaradayCronTab.tick(self)
        time.sleep(sleep_time)


class CronItem:

    def __init__(self, schedule, app=None):
        self.app = app
        self.valid = True
        self.active = schedule.active
        self.crontab = schedule.crontab
        self.last_run = self.schedule().get_prev(datetime.datetime)
        self.schedule_id = schedule.id
        self.timezone = dateutil.tz.gettz(schedule.timezone)
        if not self.timezone:
            self.timezone = dateutil.tz.tzlocal()

    def update(self, schedule):
        if self.crontab != schedule.crontab:
            self.crontab = schedule.crontab
            logger.info(f"Update Scheduler: {self.schedule_id} crontab: [{self.crontab}]")
        self.active = schedule.active

    def run(self):
        # TODO: Raise implementing
        return self.schedule_id

    def schedule(self, date_from=None):
        if not date_from:
            try:
                date_from = datetime.datetime.now(tz=self.timezone)
            except AttributeError:
                date_from = datetime.datetime.now(tz=dateutil.tz.tzlocal())
        return croniter(self.crontab, date_from, ret_type=datetime)

    def run_pending(self, now=None):
        if not now:
            now = datetime.datetime.now()
        now = now.replace(second=0, microsecond=0, tzinfo=self.timezone)
        if self.active:
            next_time = self.schedule(self.last_run).get_next(datetime.datetime)
            if not next_time.tzinfo:
                next_time = next_time.replace(tzinfo=self.timezone)
            if next_time <= now:
                logger.info(f"Running Job {self.schedule_id} [{self.crontab}]")
                self.last_run = next_time
                return self.run()
            else:
                logger.debug(f"Job {self.schedule_id} will run in {next_time}")
        else:
            logger.warning(f"Try to run inactive job: {self.schedule_id}")
        return False


class AgentsCronItem(CronItem):

    def run(self):
        with self.app.app_context():
            schedule: AgentsSchedule = db.session.query(AgentsSchedule).\
                filter_by(id=self.schedule_id).first()

            if not schedule:
                logger.warning(f"Schedule with ID {self.schedule_id} not found!, skipping agent execution")
                return False
            if schedule.executor.agent.is_offline or not schedule.executor.agent.active:
                logger.info(f'Agent is not online or paused. Agent status: {schedule.executor.agent.status},'
                            f' active flag: {schedule.executor.agent.active}')
                return False

            schedule.last_run = datetime.datetime.now()
            db.session.add(schedule)
            logger.info(f"Agent {schedule.executor.agent.name} executed with executor {schedule.executor.name}")
            agent_executions = []
            commands = []
            for workspace in schedule.workspaces:
                try:
                    command, agent_execution = get_command_and_agent_execution(executor=schedule.executor,
                                                                               workspace=workspace,
                                                                               user_id=schedule.creator.id,
                                                                               parameters=schedule.parameters,
                                                                               username=schedule.creator.username)
                except Exception as e:
                    logger.exception(f"Scheduler with id {self.schedule_id} could not run.", exc_info=e)
                    continue
                agent_executions.append(agent_execution)
                commands.append(command)
                db.session.add(agent_execution)
            db.session.commit()
            plugin_args = {
                "ignore_info": schedule.ignore_info,
                "resolve_hostname": schedule.resolve_hostname
            }
            if schedule.vuln_tag:
                plugin_args["vuln_tag"] = schedule.vuln_tag.split(",")
            if schedule.service_tag:
                plugin_args["service_tag"] = schedule.service_tag.split(",")
            if schedule.host_tag:
                plugin_args["host_tag"] = schedule.host_tag.split(",")
            message = {
                "execution_ids": [agent_execution.id for agent_execution in agent_executions],
                "agent_id": schedule.executor.agent.id,
                "workspaces": [workspace.name for workspace in schedule.workspaces],
                "action": 'RUN',
                "executor": schedule.executor.name,
                "args": schedule.parameters,
                "plugin_args": plugin_args
            }
            if schedule.executor.agent.is_offline:
                logger.warning("Agent %s with id %s is offline.",
                               schedule.executor.agent.name,
                               schedule.executor.agent.id)
                return self.schedule_id
            socketio.emit("run", message, to=schedule.executor.agent.sid, namespace='/dispatcher')
            logger.info(f"Agent {schedule.executor.agent.name} executed with executor {schedule.executor.name}")
            return self.schedule_id
