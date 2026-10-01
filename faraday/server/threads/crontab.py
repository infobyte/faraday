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
from uuid import uuid4

# Related third party imports
from croniter import croniter, CroniterBadCronError
import dateutil

# Local application imports
from faraday.server.extensions import socketio
from faraday.server.models import AgentsSchedule, SchedulerGeneric, db
from faraday.server.utils.agents import get_command_and_agent_execution
from faraday.server.utils.schedules import (
    ONCE_GRACE_PERIOD,
    SCHEDULE_TYPE_CRON,
    SCHEDULE_TYPE_ONCE,
    next_cron_run,
    to_aware,
)

logger = logging.getLogger(__name__)

# Wait before the next tick when one fails (e.g. the database is unreachable)
TICK_ERROR_BACKOFF_SECONDS = 60


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
        for job in list(self.jobs.values()):
            # One broken job must not stop the others, nor kill the thread
            try:
                ret = job.run_pending(**kwargs)
            except Exception:
                logger.exception(f"Scheduled job {job.schedule_id} failed")
                continue
            if ret:
                yield ret

    def stop(self):
        logger.info("Crontab Thread [Stopping...]")
        self.__event.set()

    def run(self):
        logger.info("Crontab Thread [Start]")
        while not self.__event.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("Crontab Thread tick failed")
                self.__event.wait(TICK_ERROR_BACKOFF_SECONDS)
        logger.info("Crontab Thread [Stop]")

    def tick(self):
        for value in self.run_pending(now=datetime.datetime.now(datetime.timezone.utc)):
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
                    try:
                        job = AgentsCronItem(schedule, app=self.app)
                        if job.valid:
                            logger.info(f'Loaded schedule for agent {schedule.executor.agent.id} '
                                        f'[{schedule.crontab or schedule.run_at}]')
                            self.jobs[schedule.id] = job
                    except Exception as e:
                        # A single bad schedule (e.g. unparseable crontab) must never crash
                        # the scheduler thread or app startup; log it and skip.
                        logger.error(f"Skipping schedule {schedule.id} with invalid crontab "
                                     f"[{schedule.crontab}]: {e}")

    def tick(self, sleep_time=60):
        self.refresh_schedule()
        FaradayCronTab.tick(self)
        time.sleep(sleep_time)


def _frequency_of(schedule):
    """Everything that decides when a schedule fires, as stored."""
    # getattr: not every scheduled item is a SchedulerGeneric row
    return (
        schedule.crontab,
        schedule.timezone,
        getattr(schedule, 'schedule_type', None) or SCHEDULE_TYPE_CRON,
        getattr(schedule, 'start_date', None),
        getattr(schedule, 'run_at', None),
    )


class CronItem:

    def __init__(self, schedule, app=None):
        self.app = app
        self.active = schedule.active
        self.schedule_id = schedule.id
        self._load_frequency(schedule)

    def _load_frequency(self, schedule):
        self._frequency = _frequency_of(schedule)
        self.crontab, timezone, self.schedule_type, self.start_date, self.run_at = self._frequency
        self.valid = True
        self.timezone = dateutil.tz.gettz(timezone)
        if not self.timezone:
            self.timezone = dateutil.tz.tzlocal()
        if self.schedule_type == SCHEDULE_TYPE_ONCE:
            # 'once' fires at run_at, it doesn't need an anchor
            self.last_run = None
            return
        try:
            self.last_run = self.schedule().get_prev(datetime.datetime)
        except CroniterBadCronError:
            logger.warning(f"Invalid crontab expression for schedule {schedule.id}: '{schedule.crontab}'. Skipping.")
            self.valid = False
            self.last_run = datetime.datetime.now()

    def update(self, schedule):
        if _frequency_of(schedule) != self._frequency:
            # Re-anchored at now, so a change never triggers runs that were due before it
            self._load_frequency(schedule)
            logger.info(f"Update Scheduler: {self.schedule_id} [{self.schedule_type}] "
                        f"crontab: [{self.crontab}] run_at: [{self.run_at}]")
        self.active = schedule.active

    def deactivate(self):
        """Turns the schedule off, in memory and in the database."""
        self.active = False
        if self.app is None:
            return
        with self.app.app_context():
            schedule = db.session.query(SchedulerGeneric).filter_by(id=self.schedule_id).first()
            if schedule:
                schedule.active = False
                db.session.commit()

    def _stored_last_run(self):
        if self.app is None:
            return None
        with self.app.app_context():
            schedule = db.session.query(SchedulerGeneric).filter_by(id=self.schedule_id).first()
            return schedule.last_run if schedule else None

    def _save_last_run(self, last_run):
        if self.app is None:
            return
        with self.app.app_context():
            schedule = db.session.query(SchedulerGeneric).filter_by(id=self.schedule_id).first()
            if schedule:
                schedule.last_run = last_run
                db.session.commit()

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
            now = datetime.datetime.now(tz=self.timezone)
        else:
            if now.tzinfo is None:
                logger.warning(f"Timezone not set for schedule {self.schedule_id}. This will be deprecated soon.")
                now = now.replace(tzinfo=self.timezone)
            else:
                now = now.astimezone(self.timezone)
        # 'once' compares against the exact time: run_at may have seconds
        exact_now = now
        now = now.replace(second=0, microsecond=0)
        if not self.valid:
            return False
        if self.active and self.schedule_type == SCHEDULE_TYPE_ONCE:
            return self._run_pending_once(exact_now)
        if self.active:
            next_time = self.schedule(self.last_run).get_next(datetime.datetime)
            if not next_time.tzinfo:
                logger.warning(f"Timezone not set for schedule {self.schedule_id}. This will be deprecated soon.")
                next_time = next_time.replace(tzinfo=self.timezone)
            start = to_aware(self.start_date, self.timezone)
            if start is not None and next_time < start:
                next_time = next_cron_run(self.crontab, self.timezone, next_time, start_date=self.start_date)
            logger.debug(f"Next run for {self.schedule_id}: {next_time}")
            logger.debug(f"Now: {now}")
            if next_time <= now:
                logger.info(f"Running Job {self.schedule_id} [{self.crontab}]")
                self.last_run = next_time
                return self.run()
            else:
                logger.debug(f"Job {self.schedule_id} will run in {next_time}")
        else:
            logger.warning(f"Try to run inactive job: {self.schedule_id}")
        return False

    def _run_pending_once(self, now):
        run_at = to_aware(self.run_at, self.timezone)
        if run_at is None or run_at > now:
            return False
        if now - run_at > ONCE_GRACE_PERIOD:
            logger.warning(f"Job {self.schedule_id} missed its run at {run_at} "
                           f"(more than {ONCE_GRACE_PERIOD} late), deactivating it")
            self.deactivate()
            return False
        # last_run is what marks it as fired (`active` stays the user's choice). It's saved
        # before running, so if the process dies mid-run it's not run again after a restart.
        previous_last_run = self._stored_last_run()
        if previous_last_run is not None and previous_last_run >= self.run_at:
            logger.info(f"Job {self.schedule_id} already ran at {previous_last_run}, deactivating it")
            self.deactivate()
            return False
        logger.info(f"Running Job {self.schedule_id} [once at {run_at}]")
        self._save_last_run(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
        try:
            result = self.run()
        except Exception:
            # Failed before dispatching: retried on the next ticks, within the grace period
            self._save_last_run(previous_last_run)
            raise
        if result:
            self.deactivate()
        else:
            # Not dispatched (e.g. agent offline): retried on the next ticks, within the grace period
            self._save_last_run(previous_last_run)
        return result


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

            schedule.last_run = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            db.session.add(schedule)
            logger.info(f"Agent {schedule.executor.agent.name} executed with executor {schedule.executor.name}")
            agent_executions = []
            commands = []
            workspaces_commands = []
            parameters_data = {
                "ignore_info": schedule.ignore_info,
                "resolve_hostname": schedule.resolve_hostname,
                "executor_data": {
                    "args": schedule.parameters,
                    "executor": schedule.executor.name
                },
                "workspaces_names": [workspace.name for workspace in schedule.workspaces]
            }
            run_uuid = uuid4()
            for workspace in schedule.workspaces:
                try:
                    command, agent_execution = get_command_and_agent_execution(executor=schedule.executor,
                                                                               workspace=workspace,
                                                                               user_id=schedule.creator.id,
                                                                               parameters=parameters_data,
                                                                               username=schedule.creator.username,
                                                                               triggered_by=schedule.description,
                                                                               run_uuid=run_uuid)
                except Exception as e:
                    logger.exception(f"Scheduler with id {self.schedule_id} could not run.", exc_info=e)
                    continue
                agent_executions.append(agent_execution)
                commands.append(command)
                db.session.add(command)
                db.session.commit()
                workspaces_commands.append({"workspace_name": workspace.name, "command_id": command.id})

            parameters_data["workspaces_commands"] = workspaces_commands
            parameters_data.pop("workspaces_names", None)
            for agent_execution in agent_executions:
                agent_execution.parameters_data = parameters_data
                db.session.add(agent_execution)

            db.session.commit()
            plugin_args = {
                "ignore_info": schedule.ignore_info,
                "resolve_hostname": schedule.resolve_hostname,
                "min_severity": schedule.min_severity,
                "max_severity": schedule.max_severity,
            }
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
                # Never dispatched: close the executions instead of leaving them as if they were pending
                for agent_execution in agent_executions:
                    agent_execution.running = False
                    agent_execution.successful = False
                    agent_execution.message = "The agent went offline before the run could be dispatched."
                    agent_execution.end_date = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                db.session.commit()
                return False
            socketio.emit("run", message, to=schedule.executor.agent.sid, namespace='/dispatcher')
            logger.info(f"Agent {schedule.executor.agent.name} executed with executor {schedule.executor.name}")
            return self.schedule_id
