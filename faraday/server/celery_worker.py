#!/usr/bin/env python
import argparse
import os

import faraday.server.config
from faraday.server.app import celery, get_app  # noqa
from faraday.server.utils.celery import require_celery_enabled
from faraday.server.utils.logger import setup_celery_logging


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--queue', type=str, help='Celery queue', default='celery', required=False)
    parser.add_argument('--concurrency', type=str, help='Celery concurrency', required=False)
    parser.add_argument('--loglevel', type=str, help='Celery log level', required=False)
    args = parser.parse_args()

    require_celery_enabled('workers')
    get_app()
    print("Starting celery %s", args)

    queue = 'celery'
    if args.queue:
        queue = args.queue

    concurrency = 1
    if os.cpu_count():
        concurrency = os.cpu_count() - 1

    if args.concurrency:
        concurrency = args.concurrency

    loglevel = 'WARNING'
    if faraday.server.config.faraday_server.debug:
        loglevel = 'DEBUG'
    else:
        if args.loglevel:
            loglevel = args.loglevel

    setup_celery_logging()
    celery.worker_main(
        [
            'worker',
            '-Q',
            queue,
            '--concurrency',
            concurrency,
            '--loglevel',
            loglevel,
        ]
    )


if __name__ == '__main__':
    main()
