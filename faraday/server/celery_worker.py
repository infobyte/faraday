#!/usr/bin/env python
import argparse
import os

import faraday.server.config
from faraday.server.app import celery, get_app  # noqa
from faraday.server.config import CELERY_LOG_FILE

application = get_app()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--queue', type=str, help='Celery queue', default='celery', required=False)
    parser.add_argument('--concurrency', type=str, help='Celery concurrency', required=False)
    parser.add_argument('--loglevel', type=str, help='Celery log level', required=False)
    args = parser.parse_args()
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

    celery.worker_main(
        [
            'worker',
            '-Q',
            queue,
            '--concurrency',
            concurrency,
            '--loglevel',
            loglevel,
            '-f',
            CELERY_LOG_FILE
        ]
    )


if __name__ == '__main__':
    main()
