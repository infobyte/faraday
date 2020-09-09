import sys
import shutil
import tempfile
from pathlib import Path

from tqdm import tqdm
from colorama import init
from colorama import Fore, Style

import distro

from faraday.server.config import CONST_FARADAY_HOME_PATH

from faraday.server.commands import status_check

init()


def init_config():
    # Creates the directory where all the info will go to
    return Path(tempfile.mkdtemp())


def get_status_check(path: Path):
    # Executes status check from with-in the code and uses stdout to save
    # info to file
    # stdout was the only way to get this information without doing a big
    # refactor
    original_stdout = sys.stdout

    sys.stdout = (path / 'status_check.txt').open('wt')
    status_check.full_status_check()

    sys.stdout.close()
    sys.stdout = original_stdout


def get_logs(path: Path):
    # Copies the logs using the logs path saved on constants
    orig_path = CONST_FARADAY_HOME_PATH / 'logs'
    dst_path = path / 'logs'
    shutil.copytree(str(orig_path), str(dst_path),  # I would do this in other
                    ignore=shutil.ignore_patterns('access*.*'))  # way. by Eric


def make_zip(path: Path):
    # Makes a zip file of the new folder with all the information obtained
    # inside
    shutil.make_archive('faraday_support', 'zip', str(path))


def end_config(path: Path):
    # Deletes recursively the directory created on the init_config
    shutil.rmtree(path)


def revise_os(path: Path):
    with (path / 'os_distro.txt').open('wt') as os_file:
        os_file.write(f"{distro.linux_distribution()}")


def all_for_support():
    with tqdm(total=6) as pbar:
        path = init_config()
        get_status_check(path)
        pbar.update(1)
        get_logs(path)
        pbar.update(1)
        pbar.update(1)
        revise_os(path)
        pbar.update(1)
        make_zip(path)
        pbar.update(1)
        end_config(path)
        pbar.update(1)

    print('[{green}+{white}] Process Completed. A {bright}faraday_support.zip{normal} was generated'
            .format(green=Fore.GREEN, white=Fore.WHITE, bright=Style.BRIGHT, normal=Style.NORMAL))
