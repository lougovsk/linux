# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import argparse
import logging
import os
import sys
import datetime
import pathlib

from test_runner import TestRunner
from selftest import SelftestStatus


def cli():
    parser = argparse.ArgumentParser(
        prog="KVM Selftests Runner",
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False
    )

    parser.add_argument("--test-files",
                        nargs="*",
                        default=[],
                        help="Test files to run. Provide the space separated test file paths")

    parser.add_argument("--test-dirs",
                        nargs="*",
                        default=[],
                        help="Run tests in the given directory and all of its sub directories. Provide the space separated paths to add multiple directories.")

    parser.add_argument("-e",
                        "--executable",
                        nargs='?',
                        default=".",
                        help="Finds the test executables in the given directory. Default is the current directory.")

    parser.add_argument("-t",
                        "--timeout",
                        default=120,
                        type=int,
                        help="Timeout, in seconds, before runner kills the running test. (Default: 120 seconds)")

    parser.add_argument("-o",
                        "--output",
                        nargs='?',
                        help="Dumps test runner output which includes each test execution result, their stdouts and stderrs hierarchically in the given directory.")

    parser.add_argument("--append-output-time",
                        action="store_true",
                        default=False,
                        help="Appends timestamp to the output directory.")

    parser.add_argument("-j",
                        "--jobs",
                        default=1,
                        type=int,
                        help="Maximum number of tests that can be run concurrently. (Default: 1)")

    return parser.parse_args()


def setup_logging(args):
    class TerminalColorFormatter(logging.Formatter):
        reset = "\033[0m"
        red_bold = "\033[31;1m"
        red = "\033[31;1m"
        green = "\033[32m"
        yellow = "\033[33m"
        blue = "\033[34m"

        COLORS = {
            SelftestStatus.PASSED: green,
            SelftestStatus.NO_RUN: blue,
            SelftestStatus.SKIPPED: yellow,
            SelftestStatus.FAILED: red_bold,
            SelftestStatus.TIMED_OUT: red
        }

        def __init__(self, fmt=None, datefmt=None):
            super().__init__(fmt, datefmt)

        def format(self, record):
            return (self.COLORS.get(record.levelno, "") +
                    super().format(record) + self.reset)

    logger = logging.getLogger("runner")
    logger.setLevel(logging.INFO)

    formatter_args = {
        "fmt": "%(asctime)s | %(message)s",
        "datefmt": "%H:%M:%S"
    }

    ch = logging.StreamHandler()
    ch_formatter = TerminalColorFormatter(**formatter_args)
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)

    if args.output != None:
        if (args.append_output_time):
            args.output += datetime.datetime.now().strftime(".%Y.%m.%d.%H.%M.%S")
        pathlib.Path(args.output).mkdir(parents=True, exist_ok=True)
        logging_file = os.path.join(args.output, "log")
        fh = logging.FileHandler(logging_file)
        fh_formatter = logging.Formatter(**formatter_args)
        fh.setFormatter(fh_formatter)
        logger.addHandler(fh)


def fetch_tests_from_dirs(scan_dirs):
    test_files = []
    for scan_dir in scan_dirs:
        for root, dirs, files in os.walk(scan_dir):
            for file in files:
                test_files.append(os.path.join(root, file))
    return test_files


def fetch_test_files(args):
    test_files = args.test_files
    test_files.extend(fetch_tests_from_dirs(args.test_dirs))
    # Remove duplicates
    test_files = list(dict.fromkeys(test_files))
    return test_files


def main():
    args = cli()
    setup_logging(args)
    test_files = fetch_test_files(args)
    return TestRunner(test_files, args).start()


if __name__ == "__main__":
    sys.exit(main())
