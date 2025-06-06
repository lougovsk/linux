# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import argparse
import logging
import os
import sys

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

    ch = logging.StreamHandler()
    ch_formatter = TerminalColorFormatter(fmt="%(asctime)s | %(message)s",
                                          datefmt="%H:%M:%S")
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)


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
