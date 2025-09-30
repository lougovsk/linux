# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import pathlib
import enum
import os
import subprocess

class SelftestStatus(enum.IntEnum):
    """
    Selftest Status. Integer values are just +1 to the logging.INFO level.
    """

    PASSED = 21
    NO_RUN = 22
    SKIPPED = 23
    FAILED = 24

    def __str__(self):
        return str.__str__(self.name)

class Selftest:
    """
    Represents a single selftest.

    Extract the test execution command from test file and executes it.
    """

    def __init__(self, test_path):
        test_command = pathlib.Path(test_path).read_text().strip()
        if not test_command:
            raise ValueError("Empty test command in " + test_path)

        test_command = os.path.join(".", test_command)
        self.exists = os.path.isfile(test_command.split(maxsplit=1)[0])
        self.test_path = test_path
        self.command = test_command
        self.status = SelftestStatus.NO_RUN
        self.stdout = ""
        self.stderr = ""

    def run(self):
        if not self.exists:
            self.stderr = "File doesn't exists."
            return

        run_args = {
            "universal_newlines": True,
            "shell": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE
        }
        proc = subprocess.run(self.command, **run_args)
        self.stdout = proc.stdout
        self.stderr = proc.stderr

        if proc.returncode == 0:
            self.status = SelftestStatus.PASSED
        elif proc.returncode == 4:
            self.status = SelftestStatus.SKIPPED
        else:
            self.status = SelftestStatus.FAILED
