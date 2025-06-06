# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import command
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
    TIMED_OUT = 25

    def __str__(self):
        return str.__str__(self.name)


class Selftest:
    """
    Represents a single selftest.

    Extract the test execution command from test file and executes it.
    """

    def __init__(self, test_path, executable_dir, timeout, output_dir):
        test_command = pathlib.Path(test_path).read_text().strip()
        if not test_command:
            raise ValueError("Empty test command in " + test_path)

        test_command = os.path.join(executable_dir, test_command)
        self.exists = os.path.isfile(test_command.split(maxsplit=1)[0])
        self.test_path = test_path

        if output_dir is not None:
            output_dir = os.path.join(output_dir, test_path.lstrip("/"))
        self.command = command.Command(test_command, timeout, output_dir)

        self.status = SelftestStatus.NO_RUN
        self.stdout = ""
        self.stderr = ""

    def run(self):
        if not self.exists:
            self.stderr = "File doesn't exists."
            return

        try:
            ret, self.stdout, self.stderr = self.command.run()
            if ret == 0:
                self.status = SelftestStatus.PASSED
            elif ret == 4:
                self.status = SelftestStatus.SKIPPED
            else:
                self.status = SelftestStatus.FAILED
        except subprocess.TimeoutExpired as e:
            self.status = SelftestStatus.TIMED_OUT
