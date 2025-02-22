# SPDX-License-Identifier: GPL-2.0
import subprocess
import command
import pathlib
import enum
import os
import logging


class SelftestStatus(str, enum.Enum):
    PASSED = "Passed"
    FAILED = "Failed"
    SKIPPED = "Skipped"
    TIMED_OUT = "Timed out"
    NO_RUN = "No run"

    def __str__(self):
        return str.__str__(self)


class Selftest:
    """A single test.

    A test which can be run on its own.
    """

    def __init__(self, test_path, output_dir=None, timeout=None,):
        test_command = pathlib.Path(test_path).read_text().strip()
        if not test_command:
            raise ValueError("Empty test command in " + test_path)

        if output_dir is not None:
            output_dir = os.path.join(output_dir, test_path)
        self.test_path = test_path
        self.command = command.Command(test_command, timeout, output_dir)
        self.status = SelftestStatus.NO_RUN

    def run(self):
        try:
            ret = self.command.run()
            if ret == 0:
                self.status = SelftestStatus.PASSED
            elif ret == 4:
                self.status = SelftestStatus.SKIPPED
            else:
                self.status = SelftestStatus.FAILED
        except subprocess.TimeoutExpired as e:
            # logging.error(type(e).__name__ + str(e))
            self.status = SelftestStatus.TIMED_OUT
