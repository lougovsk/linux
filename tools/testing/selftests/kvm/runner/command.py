# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import subprocess


class Command:
    """Executes a command in shell.

    Returns the exit code, std output and std error of the command.
    """

    def __init__(self, command):
        self.command = command

    def run(self):
        run_args = {
            "universal_newlines": True,
            "shell": True,
            "capture_output": True,
        }

        proc = subprocess.run(self.command, **run_args)
        return proc.returncode, proc.stdout, proc.stderr
