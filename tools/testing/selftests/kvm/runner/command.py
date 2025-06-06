# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import subprocess
import pathlib
import contextlib
import os


class Command:
    """Executes a command in shell.

    Returns the exit code, std output and std error of the command.
    """

    def __init__(self, command, timeout, output_dir):
        self.command = command
        self.timeout = timeout
        self.output_dir = output_dir

    def _run(self, output=None, error=None):
        run_args = {
            "universal_newlines": True,
            "shell": True,
            "timeout": self.timeout,
        }

        if output is None and error is None:
            run_args.update({"capture_output": True})
        else:
            run_args.update({"stdout": output, "stderr": error})

        proc = subprocess.run(self.command, **run_args)
        return proc.returncode, proc.stdout, proc.stderr

    def run(self):
        if self.output_dir is not None:
            pathlib.Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        output = None
        error = None
        with contextlib.ExitStack() as stack:
            if self.output_dir is not None:
                output_path = os.path.join(self.output_dir, "stdout")
                output = stack.enter_context(
                    open(output_path, encoding="utf-8", mode="w"))

                error_path = os.path.join(self.output_dir, "stderr")
                error = stack.enter_context(
                    open(error_path, encoding="utf-8", mode="w"))
            return self._run(output, error)
