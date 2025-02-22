# SPDX-License-Identifier: GPL-2.0
import contextlib
import subprocess
import os
import pathlib


class Command:
    """Executes a command

    Just execute a command. Dump output to the directory if provided.

    Returns the exit code of the command.
    """

    def __init__(self, command, timeout=None, output_dir=None):
        self.command = command
        self.timeout = timeout
        self.output_dir = output_dir

    def __run(self, output=None, error=None):
        proc = subprocess.run(self.command, stdout=output,
                              stderr=error, universal_newlines=True,
                              shell=True, timeout=self.timeout)
        return proc.returncode

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
            return self.__run(output, error)
