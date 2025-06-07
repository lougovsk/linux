# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import logging
import concurrent.futures

from selftest import Selftest
from selftest import SelftestStatus

logger = logging.getLogger("runner")


class TestRunner:
    def __init__(self, test_files, args):
        self.tests = []
        self.status = {x: 0 for x in SelftestStatus}
        self.output_dir = args.output
        self.jobs = args.jobs
        self.print_status = args.print_status
        self.print_stds = {
            SelftestStatus.PASSED: args.print_passed,
            SelftestStatus.FAILED: args.print_failed,
            SelftestStatus.SKIPPED: args.print_skipped,
            SelftestStatus.TIMED_OUT: args.print_timed_out,
            SelftestStatus.NO_RUN: args.print_no_runs
        }

        for test_file in test_files:
            self.tests.append(Selftest(test_file, args.executable,
                                       args.timeout, args.output))

    def _run_test(self, test):
        test.run()
        return test

    def _sticky_update(self):
        print(f"\r\033[1mTotal: {self.tests_ran}/{len(self.tests)}" \
                f"\033[32;1m Passed: {self.status[SelftestStatus.PASSED]}" \
                f"\033[31;1m Failed: {self.status[SelftestStatus.FAILED]}" \
                f"\033[33;1m Skipped: {self.status[SelftestStatus.SKIPPED]}"\
                f"\033[91;1m Timed Out: {self.status[SelftestStatus.TIMED_OUT]}"\
                f"\033[34;1m No Run: {self.status[SelftestStatus.NO_RUN]}\033[0m", end="\r")

    def _log_result(self, test_result):
        # Clear the status line
        print("\033[2K", end="\r")
        logger.log(test_result.status,
                   f"[{test_result.status}] {test_result.test_path}")
        if (self.output_dir is None and self.print_status is False
                and self.print_stds.get(test_result.status, True)):
            logger.info("************** STDOUT BEGIN **************")
            logger.info(test_result.stdout)
            logger.info("************** STDOUT END **************")
            logger.info("************** STDERR BEGIN **************")
            logger.info(test_result.stderr)
            logger.info("************** STDERR END **************")

        self.status[test_result.status] += 1
        # Sticky bottom line
        self._sticky_update()

    def start(self):
        ret = 0
        self.tests_ran = 0

        with concurrent.futures.ProcessPoolExecutor(max_workers=self.jobs) as executor:
            all_futures = []
            for test in self.tests:
                future = executor.submit(self._run_test, test)
                all_futures.append(future)

            for future in concurrent.futures.as_completed(all_futures):
                test_result = future.result()
                self.tests_ran += 1
                self._log_result(test_result)
                if (test_result.status not in [SelftestStatus.PASSED,
                                               SelftestStatus.NO_RUN,
                                               SelftestStatus.SKIPPED]):
                    ret = 1
        print("\n")
        return ret
