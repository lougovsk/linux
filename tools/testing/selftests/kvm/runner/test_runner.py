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
        self.output_dir = args.output
        self.jobs = args.jobs

        for test_file in test_files:
            self.tests.append(Selftest(test_file, args.executable,
                                       args.timeout, args.output))

    def _run_test(self, test):
        test.run()
        return test

    def _log_result(self, test_result):
        logger.log(test_result.status,
                   f"[{test_result.status}] {test_result.test_path}")
        if (self.output_dir is None):
            logger.info("************** STDOUT BEGIN **************")
            logger.info(test_result.stdout)
            logger.info("************** STDOUT END **************")
            logger.info("************** STDERR BEGIN **************")
            logger.info(test_result.stderr)
            logger.info("************** STDERR END **************")

    def start(self):
        ret = 0

        with concurrent.futures.ProcessPoolExecutor(max_workers=self.jobs) as executor:
            all_futures = []
            for test in self.tests:
                future = executor.submit(self._run_test, test)
                all_futures.append(future)

            for future in concurrent.futures.as_completed(all_futures):
                test_result = future.result()
                self._log_result(test_result)
                if (test_result.status not in [SelftestStatus.PASSED,
                                               SelftestStatus.NO_RUN,
                                               SelftestStatus.SKIPPED]):
                    ret = 1
        return ret
