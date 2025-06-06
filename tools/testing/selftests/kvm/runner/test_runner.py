# SPDX-License-Identifier: GPL-2.0
# Copyright 2025 Google LLC
#
# Author: vipinsh@google.com (Vipin Sharma)

import logging
from selftest import Selftest
from selftest import SelftestStatus

logger = logging.getLogger("runner")


class TestRunner:
    def __init__(self, test_files, args):
        self.tests = []

        for test_file in test_files:
            self.tests.append(Selftest(test_file, args.executable, args.timeout))

    def _log_result(self, test_result):
        logger.log(test_result.status,
                   f"[{test_result.status}] {test_result.test_path}")
        logger.info("************** STDOUT BEGIN **************")
        logger.info(test_result.stdout)
        logger.info("************** STDOUT END **************")
        logger.info("************** STDERR BEGIN **************")
        logger.info(test_result.stderr)
        logger.info("************** STDERR END **************")

    def start(self):
        ret = 0

        for test in self.tests:
            test.run()
            self._log_result(test)

            if (test.status not in [SelftestStatus.PASSED,
                                    SelftestStatus.NO_RUN,
                                    SelftestStatus.SKIPPED]):
                ret = 1
        return ret
