# SPDX-License-Identifier: GPL-2.0
import queue
import concurrent.futures
import logging
import time
import selftest


class TestRunner:
    def __init__(self, test_files, output_dir, timeout, parallelism):
        self.parallelism = parallelism
        self.tests = []

        for test_file in test_files:
            self.tests.append(selftest.Selftest(
                test_file, output_dir, timeout))

    def _run(self, test):
        test.run()
        return test

    def start(self):

        status = {x: 0 for x in selftest.SelftestStatus}
        count = 0
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.parallelism) as executor:
            all_futures = []
            for test in self.tests:
                future = executor.submit(self._run, test)
                all_futures.append(future)

            for future in concurrent.futures.as_completed(all_futures):
                test = future.result()
                logging.info(f"[{test.status}] {test.test_path}")
                status[test.status] += 1
                count += 1

        logging.info(f"Tests ran: {count} tests")
        for result, count in status.items():
            logging.info(f"{result}: {count}")
