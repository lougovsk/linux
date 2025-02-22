# SPDX-License-Identifier: GPL-2.0
import pathlib
import argparse
import platform
import logging
import os
import enum
import test_runner


def cli():
    parser = argparse.ArgumentParser(
        prog="KVM Selftests Runner",
        description="Run KVM selftests with different configurations",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--tests",
                        nargs="*",
                        default=[],
                        help="Test cases to run. Provide the space separated test case file paths")

    parser.add_argument("--test_dirs",
                        nargs="*",
                        default=[],
                        help="Run tests in the given directory and all its sub directories. Provide the space separated paths to add multiple directories.")

    parser.add_argument("-j",
                        "--jobs",
                        default=1,
                        type=int,
                        help="Number of parallel test runners to start")

    parser.add_argument("-t",
                        "--timeout",
                        default=120,
                        type=int,
                        help="How long to wait for a single test to finish before killing it")

    parser.add_argument("-o",
                        "--output",
                        nargs='?',
                        help="Output directory for test results.")

    return parser.parse_args()


def setup_logging(args):
    output = args.output
    if output == None:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s | %(process)d | %(levelname)8s | %(message)s")
    else:
        logging_file = os.path.join(output, "log")
        pathlib.Path(output).mkdir(parents=True, exist_ok=True)
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s | %(process)d | %(levelname)8s | %(message)s",
                            handlers=[
                                logging.FileHandler(logging_file, mode='w'),
                                logging.StreamHandler()
                            ])


def fetch_tests_from_dirs(scan_dirs, exclude_dirs):
    test_files = []
    for scan_dir in scan_dirs:
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [dir for dir in dirs if dir not in exclude_dirs]
            for file in files:
                test_files.append(os.path.join(root, file))
    return test_files


def fetch_test_files(args):
    exclude_dirs = ["aarch64", "x86_64", "riscv", "s390x"]
    # Don't exclude tests of the current platform
    exclude_dirs.remove(platform.machine())

    test_files = args.tests
    test_files.extend(fetch_tests_from_dirs(args.test_dirs, exclude_dirs))
    # Remove duplicates
    test_files = list(dict.fromkeys(test_files))
    return test_files


def main():
    args = cli()
    setup_logging(args)
    test_files = fetch_test_files(args)
    tr = test_runner.TestRunner(
        test_files, args.output, args.timeout, args.jobs)
    tr.start()


if __name__ == "__main__":
    main()
