#!/usr/bin/python3 -EsSB
"""Exercise pipe cleanup with real child processes and retained tracebacks."""

from contextlib import ExitStack
import subprocess
import sys
import unittest
from unittest.mock import patch

import openbao_test_harness as subject


class BoundedProcessTests(unittest.TestCase):
    def exercise(self, code, *, maximum=1024, timeout=5, failure=None, setup=None):
        processes = []
        retained = None
        original = subprocess.Popen

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        with ExitStack() as stack:
            stack.enter_context(patch.object(subject.subprocess, "Popen", side_effect=spawn))
            if setup == "nonblocking":
                stack.enter_context(patch.object(subject.os, "set_blocking", side_effect=OSError("fixture setup")))
            if setup == "selector":
                stack.enter_context(patch.object(subject.selectors, "DefaultSelector", side_effect=OSError("fixture setup")))
            if setup == "register":
                stack.enter_context(patch.object(subject.selectors.DefaultSelector, "register", side_effect=OSError("fixture setup")))
            if setup == "interrupt":
                stack.enter_context(patch.object(subject.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt))
            try:
                result = subject.run_bounded([sys.executable, "-E", "-s", "-S", "-c", code],
                    maximum, timeout=timeout, environment={"PATH": "/usr/bin:/bin"})
            except BaseException as error:
                if failure is None:
                    raise
                self.assertIsInstance(error, failure)
                retained = error
            else:
                self.assertIsNone(failure)
                self.assertEqual(result, b"ok")
        self.assertEqual(len(processes), 1)
        process = processes[0]
        # Keep both the process and exception/traceback alive: GC must not be
        # responsible for closing the pipe, even on an exceptional return.
        self.assertTrue(process.stdout.closed)
        self.assertIsNotNone(process.poll())
        if failure:
            self.assertIsNotNone(retained.__traceback__)

    def test_success_and_nonzero_exit_close_pipe(self):
        self.exercise("import sys; sys.stdout.write('ok')")
        self.exercise("import sys; sys.exit(7)", failure=subject.HarnessError)

    def test_timeout_and_output_overflow_close_pipe_and_reap_child(self):
        self.exercise("import time; time.sleep(30)", timeout=0.05, failure=subject.HarnessError)
        self.exercise("import sys; sys.stdout.write('x' * 4096)", maximum=8, failure=subject.HarnessError)

    def test_setup_failures_and_interrupt_close_pipe_and_reap_child(self):
        for setup in ("nonblocking", "selector", "register", "interrupt"):
            with self.subTest(setup=setup):
                self.exercise("import time; time.sleep(30)", setup=setup,
                    failure=KeyboardInterrupt if setup == "interrupt" else OSError)


if __name__ == "__main__":
    unittest.main()
