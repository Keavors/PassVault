# -*- coding: utf-8 -*-
"""Задержка после неверных мастер-паролей.

Тесты блокировки сети переехали отсюда в test_netblock.py: они здесь никогда
не были к месту и просто нашли себе свободный файл.
"""

import os
import shutil
import tempfile
import unittest

from pvault.throttle import AttemptGuard


class ThrottleTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pvthr-")
        self.guard = AttemptGuard(os.path.join(self.dir, "attempts.json"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_three_attempts_then_pause(self):
        now = 1000.0
        self.assertEqual(self.guard.record_failure(now), 0)
        self.assertEqual(self.guard.record_failure(now), 0)
        self.assertEqual(self.guard.record_failure(now), 5)
        self.assertTrue(self.guard.is_locked(now))
        self.assertEqual(self.guard.attempts_left(now), 0)

    def test_pause_expires(self):
        now = 1000.0
        for _ in range(3):
            self.guard.record_failure(now)
        self.assertFalse(self.guard.is_locked(now + 6))
        self.assertEqual(self.guard.attempts_left(now + 6), 3)

    def test_delay_grows(self):
        now = 1000.0
        delays = []
        for i in range(1, 16):
            d = self.guard.record_failure(now)
            if d:
                delays.append(d)
                now += d + 1
        self.assertEqual(delays[:4], [5, 30, 120, 600])

    def test_survives_restart(self):
        """Перезапуск программы не должен снимать паузу."""
        now = 1000.0
        for _ in range(3):
            self.guard.record_failure(now)
        again = AttemptGuard(self.guard.path)
        self.assertTrue(again.is_locked(now))

    def test_clock_rollback_does_not_clear_pause(self):
        now = 1000.0
        for _ in range(3):
            self.guard.record_failure(now)
        self.assertTrue(self.guard.is_locked(now - 10_000))

    def test_success_resets(self):
        now = 1000.0
        for _ in range(3):
            self.guard.record_failure(now)
        self.guard.record_success()
        self.assertEqual(self.guard.failures(), 0)
        self.assertFalse(self.guard.is_locked(now))

    def test_broken_state_file_is_ignored(self):
        with open(self.guard.path, "w", encoding="utf-8") as f:
            f.write("не json")
        self.assertEqual(self.guard.failures(), 0)
        self.assertFalse(self.guard.is_locked())

    def test_success_without_failures_leaves_no_file(self):
        """Успешный вход не должен плодить служебный файл на пустом месте.

        FileNotFoundError попадал в общий except OSError, и рядом с хранилищем
        появлялся vault.pmv.att после каждого открытия — даже когда ни одной
        неверной попытки не было.
        """
        self.assertFalse(os.path.exists(self.guard.path))
        self.guard.record_success()
        self.assertFalse(os.path.exists(self.guard.path),
                         "счётчика не было — создавать его незачем")

    def test_success_removes_existing_file(self):
        self.guard.record_failure(1000.0)
        self.assertTrue(os.path.exists(self.guard.path))
        self.guard.record_success()
        self.assertFalse(os.path.exists(self.guard.path))
