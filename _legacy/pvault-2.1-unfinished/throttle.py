# -*- coding: utf-8 -*-
"""Задержка после неверных мастер-паролей.

Правило: три неверные попытки — пауза, затем снова три попытки, и так далее.

Чтобы задержка была настоящей, а не декоративной, состояние лежит на диске
рядом с прочими служебными файлами хранилища. Перезапуск программы паузу не
снимает — иначе обходить её можно было бы закрытием окна.

Отдельно учитывается перевод системных часов назад: сохраняется не только
момент окончания паузы, но и момент её начала. Если «сейчас» оказалось раньше
начала, часы явно двигали, и пауза отсчитывается заново.
"""

import json
import os
import time

MAX_ATTEMPTS = 3          # столько неверных попыток подряд до паузы
LOCK_SECONDS = 5          # длительность паузы


class AttemptGuard:
    def __init__(self, state_path, max_attempts=MAX_ATTEMPTS,
                 lock_seconds=LOCK_SECONDS):
        self.path = state_path
        self.max_attempts = max_attempts
        self.lock_seconds = lock_seconds

    # ------------------------------------------------------------------
    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {}
            return data
        except (OSError, ValueError):
            return {}

    def _save(self, data):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError:
            pass          # не смогли записать — но в памяти счётчик всё равно работает

    # ------------------------------------------------------------------
    def remaining(self, now=None):
        """Сколько секунд осталось ждать. 0 — можно пробовать."""
        now = time.time() if now is None else now
        data = self._load()
        until = data.get("locked_until")
        if not isinstance(until, (int, float)):
            return 0

        started = data.get("locked_at")
        if isinstance(started, (int, float)) and now < started - 1:
            # Часы перевели назад — не даём так сбросить паузу.
            self._save({"failures": data.get("failures", self.max_attempts),
                        "locked_at": now,
                        "locked_until": now + self.lock_seconds})
            return self.lock_seconds

        left = until - now
        return int(left) + 1 if left > 0 else 0

    def is_locked(self, now=None):
        return self.remaining(now) > 0

    def failures(self):
        data = self._load()
        n = data.get("failures", 0)
        return n if isinstance(n, int) and n >= 0 else 0

    def attempts_left(self, now=None):
        """Сколько попыток осталось до паузы."""
        if self.is_locked(now):
            return 0
        return max(0, self.max_attempts - self.failures())

    # ------------------------------------------------------------------
    def record_failure(self, now=None):
        """Отмечает неверный пароль. Возвращает секунды паузы (0 — паузы нет)."""
        now = time.time() if now is None else now
        failures = self.failures() + 1
        data = {"failures": failures}
        if failures % self.max_attempts == 0:
            data["locked_at"] = now
            data["locked_until"] = now + self.lock_seconds
            self._save(data)
            return self.lock_seconds
        self._save(data)
        return 0

    def record_success(self):
        """Верный пароль — счётчик и пауза сбрасываются."""
        try:
            os.remove(self.path)
        except OSError:
            self._save({"failures": 0})
