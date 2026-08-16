# -*- coding: utf-8 -*-
"""Задержка после неверных мастер-паролей.

Правило: три неверные попытки — пауза, дальше пауза растёт.

    попытки 1-3     без задержки
    после 3-й       5 секунд
    после 6-й       30 секунд
    после 9-й       2 минуты
    после 12-й      10 минут
    дальше          30 минут

Честно о том, чего это НЕ даёт. Файл хранилища у злоумышленника всё равно
можно перебирать чем угодно, минуя программу, — от перебора защищает KDF
(600 000 итераций PBKDF2 либо Argon2id), а не эта пауза. Здесь закрывается
другой случай: чужие руки на разблокированном компьютере, когда кто-то просто
подбирает пароль в открытом окне. Против такого пауза работает.

Состояние лежит на диске рядом с прочими служебными файлами хранилища.
Перезапуск программы паузу не снимает — иначе обходить её можно было бы
закрытием окна. Удалить файл руками, конечно, можно; это осознанный предел.

Отдельно учитывается перевод системных часов назад: сохраняется не только
момент окончания паузы, но и момент её начала. Если «сейчас» оказалось раньше
начала, часы двигали, и пауза отсчитывается заново.
"""

import json
import os
import time

ATTEMPTS_PER_STEP = 3
DELAY_LADDER = (5, 30, 120, 600, 1800)


class AttemptGuard:
    def __init__(self, state_path, attempts_per_step=ATTEMPTS_PER_STEP,
                 ladder=DELAY_LADDER):
        self.path = state_path
        self.attempts_per_step = attempts_per_step
        self.ladder = ladder

    # ------------------------------------------------------------------
    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
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
            pass          # не смогли записать — счётчик всё равно живёт в файле дальше

    def _delay_for(self, failures):
        step = failures // self.attempts_per_step
        if step <= 0:
            return 0
        return self.ladder[min(step - 1, len(self.ladder) - 1)]

    # ------------------------------------------------------------------
    def failures(self):
        n = self._load().get("failures", 0)
        return n if isinstance(n, int) and n >= 0 else 0

    def remaining(self, now=None):
        """Сколько секунд осталось ждать. 0 — можно пробовать."""
        now = time.time() if now is None else now
        data = self._load()
        until = data.get("locked_until")
        if not isinstance(until, (int, float)):
            return 0

        started = data.get("locked_at")
        if isinstance(started, (int, float)) and now < started - 1:
            # Часы перевели назад — так паузу не сбросить.
            delay = self._delay_for(self.failures())
            self._save({"failures": self.failures(),
                        "locked_at": now, "locked_until": now + delay})
            return delay

        left = until - now
        return int(left) + 1 if left > 0 else 0

    def is_locked(self, now=None):
        return self.remaining(now) > 0

    def attempts_left(self, now=None):
        """Сколько попыток осталось до следующей паузы."""
        if self.is_locked(now):
            return 0
        return max(0, self.attempts_per_step - (self.failures() % self.attempts_per_step))

    # ------------------------------------------------------------------
    def record_failure(self, now=None):
        """Отмечает неверный пароль. Возвращает секунды паузы (0 — паузы нет)."""
        now = time.time() if now is None else now
        failures = self.failures() + 1
        data = {"failures": failures}
        if failures % self.attempts_per_step == 0:
            delay = self._delay_for(failures)
            data["locked_at"] = now
            data["locked_until"] = now + delay
            self._save(data)
            return delay
        self._save(data)
        return 0

    def record_success(self):
        """Верный пароль — счётчик и пауза сбрасываются.

        Если файла и не было, создавать его незачем: раньше FileNotFoundError
        попадал в общий except OSError, и рядом с хранилищем появлялся
        vault.pmv.att после каждого успешного входа, даже когда ни одной
        неверной попытки не случалось.
        """
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass
        except OSError:
            self._save({"failures": 0})


def human_delay(seconds):
    if seconds < 60:
        return "%d с" % seconds
    if seconds < 3600:
        return "%d мин" % round(seconds / 60)
    return "%.1f ч" % (seconds / 3600)
