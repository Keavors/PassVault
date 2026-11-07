# -*- coding: utf-8 -*-
"""Быстрая проверка собранной программы: `GemSwap.exe --selfcheck`.

Автотесты гоняются на исходниках, а пользователю в руки попадает exe. Между
ними есть зазор: сборщик может не положить внутрь нативную библиотеку, и тогда
Argon2id молча не заработает — а узнается это в тот момент, когда человек
попробует открыть своё хранилище.

Проверка идёт по настоящему пути: зашифровать, записать на диск через тот же
атомарный слой, прочитать обратно, сверить.
"""

import os
import shutil
import tempfile

from . import backup, crypto, storage
from .generator import DEFAULT_GEN, generate_password
from .merge import INCOMING, apply_merge, plan_merge
from .model import normalize_data, now_iso
from .session import DEFAULT_APP_SETTINGS

SAMPLE = {
    "version": 1,
    "entries": [{"id": "a1", "title": "Проверка ёЁ", "login": "u",
                 "password": "пАроль Йц1!", "url": "", "notes": "заметка",
                 "created": "2026-01-01T00:00:00Z",
                 "modified": "2026-01-01T00:00:00Z"}],
    "settings": {"generator": dict(DEFAULT_GEN), "app": dict(DEFAULT_APP_SETTINGS)},
}

PW = "проверочная мастер-фраза"


def _roundtrip(params, tmpdir, name):
    blob, key, p = crypto.create_encrypted(SAMPLE, PW, params)
    path = os.path.join(tmpdir, name)
    storage.atomic_write(path, blob, verify_key=key,
                         prev_path=os.path.join(tmpdir, "side", "previous.pmv"))
    with open(path, "rb") as f:
        back, _k, back_params = crypto.decrypt_vault(f.read(), PW)
    if back != SAMPLE:
        raise AssertionError("содержимое не совпало после записи и чтения")
    if back_params.kdf_id != params.kdf_id:
        raise AssertionError("формат контейнера изменился при записи")
    return p


def _workdir():
    r"""Куда писать проверочные файлы.

    Сначала — рядом с программой. Самопроверка шифрует настоящим шифром и
    пишет настоящие хранилища; в профиле пользователя на системном диске им
    не место, а вся программа построена на правиле «ничего в %APPDATA%».
    Если рядом с программой писать нельзя (папка только на чтение), деваться
    некуда — берём системную временную.
    """
    from . import paths
    here = os.path.join(paths.app_dir(), ".selfcheck")
    try:
        os.makedirs(here, exist_ok=True)
        return tempfile.mkdtemp(prefix="pvcheck-", dir=here)
    except OSError:
        return tempfile.mkdtemp(prefix="pvcheck-")


def run():
    """Возвращает (успех, отчёт)."""
    lines = []
    tmpdir = _workdir()
    try:
        # Формат записи ровно один, и если он не работает — программа не
        # работает. Раньше отсутствие argon2-cffi было лишь пометкой
        # «НЕДОСТУПЕН»: PBKDF2 подхватывал работу, и человек мог годами
        # пользоваться слабым вариантом, не зная об этом.
        if not crypto.argon2_available():
            raise AssertionError(crypto.ARGON2_MISSING.split("\n")[0])
        _roundtrip(crypto.KdfParams.new_argon2id(
            time_cost=1, memory_kib=8 * 1024, parallelism=1), tmpdir, "v2.pmv")
        lines.append("PMVAULT2 (Argon2id) — работает, это формат записи")

        # Старые файлы обязаны продолжать открываться: их полно на дисках
        # пользователей, и в архивах снимков они будут лежать годами.
        _roundtrip(crypto.KdfParams.new_pbkdf2(iterations=20_000),
                   tmpdir, "v1.pmv")
        lines.append("PMVAULT1 (PBKDF2)   — читается, старые файлы открываются")

        pwd, pool = generate_password(DEFAULT_GEN)
        if len(pwd) != DEFAULT_GEN["exact_len"] or pool < 20:
            raise AssertionError("генератор паролей ведёт себя неожиданно")
        lines.append("Генератор паролей   — работает")

        local = [dict(SAMPLE["entries"][0])]
        incoming = [dict(SAMPLE["entries"][0], password="ДРУГОЙ",
                         modified=now_iso())]
        plan = plan_merge(local, incoming)
        apply_merge(local, plan, [INCOMING] * len(plan.conflicts))
        if local[0]["password"] != "ДРУГОЙ":
            raise AssertionError("слияние не применилось")
        if "пАроль Йц1!" not in [h["password"] for h in local[0].get("history", [])]:
            raise AssertionError("прежний пароль не попал в историю при слиянии")
        lines.append("Слияние и история   — работает")

        mgr = backup.BackupManager(os.path.join(tmpdir, "backups"))
        snap = mgr.write_snapshot(b"PMVAULT1" + b"\0" * 60, "d", tag="premerge")
        if snap is None or not os.path.isfile(snap.path):
            raise AssertionError("снимок не создался")
        lines.append("Архив снимков       — работает")

        normalize_data({"version": 1, "entries": [{"id": "x", "totp": "Z"}]},
                       DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        lines.append("Разбор хранилища    — работает")

        from . import netblock
        netblock.install()
        lines.append("Блокировка сети     — %s"
                     % ("включена" if netblock.is_blocked() else "НЕ РАБОТАЕТ"))

        ok = all("НЕ" not in ln and "НЕДОСТУПЕН" not in ln for ln in lines)
        return ok, "\n".join(lines)
    except Exception as e:
        lines.append("СБОЙ: %s" % e)
        return False, "\n".join(lines)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        # И саму .selfcheck, если она опустела: оставлять пустую папку рядом
        # с программой некрасиво, а удалять её с содержимым — опасно, вдруг
        # параллельно идёт другая проверка. rmdir снимает только пустую.
        try:
            os.rmdir(os.path.dirname(tmpdir))
        except OSError:
            pass
