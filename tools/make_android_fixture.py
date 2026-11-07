# -*- coding: utf-8 -*-
r"""Создаёт эталонный vault.pmv для тестов Android-проекта.

    python tools\make_android_fixture.py

Файл кладётся в
    D:\vscode_projects\PassVaultAndroid\app\src\test\resources\pc_vault.pmv
и читается тестом PcCompatibilityTest.

Зачем это нужно. Расхождение форматов между ПК и телефоном — самый дорогой вид
ошибки: он не падает, а молча съедает данные при синхронизации. Поэтому файл
для проверки пишет НАСТОЯЩИЙ код ПК-версии, а не руками собранный JSON.

В эталон намеренно вложено то, на чём совместимость ломается чаще всего:
кириллица, многострочные заметки, старый формат метки времени, надгробие,
история паролей и поле future_field, о котором телефон не знает и которое
обязан вернуть нетронутым.
"""

import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from pvault import crypto                    # noqa: E402
from pvault.generator import DEFAULT_GEN     # noqa: E402

ANDROID_PROJECT = os.environ.get("PASSVAULT_ANDROID_PROJECT",
                                 r"D:\vscode_projects\PassVaultAndroid")
PASSWORD = "тестовая мастер-фраза"

# В тестах медленный KDF ни к чему: проверяется формат контейнера, а не
# стойкость. Настоящие 600 000 итераций и 256 МиБ гонять незачем.
ITERATIONS = 20_000
FAST_ARGON2 = dict(time_cost=1, memory_kib=8 * 1024, parallelism=1)


def build_data():
    gen = dict(DEFAULT_GEN)
    gen.update(exact_len=18, no_ambiguous=True)

    return {
        "version": 1,
        "entries": [
            {
                "id": "aaaa1111bbbb2222",
                "title": "Почта Ёлка",
                "login": "user@example.com",
                "password": "пАроль Йц1!",
                "url": "https://mail.example.com",
                "notes": "первая строка\nвторая строка с ёЁ",
                "created": "2026-01-01T09:00:00Z",
                "modified": "2026-01-03T12:30:45Z",
                "history": [
                    {"password": "прошлый-1", "changed": "2026-01-02T10:00:00Z"},
                    {"password": "прошлый-2", "changed": "2026-01-01T10:00:00Z"},
                ],
                # Поле из «будущей» версии. Телефон о нём не знает и обязан
                # вернуть его в файл нетронутым.
                "future_field": {"kept": True, "nested": [1, 2, 3]},
            },
            {
                "id": "cccc3333dddd4444",
                "title": "Старый формат времени",
                "login": "legacy",
                "password": "p",
                "url": "",
                "notes": "метка времени как в версии 1.x",
                "created": "2026-01-02 11:30",
                "modified": "2026-01-02 11:30",
            },
            {
                "id": "eeee5555ffff6666",
                "title": "Удалено на ПК",
                "login": "",
                "password": "",
                "url": "",
                "notes": "",
                "created": "2026-01-01T09:00:00Z",
                "modified": "2026-01-04T08:00:00Z",
                "deleted": True,
            },
        ],
        "settings": {"generator": gen, "app": {"autolock_minutes": 7,
                                               "clipboard_seconds": 30}},
    }


def write(target_dir, name, params):
    blob, _key, _p = crypto.create_encrypted(build_data(), PASSWORD, params)
    target = os.path.join(target_dir, name)
    with open(target, "wb") as f:
        f.write(blob)

    # Сразу читаем обратно своим же кодом: файл, который не открывается,
    # эталоном быть не может.
    with open(target, "rb") as f:
        back, _k, p = crypto.decrypt_vault(f.read(), PASSWORD)
    assert len(back["entries"]) == 3
    print("  %s — %d байт, %s" % (name, len(blob), p.describe()))
    return target


def main():
    target_dir = os.path.join(ANDROID_PROJECT, "app", "src", "test", "resources")
    if not os.path.isdir(os.path.join(ANDROID_PROJECT, "app")):
        print("Не найден Android-проект: %s" % ANDROID_PROJECT)
        return 1
    os.makedirs(target_dir, exist_ok=True)

    if not crypto.argon2_available():
        print("Не установлена argon2-cffi — эталоны собрать нельзя.")
        print("Установи её командой:  pip install argon2-cffi")
        return 1

    print("Эталоны для тестов Android:")

    # Основной эталон — PMVAULT2. Это единственный формат, который ПК-версия
    # теперь пишет, и именно такие файлы поедут на телефон.
    write(target_dir, "pc_vault_argon2.pmv",
          crypto.KdfParams.new_argon2id(**FAST_ARGON2))

    # Второй эталон — PMVAULT1. Программа таких файлов больше не создаёт, но
    # ЧИТАТЬ их обязана вечно: они лежат у пользователей на дисках и годами
    # будут лежать в архивах снимков. Телефон должен открывать их так же.
    write(target_dir, "pc_vault.pmv",
          crypto.KdfParams.new_pbkdf2(iterations=ITERATIONS))

    print("Пароль: %s" % PASSWORD)
    return 0


if __name__ == "__main__":
    sys.exit(main())
