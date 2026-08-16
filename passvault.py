#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PassVault — офлайн-хранилище и генератор паролей (версия для ПК).

    python passvault.py            запуск
    python passvault.py --test     самопроверка
    python passvault.py --version  версия
    python passvault.py ФАЙЛ.pmv   открыть конкретное хранилище

Зависимости (обе обязательны):
    pip install cryptography
    pip install argon2-cffi

Код разложен по пакету pvault/. Разделение сделано не ради красоты: в версии
1.x всё лежало одним файлом, слой записи на диск нельзя было проверить
автотестом, и именно там жил баг, стиравший хранилище безвозвратно. Теперь на
него есть тест, который имитирует сбой ровно в опасный момент.

Формат файла vault.pmv описан в pvault/crypto.py. PMVAULT1 не менялся и байт в
байт совпадает с прежним, поэтому существующие хранилища — в том числе
принесённые с телефона — открываются без конвертации.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pvault import __version__, netblock          # noqa: E402

# Отключаем сетевые функции Python до всего остального: любая попытка выйти в
# сеть штатным способом упадёт с ошибкой. Это защита в глубину, а не гарантия —
# гарантию уровня системы даёт правило брандмауэра (см. README).
netblock.install()

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # noqa: F401
except ImportError:
    sys.stderr.write("Не найдена библиотека cryptography.\n"
                     "Установи её командой:  pip install cryptography\n")
    raise

# Argon2id — единственный формат записи, поэтому argon2-cffi обязательна.
# Раньше она была необязательной, и без неё программа просто не предлагала
# «усиленный» формат. Теперь без неё нельзя ни создать хранилище, ни открыть
# его, и узнать об этом надо сейчас, а не в момент сохранения.
try:
    import argon2.low_level                                          # noqa: F401
except ImportError:
    sys.stderr.write("Не найдена библиотека argon2-cffi.\n"
                     "Установи её командой:  pip install argon2-cffi\n")
    raise


def _safe_print(text):
    """Печать, переживающая консоль в cp866/cp1251.

    Прежняя версия падала с UnicodeEncodeError на символе «галочка»: все
    проверки проходили, а команда возвращала ошибку.
    """
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def run_tests(verbosity=1):
    import unittest
    here = os.path.dirname(os.path.abspath(__file__))
    suite = unittest.defaultTestLoader.discover(
        os.path.join(here, "tests"), top_level_dir=here)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    if result.wasSuccessful():
        _safe_print("\nВсе проверки пройдены ✔")
        return 0
    _safe_print("\nЕсть непройденные проверки ✘")
    return 1


def main(argv):
    if "--version" in argv:
        _safe_print("PassVault %s" % __version__)
        return 0
    if "--test" in argv:
        return run_tests(verbosity=2 if "-v" in argv else 1)

    try:
        import tkinter                                    # noqa: F401
    except Exception:
        _safe_print("Tkinter недоступен в этой системе.\n"
                    "На Windows/macOS он входит в состав Python с python.org.\n"
                    "На Linux установи пакет:  sudo apt install python3-tk")
        return 1

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # чёткий шрифт на HiDPI
        except Exception:
            pass

    from pvault import setup as setuplib

    if "--selfcheck" in argv:
        from pvault.selfcheck import run as selfcheck
        ok, report = selfcheck()
        _safe_print(report)
        if setuplib.is_frozen() and "--quiet" not in argv:
            from tkinter import Tk, messagebox
            root = Tk()
            root.withdraw()
            title = "Самопроверка PassVault %s" % __version__
            if ok:
                messagebox.showinfo(title, report + "\n\nВсё в порядке.")
            else:
                messagebox.showerror(title, report)
            root.destroy()
        return 0 if ok else 1

    # Программа переносимая и в систему не ставится, поэтому ключа --install
    # больше нет. Ключ --uninstall остался: его прописали в «Установленные
    # программы» версии 2.x–3.2, и оттуда он будет приходить ещё долго. Теперь
    # он открывает окно уборки, а не удаления файлов.
    if "--uninstall" in argv:
        from pvault.ui.setup_ui import run_cleanup
        run_cleanup(quiet="--quiet" in argv)
        return 0

    vault_path = next((a for a in argv[1:] if not a.startswith("-")), None)

    from pvault.ui.app import App
    App(vault_path).mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
