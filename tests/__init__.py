# -*- coding: utf-8 -*-
r"""Автотесты PassVault.

Запуск:  python passvault.py --test

Всё, кроме pvault/ui, проверяется здесь без единого окна на экране. Это и было
причиной разделить программу на слои: в версии 1.x слой записи на диск не
проверялся ничем, и именно там жил баг, стиравший хранилище безвозвратно.
Соответствующий тест — test_storage.SurviveCrashTest.

Изоляция тестов
---------------
Ниже переопределяются два места, и оба — не мелочь.

1. tempfile.tempdir. По умолчанию временные файлы уходят в профиль
   пользователя на системном диске. Тесты менеджера паролей создают там
   десятки хранилищ с настоящим шифрованием; ни одному из них там не место.
   Всё пишется в .testtmp рядом с проектом.

2. PASSVAULT_HOME. Без него config.py писал список недавних хранилищ в
   config.json РАБОЧЕЙ ПАПКИ ПРОГРАММЫ — то есть каждый прогон тестов затирал
   пользователю настоящий список путями вида
   C:\Users\...\Temp\pvui-13l769mw\vault.pmv, и при следующем запуске
   программа честно пыталась открыть несуществующий временный файл.
"""

import atexit
import os
import shutil
import tempfile

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEST_TMP_ROOT = os.path.join(_PROJECT_ROOT, ".testtmp")
TEST_HOME = os.path.join(TEST_TMP_ROOT, "home")

os.makedirs(TEST_HOME, exist_ok=True)

tempfile.tempdir = TEST_TMP_ROOT
os.environ["PASSVAULT_HOME"] = TEST_HOME


@atexit.register
def _cleanup():
    """Убираем за собой. Мусор от упавшего теста интереснее, чем чистота,
    поэтому папка сносится только целиком и только по завершении прогона."""
    shutil.rmtree(TEST_TMP_ROOT, ignore_errors=True)
