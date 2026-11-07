# -*- coding: utf-8 -*-
r"""Тесты установки и удаления.

Ярлыки и реестр здесь выключены: автотест не имеет права сорить в меню «Пуск»
и в профиле пользователя — и, что важнее, не имеет права снести НАСТОЯЩИЙ
ярлык и НАСТОЯЩУЮ запись в реестре у того, кто гоняет тесты на своей машине.

Главное здесь — UninstallKeepsUserDataTest. Раньше на этом месте лежала
проверка

    data = os.path.normcase(setuplib.data_dir_note())   # "рядом с файлом хранилища"
    install = os.path.normcase(setuplib.default_install_dir())
    self.assertFalse(data.startswith(install))

то есть русская фраза сравнивалась с путём. Она проходила всегда и не защищала
ни от чего, при том что называлась «удаление не должно задевать хранилище».
А удаление в это время выполняло `rmdir /s /q` по папке программы и вместе с
ней стирало vault.pmv, откат и весь архив снимков.
"""

import os
import shutil
import sys
import tempfile
import unittest

from pvault import setup as setuplib


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pvinst-")
        self.fake_exe = os.path.join(self.root, "GemSwap-Setup-3.2.exe")
        with open(self.fake_exe, "wb") as f:
            f.write(b"MZ" + b"\0" * 4096)

        self._real_self_path = setuplib.self_path
        self._real_is_frozen = setuplib.is_frozen
        setuplib.self_path = lambda: self.fake_exe
        setuplib.is_frozen = lambda: True

    def tearDown(self):
        setuplib.self_path = self._real_self_path
        setuplib.is_frozen = self._real_is_frozen
        shutil.rmtree(self.root, ignore_errors=True)

    def target(self):
        return os.path.join(self.root, "installed")

    def do_install(self):
        return setuplib.install(self.target(), desktop_shortcut=False,
                                start_menu=False, register=False)

    # ------------------------------------------------------------------
    def test_reinstall_over_existing_works(self):
        self.do_install()
        with open(self.fake_exe, "wb") as f:
            f.write(b"MZ" + b"\1" * 4096)          # «новая версия»
        exe = self.do_install()
        with open(exe, "rb") as f:
            self.assertEqual(f.read()[2:6], b"\1\1\1\1")

    def test_refuses_to_install_onto_itself(self):
        exe = self.do_install()
        setuplib.self_path = lambda: exe
        with self.assertRaises(OSError):
            self.do_install()

    def test_name_decides_installer_or_app(self):
        """GemSwap-Setup.exe ставит, GemSwap.exe открывает хранилище."""
        self.assertTrue(setuplib.looks_like_setup_exe())
        setuplib.self_path = lambda: os.path.join(self.root, setuplib.EXE_NAME)
        self.assertFalse(setuplib.looks_like_setup_exe())

    def test_update_over_old_name_replaces_old_exe_and_keeps_data(self):
        """Обновление поверх установки под прежним именем.

        Старый PassVault.exe — та же программа, его место занимает новый exe:
        оставь его — и рядом с новым значком висел бы прежний «PassVault».
        Хранилище при этом остаётся на месте.
        """
        target = self.target()
        os.makedirs(target)
        for name in setuplib.LEGACY_EXE_NAMES:
            with open(os.path.join(target, name), "wb") as f:
                f.write(b"MZ old")
        vault = os.path.join(target, "vault.pmv")
        with open(vault, "wb") as f:
            f.write(b"PMVAULT2data")

        exe = self.do_install()

        self.assertEqual(os.path.basename(exe), setuplib.EXE_NAME)
        self.assertTrue(os.path.isfile(exe))
        for name in setuplib.LEGACY_EXE_NAMES:
            self.assertFalse(os.path.exists(os.path.join(target, name)),
                             "старый exe остался рядом с новым")
        with open(vault, "rb") as f:
            self.assertEqual(f.read(), b"PMVAULT2data", "ХРАНИЛИЩЕ ИЗМЕНЕНО")

    def test_running_from_sources_is_never_the_installer(self):
        """`python passvault.py` обязан открыть хранилище, а не окно установки.

        Из исходников self_path() отдаёт путь к самому модулю — pvault\\setup.py.
        Слово «setup» находилось в его имени, и программа из исходников
        запускала установщик. То есть не запускалась вовсе.
        """
        setuplib.is_frozen = lambda: False
        setuplib.self_path = self._real_self_path      # настоящий pvault/setup.py
        self.assertIn("setup", os.path.basename(setuplib.self_path()).lower(),
                      "проверка потеряла смысл: модуль переименовали")
        self.assertFalse(setuplib.looks_like_setup_exe())

    def test_default_dir_is_per_user(self):
        d = setuplib.default_install_dir()
        self.assertIn(setuplib.EXE_STEM, d)
        self.assertNotIn("Program Files", d)

    @unittest.skipUnless(sys.platform == "win32", "только Windows")
    def test_default_dir_follows_the_drive_of_the_setup_exe(self):
        """Запущен с D: — предлагаем D:, а не системный диск."""
        setuplib.self_path = lambda: r"D:\Downloads\GemSwap-Setup-3.2.exe"
        self.assertEqual(setuplib.default_install_dir().upper(),
                         os.path.join("D:\\", setuplib.EXE_STEM).upper())


class NoSuspiciousBehaviourTest(unittest.TestCase):
    r"""Установщик не должен вести себя как вредоносный загрузчик.

    Windows Defender заблокировал установку версии 3.1 с вердиктом
    Behavior:Win32/DefenseEvasion.A!ml и удалил файл. Вердикт был ложным —
    это эвристика (суффикс !ml), а не сигнатура: тот же файл под именем
    PassVault.exe проверку содержимого проходил, а под именем
    PassVault-Setup-3.1.exe удалялся. Байты одни и те же, отличалось поведение.

    Срабатывала связка: неподписанная программа с нулевой репутацией копирует
    себя в другую папку, тут же запускает powershell с готовым скриптом, пишет
    ключ в CurrentVersion\Uninstall и стартует записанный файл. Самое приметное
    здесь — вызов powershell, и он убран: ярлык делается через COM внутри
    своего процесса.

    Спорить с антивирусом бессмысленно, поэтому проверяем механикой: код
    установки не имеет права порождать powershell.
    """

    @staticmethod
    def _live_strings(module):
        """Строковые литералы модуля без комментариев и docstring'ов.

        Проверять по тексту файла нельзя: слово powershell есть в пояснении,
        почему его убрали, и проверка падала бы на собственной документации.
        Разбираем синтаксическое дерево и берём только те строки, которые
        действительно попадают в исполняемый код.
        """
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(module))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                body = getattr(node, "body", None)
                if body and isinstance(body[0], ast.Expr) \
                        and isinstance(body[0].value, ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    docstrings.add(id(body[0].value))
        return [n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in docstrings]

    def test_installer_never_spawns_powershell(self):
        strings = " ".join(self._live_strings(setuplib)).lower()
        for word in ("powershell", "pwsh", "wscript.shell"):
            self.assertNotIn(word, strings,
                             "установщик снова запускает %s — Defender "
                             "заблокирует установку" % word)

    def test_installer_does_not_spawn_the_installed_program(self):
        r"""Установщик не запускает записанный exe дочерним процессом.

        Дроппер копирует исполняемый файл и тут же исполняет его как своего
        потомка. Именно эту связку — копирование в другую папку, запись ключа
        в CurrentVersion\Uninstall, ярлык и запуск записанного файла —
        поведенческий монитор Defender метит как DefenseEvasion (в отчёте
        видны два процесса, родитель и потомок). Программу после установки
        открываем через оболочку, os.startfile, а не subprocess: тогда в
        дереве процессов установщик её родителем не значится.
        """
        import ast
        import inspect
        from pvault.ui import setup_ui
        tree = ast.parse(inspect.getsource(setup_ui))
        spawned = [node.func.attr for node in ast.walk(tree)
                   if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute)
                   and isinstance(node.func.value, ast.Name)
                   and node.func.value.id == "subprocess"]
        self.assertEqual(
            spawned, [],
            "установщик снова порождает процесс через subprocess — Defender "
            "метит связку «скопировал exe и запустил» как дроппер: %s" % spawned)

    def test_shortcut_failure_never_breaks_installation(self):
        """Ярлык — удобство, а не смысл установки.

        Проверять, что ярлык РЕАЛЬНО создался, здесь нельзя: антивирус в
        режиме проверки перехватывает запись .lnk и возвращает оболочке отказ,
        причём непредсказуемо — на одном и том же коде вызов то проходит, то
        нет. Такой тест валил бы сборку по погоде. Проверяем то, что зависит
        от нас: функция обязана вернуть True или False и не бросить исключение.
        """
        if os.name != "nt":
            self.skipTest("только Windows")
        root = tempfile.mkdtemp(prefix="pvlnk-")
        try:
            target = os.path.join(root, "PassVault.exe")
            with open(target, "wb") as f:
                f.write(b"MZ" + b"\0" * 512)
            result = setuplib._make_shortcut(
                os.path.join(root, "menu", "PassVault.lnk"), target, root, "описание")
            self.assertIn(result, (True, False))
        finally:
            shutil.rmtree(root, ignore_errors=True)


class UninstallKeepsUserDataTest(unittest.TestCase):
    r"""Удаление программы не имеет права тронуть хранилище.

    Случай не выдуманный: переносимый режим кладёт vault.pmv рядом с exe, а
    установщик по умолчанию предлагает тот диск, с которого запущен. Папка
    D:\PassVault с программой и хранилищем внутри — штатный результат, а не
    экзотика.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pvuninst-")
        self.installed = os.path.join(self.root, "PassVault")
        os.makedirs(self.installed)

        self.exe = os.path.join(self.installed, setuplib.EXE_NAME)
        with open(self.exe, "wb") as f:
            f.write(b"MZ" + b"\0" * 1024)

        self._real_self_path = setuplib.self_path
        setuplib.self_path = lambda: self.exe

    def tearDown(self):
        setuplib.self_path = self._real_self_path
        shutil.rmtree(self.root, ignore_errors=True)

    def put(self, name, content=b"PMVAULT1data"):
        path = os.path.join(self.installed, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def do_uninstall(self):
        return setuplib.uninstall(shortcuts=False, register=False, defer=False)

    # ------------------------------------------------------------------
    def test_vault_next_to_the_program_survives(self):
        vault = self.put("vault.pmv")
        prev = self.put("vault.pmv.prev")
        backups = os.path.join(self.installed, "vault_backups")
        os.makedirs(backups)
        snap = os.path.join(backups, "snap-20260808-090545.pmv")
        with open(snap, "wb") as f:
            f.write(b"PMVAULT1snapshot")

        _target, kept = self.do_uninstall()

        self.assertTrue(os.path.isfile(vault), "ХРАНИЛИЩЕ УДАЛЕНО")
        self.assertTrue(os.path.isfile(prev), "откат удалён")
        self.assertTrue(os.path.isfile(snap), "снимок из архива удалён")
        self.assertFalse(os.path.isfile(self.exe), "сама программа должна удалиться")
        self.assertTrue(os.path.isdir(self.installed),
                        "папку с данными сносить нельзя")
        self.assertIn("vault.pmv", kept)
        self.assertIn("vault_backups", kept)

    def test_clean_folder_is_removed_completely(self):
        """Если рядом с программой ничего чужого нет — папка уходит целиком."""
        self.put("config.json", b"{}")               # свой файл, его удаляем
        _target, kept = self.do_uninstall()
        self.assertEqual(kept, [])
        self.assertFalse(os.path.isdir(self.installed))

    def test_any_foreign_file_stops_folder_removal(self):
        """Последний рубеж: чужой файл любого вида отменяет снос папки."""
        self.put("важные заметки.txt", b"text")
        _target, kept = self.do_uninstall()
        self.assertEqual(kept, ["важные заметки.txt"])
        self.assertTrue(os.path.isdir(self.installed))
        self.assertFalse(os.path.isfile(self.exe))

    def test_exe_under_old_name_is_ours(self):
        """PassVault.exe от прежней версии — файл программы, а не чужой.

        Иначе после обновления удаление считало бы его пользовательским
        файлом и оставляло папку со старым exe внутри.
        """
        for name in setuplib.LEGACY_EXE_NAMES:
            self.put(name, b"MZ old")
        _target, kept = self.do_uninstall()
        self.assertEqual(kept, [])
        self.assertFalse(os.path.isdir(self.installed))

    def test_vault_files_are_recognised(self):
        for name in ("vault.pmv", "vault.pmv.prev", "vault.pmv.lock",
                     "vault.pmv.att", "vault.pmv.tmp", "vault.pmv.bak",
                     "рабочий.pmv"):
            self.put(name)
        os.makedirs(os.path.join(self.installed, "vault_backups"))
        found = setuplib.vault_files_in(self.installed)
        self.assertIn("vault.pmv", found)
        self.assertIn("рабочий.pmv", found)
        self.assertIn("vault_backups", found)
        self.assertNotIn(setuplib.EXE_NAME, found)

    @unittest.skipUnless(sys.platform == "win32", "только Windows")
    def test_removal_command_can_not_wipe_a_folder(self):
        r"""Отложенное удаление собирается отдельной строкой для cmd, и её
        никакой другой тест не видит. Здесь проверяется именно она.

        `rmdir /s /q` вернуть сюда очень легко — «так короче», — и цена этой
        правке ровно одна: хранилище пользователя.
        """
        cmd = setuplib.removal_command(r"D:\PassVault")

        self.assertNotIn("/s", cmd.lower(),
                         "rmdir /s снесёт папку вместе с хранилищем")
        self.assertNotIn("rd ", cmd.lower())
        self.assertIn(r'rmdir "D:\PassVault"', cmd)

        # Удаляются только поимённо перечисленные файлы программы.
        deleted = [part.strip() for part in cmd.split("&")
                   if part.strip().lower().startswith("del ")]
        self.assertEqual(len(deleted), len(setuplib.PROGRAM_FILES))
        for name in setuplib.PROGRAM_FILES:
            self.assertTrue(
                any(name in part for part in deleted),
                "файл программы %s не удаляется" % name)
        for part in deleted:
            self.assertTrue(
                any(name in part for name in setuplib.PROGRAM_FILES),
                "удаляется что-то, чего программа не клала: %s" % part)
