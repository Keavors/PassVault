# -*- coding: utf-8 -*-
r"""Тесты переносимого режима и уборки следов прежних версий.

Главное здесь — NoDropperBehaviourTest. Он не проверяет правильность работы,
он ЗАПРЕЩАЕТ программе делать то, из-за чего Windows Defender блокировал
установку версии 3.1 с вердиктом Behavior:Win32/DefenseEvasion.A!ml.

Вердикт был ложным: это эвристика, а не сигнатура (суффикс !ml). Те же байты
под именем PassVault.exe проверку проходили, а под именем
PassVault-Setup-3.1.exe удалялись с диска — отличалось поведение, не
содержимое. Срабатывала связка: неподписанная программа с нулевой репутацией
копирует себя в другую папку, пишет ключ в CurrentVersion\Uninstall, создаёт
ярлыки, запускает записанный файл, а при удалении стирает себя скрытым
процессом cmd.

Версия 3.2 убрала два самых заметных звена и всё равно ловилась на чужой
машине. Версия 3.3 убрала саму установку: программа переносимая. Спорить с
антивирусом бессмысленно, поэтому проверяем механикой — каждое из звеньев
запрещено отдельным тестом, и вернуть его молча не получится.

Тесты ниже намеренно смотрят на ВЕСЬ пакет pvault, а не на один модуль:
вернуть subprocess можно в любой файл, а последствие будет одно.
"""

import ast
import os
import re
import shutil
import tempfile
import unittest

from pvault import setup as setuplib

PACKAGE_DIR = os.path.dirname(os.path.abspath(setuplib.__file__))


def shipped_modules():
    """Все .py пакета pvault — то, что реально попадает пользователю в exe."""
    out = []
    for root, dirs, files in os.walk(PACKAGE_DIR):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in sorted(files):
            if name.endswith(".py"):
                out.append(os.path.join(root, name))
    return out


def parse(path):
    with open(path, "r", encoding="utf-8") as f:
        return ast.parse(f.read(), filename=path)


def live_strings(tree):
    """Строковые литералы, попадающие в исполняемый код.

    Docstring'и исключаются: в них подробно написано, почему powershell и
    rmdir отсюда убраны, и проверка по тексту файла падала бы на собственной
    документации. Комментарии в дерево не попадают вовсе.
    """
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


def called_attrs(tree, module_name):
    """Имена методов, вызванных как module_name.что_то(...)."""
    return [node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == module_name]


# Как в коде выглядит путь к самой программе.
SELF_REFS = ("sys.executable", "self_path", "self_dir", "__file__")


def self_referring_names(tree):
    r"""Локальные имена, в которые положили путь к самой программе.

    Без этого проверка на самокопирование дырявая, и дыра не теоретическая:
    установщик версии 3.2 писал ровно так —

        source = self_path()
        ...
        shutil.copy2(source, tmp)

    Проверка смотрела на аргумент `source`, слов self_path там не было, и
    самокопирование проходило мимо. Прослеживаем присваивания на один шаг.
    """
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = ast.unparse(node.value)
        if not any(ref in value for ref in SELF_REFS):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Tuple):
                names.update(el.id for el in target.elts
                             if isinstance(el, ast.Name))
    return names


def points_at_self(source, tainted_names):
    """Указывает ли выражение на исполняемый файл самой программы."""
    if any(ref in source for ref in SELF_REFS):
        return True
    return any(re.search(r"\b%s\b" % re.escape(name), source)
               for name in tainted_names)


class NoDropperBehaviourTest(unittest.TestCase):
    """Программа не имеет права вести себя как загрузчик вредоноса."""

    def test_nothing_in_the_package_spawns_a_process(self):
        r"""Ни один модуль не запускает внешних программ.

        Раньше отсюда запускались powershell (ярлыки) и cmd (самоудаление).
        Порождение процессов — несущий признак дроппера, и менеджеру паролей
        оно не нужно ни для чего: всё, что требуется, делается своими руками.
        """
        for path in shipped_modules():
            tree = parse(path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                    self.assertNotIn(
                        "subprocess", names,
                        "%s импортирует subprocess — Defender метит запуск "
                        "внешних процессов как поведение дроппера"
                        % os.path.basename(path))
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotEqual(
                        node.module.split(".")[0], "subprocess",
                        "%s импортирует subprocess" % os.path.basename(path))

    def test_no_module_mentions_a_shell(self):
        """Ни powershell, ни cmd, ни WScript.Shell в исполняемом коде."""
        forbidden = ("powershell", "pwsh", "wscript.shell", "cmd.exe",
                     "rmdir", "/s /q")
        for path in shipped_modules():
            strings = " ".join(live_strings(parse(path))).lower()
            for word in forbidden:
                self.assertNotIn(
                    word, strings,
                    "%s снова содержит «%s» в рабочем коде"
                    % (os.path.basename(path), word))

    def test_nothing_writes_to_the_registry(self):
        r"""В реестр программа больше не пишет — только читает и удаляет своё.

        Запись в CurrentVersion\Uninstall — это закрепление в системе
        (persistence). Само по себе законно, но в связке с копированием себя
        именно оно поднимало оценку до DefenseEvasion. Переносимой программе
        закрепляться незачем.
        """
        writes = ("SetValueEx", "SetValue", "CreateKey", "CreateKeyEx")
        for path in shipped_modules():
            used = called_attrs(parse(path), "winreg")
            for name in writes:
                self.assertNotIn(
                    name, used,
                    "%s пишет в реестр через winreg.%s — программа снова "
                    "закрепляется в системе" % (os.path.basename(path), name))

    def test_the_program_never_copies_itself(self):
        """Самокопирование — первое звено связки «дропнул и запустил».

        Запрещено копирование именно СЕБЯ, а не файлов вообще: storage.py
        копирует хранилище, чтобы сделать откат vault.pmv.prev, и это ровно
        то, ради чего программа существует. Ловим источник копирования —
        sys.executable и self_path(), то есть собственный exe.
        """
        for path in shipped_modules():
            tree = parse(path)
            tainted = self_referring_names(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "shutil"
                        and node.func.attr in ("copy", "copy2", "copyfile",
                                               "copytree")
                        and node.args):
                    continue
                source = ast.unparse(node.args[0])
                self.assertFalse(
                    points_at_self(source, tainted),
                    "%s копирует саму программу — shutil.%s(%s, …). Это "
                    "первое звено связки, которую Defender метит как дроппер"
                    % (os.path.basename(path), node.func.attr, source))

    def test_installer_entry_points_are_gone(self):
        """Установки нет, и функций установки быть не должно.

        Проверка от возврата по невнимательности: пока в модуле нет install()
        и looks_like_setup_exe(), нечему и сработать.
        """
        for name in ("install", "uninstall", "looks_like_setup_exe",
                     "removal_command", "remove_program_files",
                     "default_install_dir"):
            self.assertFalse(
                hasattr(setuplib, name),
                "в pvault/setup.py вернулась функция %s() — вместе с ней "
                "вернётся и поведение, которое блокировал Defender" % name)

    def test_no_com_shortcut_machinery(self):
        """Ручные вызовы COM через таблицу методов убраны вместе с ярлыками.

        Код, который сам разбирает vtable и дёргает методы по номеру,
        выглядит необычно для любого статического анализатора. Создавать
        ярлыки переносимой программе не нужно — это делает проводник.
        """
        strings = " ".join(live_strings(parse(setuplib.__file__))).lower()
        self.assertNotIn("{00021401", strings,
                         "вернулся CLSID_ShellLink — вернулась COM-машинерия")


class CleanupNeverTouchesDataTest(unittest.TestCase):
    r"""Уборка следов не имеет права тронуть ни хранилище, ни программу.

    История, ради которой этот тест существует: удаление версии 3.0 выполняло
    rmdir /s /q по папке программы. Переносимый режим кладёт vault.pmv ровно
    рядом с exe, поэтому удаление стирало хранилище, откат и весь архив
    снимков — а окно в этот момент писало «Хранилище и резервные копии
    останутся».

    Теперь уборка умеет удалять только ярлыки. Проверяем это поведением, а не
    обещанием: кладём рядом всё, что можно потерять, и смотрим, что уцелело.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pvclean-")
        self.folder = os.path.join(self.root, "PassVault")
        os.makedirs(self.folder)

        self.files = []
        for name in ("PassVault.exe", "vault.pmv", "vault.pmv.prev",
                     "config.json", "важные заметки.txt"):
            path = os.path.join(self.folder, name)
            with open(path, "wb") as f:
                f.write(b"PMVAULT1" + b"\0" * 64)
            self.files.append(path)

        self.backups = os.path.join(self.folder, "vault_backups")
        os.makedirs(self.backups)
        snap = os.path.join(self.backups, "snap-20260808-090545.pmv")
        with open(snap, "wb") as f:
            f.write(b"PMVAULT1snapshot")
        self.files.append(snap)

        # Настоящий ярлык трогать нельзя: тесты гоняются на живой машине.
        self.link = os.path.join(self.root, "PassVault.lnk")
        with open(self.link, "wb") as f:
            f.write(b"L\0\0\0")

        self._real_shortcuts = setuplib.legacy_shortcuts
        setuplib.legacy_shortcuts = lambda: [self.link]

    def tearDown(self):
        setuplib.legacy_shortcuts = self._real_shortcuts
        shutil.rmtree(self.root, ignore_errors=True)

    def test_only_the_shortcut_disappears(self):
        removed = setuplib.remove_legacy_traces()

        self.assertIn(self.link, removed)
        self.assertFalse(os.path.exists(self.link), "ярлык должен был уйти")
        for path in self.files:
            self.assertTrue(os.path.isfile(path),
                            "уборка удалила %s" % os.path.basename(path))
        self.assertTrue(os.path.isdir(self.folder), "папка программы снесена")
        self.assertTrue(os.path.isdir(self.backups), "архив снимков снесён")

    def test_a_non_shortcut_in_the_list_is_refused(self):
        """Последний рубеж: даже если список ярлыков подсунет чужой файл.

        Проверка расширения стоит прямо перед удалением именно на этот
        случай — ошибка в legacy_shortcuts() не должна стоить хранилища.
        """
        vault = os.path.join(self.folder, "vault.pmv")
        setuplib.legacy_shortcuts = lambda: [vault]

        removed = setuplib.remove_legacy_traces()

        self.assertTrue(os.path.isfile(vault), "ХРАНИЛИЩЕ УДАЛЕНО")
        self.assertNotIn(vault, removed)

    def test_cleanup_is_safe_to_run_twice(self):
        setuplib.remove_legacy_traces()
        setuplib.remove_legacy_traces()          # не должно ничего сломать
        self.assertFalse(os.path.exists(self.link))


class PortableModeTest(unittest.TestCase):
    """Программа работает там, где лежит."""

    def test_traces_are_reported_as_text(self):
        real = setuplib.legacy_shortcuts
        setuplib.legacy_shortcuts = lambda: [r"C:\fake\PassVault.lnk"]
        try:
            traces = setuplib.legacy_traces()
        finally:
            setuplib.legacy_shortcuts = real
        self.assertIn(r"C:\fake\PassVault.lnk", traces)

    def test_self_dir_is_where_the_program_lives(self):
        self.assertTrue(os.path.isdir(setuplib.self_dir()))

    def test_vault_defaults_to_the_program_folder(self):
        """Переносимость держится на этом: хранилище ищется рядом с программой."""
        from pvault import paths
        self.assertEqual(os.path.dirname(paths.default_vault_path()),
                         paths.app_dir())


class DispatcherTest(unittest.TestCase):
    """Точка входа больше не умеет превращаться в установщик."""

    @staticmethod
    def _entry_tree():
        path = os.path.join(os.path.dirname(PACKAGE_DIR), "passvault.py")
        with open(path, "r", encoding="utf-8") as f:
            return ast.parse(f.read(), filename=path)

    def test_no_install_switch(self):
        strings = " ".join(live_strings(self._entry_tree()))
        self.assertNotIn("--install", strings,
                         "вернулся ключ --install: установка запрещена")

    def test_uninstall_switch_survives_for_old_registry_entries(self):
        r"""«PassVault.exe --uninstall» прописан в реестре у прежних версий.

        Убрать этот ключ нельзя: кнопка «Удалить» в «Параметрах» Windows будет
        звать его ещё долго, и она обязана открывать окно, а не молчать.
        """
        strings = " ".join(live_strings(self._entry_tree()))
        self.assertIn("--uninstall", strings)
