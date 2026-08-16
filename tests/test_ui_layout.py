# -*- coding: utf-8 -*-
"""Проверка, что виджеты в окнах не наложены друг на друга.

Дымовые тесты ловят опечатки в именах и сломанные импорты, но окно с двумя
виджетами в одной ячейке сетки они пропускают: собирается оно без ошибок, а
пользователь видит кашу. Такое уже случилось при добавлении настройки очистки
буфера — новая строка сдвинула нумерацию, и поле «Папка резервных копий»
уехало поверх пояснения.

Проверяется занятость ячеек grid: одна ячейка — один виджет.
"""

import os
import shutil
import tempfile
import unittest

try:
    import tkinter as tk
    _TK = True
except Exception:                                    # pragma: no cover
    _TK = False


def _display_available():
    if not _TK:
        return False
    try:
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


HAVE_DISPLAY = _display_available()


def grid_collisions(widget):
    """Ячейки grid, занятые более чем одним виджетом.

    Учитываются columnspan и rowspan: виджет на две колонки занимает обе.
    """
    taken = {}
    clashes = []
    for child in widget.winfo_children():
        try:
            info = child.grid_info()
        except tk.TclError:
            continue
        if not info:
            continue
        row = int(info.get("row", 0))
        col = int(info.get("column", 0))
        rowspan = int(info.get("rowspan", 1))
        colspan = int(info.get("columnspan", 1))
        for r in range(row, row + rowspan):
            for c in range(col, col + colspan):
                if (r, c) in taken:
                    clashes.append(((r, c), taken[(r, c)], str(child)))
                else:
                    taken[(r, c)] = str(child)
    return clashes


def all_collisions(widget):
    out = grid_collisions(widget)
    for child in widget.winfo_children():
        out += all_collisions(child)
    return out


@unittest.skipUnless(HAVE_DISPLAY, "нет графической подсистемы")
class DialogLayoutTest(unittest.TestCase):
    def setUp(self):
        self.root_dir = tempfile.mkdtemp(prefix="pvlay-")
        self.vault_path = os.path.join(self.root_dir, "vault.pmv")
        self.app = None

    def tearDown(self):
        if self.app is not None:
            try:
                self.app.destroy()
            except Exception:
                pass
        shutil.rmtree(self.root_dir, ignore_errors=True)

    def unlocked_app(self):
        from pvault.ui.app import App
        self.app = App(self.vault_path)
        self.app.withdraw()
        self.app._pw1.set("длинная мастер-фраза")
        self.app._pw2.set("длинная мастер-фраза")
        self.app._create()
        self.app.update_idletasks()
        return self.app

    def assert_clean(self, dlg, name):
        dlg.update_idletasks()
        clashes = all_collisions(dlg)
        dlg.destroy()
        self.assertEqual(clashes, [], "в окне «%s» виджеты наложены друг на друга: %s"
                         % (name, clashes))

    # ------------------------------------------------------------------
    def test_settings_dialog_has_no_overlapping_widgets(self):
        from pvault.ui import dialogs
        app = self.unlocked_app()
        dlg = dialogs.SettingsDialog(app, app.vault.app_settings,
                                     app.vault.paths.default_backups)
        self.assert_clean(dlg, "Настройки")

    def test_change_master_dialog_has_no_overlapping_widgets(self):
        from pvault.ui import dialogs
        app = self.unlocked_app()
        self.assert_clean(dialogs.ChangeMasterDialog(app), "Смена мастер-пароля")

    def test_generator_dialog_has_no_overlapping_widgets(self):
        from pvault.ui import dialogs
        app = self.unlocked_app()
        dlg = dialogs.GeneratorDialog(app, app.vault.gen_settings)
        self.assert_clean(dlg, "Генератор паролей")

    def test_conflict_dialog_has_no_overlapping_widgets(self):
        from pvault import merge as mergelib
        from pvault.ui import dialogs
        app = self.unlocked_app()
        local = {"id": "a", "title": "Почта", "login": "u", "password": "L",
                 "url": "", "notes": "", "created": "2026-01-01T00:00:00Z",
                 "modified": "2026-01-01T00:00:00Z"}
        incoming = dict(local, password="I", modified="2026-01-02T00:00:00Z")
        plan = mergelib.plan_merge([local], [incoming])
        dlg = dialogs.ConflictDialog(app, plan.conflicts[0], 1, 1)
        self.assert_clean(dlg, "Расхождение")

    def test_unlock_screen_has_no_overlapping_widgets(self):
        from pvault.ui.app import App
        self.app = App(self.vault_path)
        self.app.withdraw()
        self.app.update_idletasks()
        clashes = all_collisions(self.app)
        self.assertEqual(clashes, [], "на экране входа виджеты наложены: %s" % clashes)
