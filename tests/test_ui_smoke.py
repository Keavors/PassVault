# -*- coding: utf-8 -*-
"""Дымовые тесты интерфейса.

Окна тут не нажимаются — проверяется, что они вообще собираются: импорты на
месте, имена виджетов не разъехались, обработчики привязываются. Этого хватает,
чтобы опечатка в интерфейсе падала на сборке, а не при первом запуске у
пользователя.
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


@unittest.skipUnless(HAVE_DISPLAY, "нет графической подсистемы")
class UiSmokeTest(unittest.TestCase):
    def setUp(self):
        self.root_dir = tempfile.mkdtemp(prefix="pvui-")
        self.appdata = os.path.join(self.root_dir, "appdata")
        os.makedirs(self.appdata, exist_ok=True)
        self._old = os.environ.get("APPDATA")
        os.environ["APPDATA"] = self.appdata
        self.vault_path = os.path.join(self.root_dir, "vault.pmv")
        self.app = None

    def tearDown(self):
        if self.app is not None:
            try:
                self.app.destroy()
            except Exception:
                pass
        if self._old is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = self._old
        shutil.rmtree(self.root_dir, ignore_errors=True)

    def make_app(self):
        from pvault.ui.app import App
        self.app = App(self.vault_path)
        self.app.withdraw()
        self.app.update_idletasks()
        return self.app

    # ------------------------------------------------------------------
    def test_unlock_screen_builds(self):
        app = self.make_app()
        self.assertEqual(os.path.normcase(app.vault.path),
                         os.path.normcase(self.vault_path))
        self.assertFalse(app.vault.is_open)

    def test_encryption_format_is_not_offered_as_a_choice(self):
        """Кнопки «Формат шифрования» быть не должно, как и самого окна."""
        from pvault.ui import app as appmod
        from pvault.ui import dialogs

        self.assertFalse(hasattr(dialogs, "FormatDialog"))
        self.assertFalse(hasattr(appmod.App, "change_format"))
        self.assertNotIn("FormatDialog", dialogs.__all__)

    def test_new_vault_is_argon2(self):
        """Хранилище, созданное через интерфейс, — сразу PMVAULT2."""
        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()
        self.assertFalse(app.vault.params.is_legacy)
        with open(self.vault_path, "rb") as f:
            self.assertEqual(f.read(8), b"PMVAULT2")

    def test_create_and_main_screen_builds(self):
        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()
        app.update_idletasks()
        self.assertTrue(app.vault.is_open)
        self.assertTrue(os.path.isfile(self.vault_path))

        app.new_entry()
        app.title_var.set("Почта")
        app.pass_var.set("секрет")
        app._on_field_change()
        app.update_idletasks()
        self.assertEqual(app.vault.entries[0]["title"], "Почта")

        self.assertTrue(app.flush_now())
        app.refresh_list()
        self.assertEqual(len(app.view_ids), 1)

    def test_search_filters_list(self):
        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()
        for title in ("Почта", "Банк", "Форум"):
            e = app.vault.new_entry()
            e["title"] = title
        app.refresh_list()
        self.assertEqual(len(app.view_ids), 3)
        app.search_var.set("бан")
        app.refresh_list()
        self.assertEqual(len(app.view_ids), 1)

    def test_password_history_committed_on_leaving_entry(self):
        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()
        app.new_entry()
        app.pass_var.set("первый")
        app._on_field_change()
        app._commit_password_history()          # уход с записи не менял пароль
        app.pass_var.set("второй")
        app._on_field_change()
        app._commit_password_history()
        history = app.vault.entries[0].get("history") or []
        self.assertIn("первый", [h["password"] for h in history])

    def test_lock_returns_to_unlock_screen(self):
        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()
        app.lock()
        app.update_idletasks()
        self.assertFalse(app.vault.is_open)

    def test_dialogs_construct(self):
        """Каждое окно должно хотя бы собираться без ошибок."""
        from pvault import merge as mergelib
        from pvault.ui import dialogs

        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()

        local = {"id": "a", "title": "Почта", "login": "u", "password": "L",
                 "url": "", "notes": "", "created": "2026-01-01T00:00:00Z",
                 "modified": "2026-01-01T00:00:00Z"}
        incoming = dict(local, password="I", modified="2026-01-02T00:00:00Z")
        plan = mergelib.plan_merge([local], [incoming])

        built = [
            dialogs.GeneratorDialog(app, app.vault.gen_settings),
            dialogs.MergePreviewDialog(app, plan, "тест.pmv"),
            dialogs.ConflictDialog(app, plan.conflicts[0], 1, 1),
            dialogs.TrashDialog(app, app.vault.entries, lambda _m: None),
            dialogs.HistoryDialog(app, local),
            dialogs.BackupDialog(app, app.vault.backups, lambda: None),
            dialogs.ChangeMasterDialog(app),
            # FormatDialog здесь больше нет: окна «Формат шифрования» не
            # существует, выбирать между PBKDF2 и Argon2id больше не из чего.
            dialogs.SettingsDialog(app, app.vault.app_settings,
                                   app.vault.paths.default_backups),
        ]
        for dlg in built:
            dlg.update_idletasks()
            dlg.destroy()

    # ------------------------------------------------------------------
    # Буфер обмена
    # ------------------------------------------------------------------
    def unlocked_app(self):
        app = self.make_app()
        app._pw1.set("длинная мастер-фраза")
        app._pw2.set("длинная мастер-фраза")
        app._create()
        return app

    def test_copied_password_is_scheduled_for_erasure(self):
        """Раньше пароль оставался в буфере обмена навсегда."""
        app = self.unlocked_app()
        app.copy_secret("секретный пароль")
        app.update_idletasks()

        self.assertEqual(app.clipboard_get(), "секретный пароль")
        self.assertIsNotNone(app._clip_job, "будильник на очистку не заведён")

    def test_erasure_clears_our_own_secret(self):
        app = self.unlocked_app()
        app.copy_secret("секретный пароль")
        app.update_idletasks()

        app._clear_clipboard("секретный пароль")     # как будто время вышло
        app.update_idletasks()
        with self.assertRaises(tk.TclError):
            app.clipboard_get()

    def test_erasure_does_not_touch_what_the_user_copied_later(self):
        """За эти секунды человек мог скопировать своё — стирать чужое нельзя."""
        app = self.unlocked_app()
        app.copy_secret("секретный пароль")
        app.update_idletasks()

        app.clipboard_clear()
        app.clipboard_append("список покупок")
        app.update_idletasks()

        app._clear_clipboard("секретный пароль")
        app.update_idletasks()
        self.assertEqual(app.clipboard_get(), "список покупок")

    def test_erasure_can_be_switched_off(self):
        app = self.unlocked_app()
        app.vault.app_settings["clipboard_seconds"] = 0
        app.copy_secret("секретный пароль")
        app.update_idletasks()

        self.assertEqual(app.clipboard_get(), "секретный пароль")
        self.assertIsNone(app._clip_job, "при 0 очистка не назначается")

    def test_recovery_dialog_builds(self):
        from pvault.storage import Candidate
        from pvault.ui import dialogs

        app = self.make_app()
        probe = os.path.join(self.root_dir, "snap.pmv")
        with open(probe, "wb") as f:
            f.write(b"PMVAULT1" + b"\0" * 60)
        dlg = dialogs.RecoveryDialog(
            app, self.vault_path,
            [Candidate(probe, "snapshot", "снимок из архива")])
        dlg.update_idletasks()
        dlg.destroy()
