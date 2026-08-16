# -*- coding: utf-8 -*-
"""Тесты полного цикла работы с хранилищем — то, что раньше жило в классе окна
и не проверялось ничем."""

import os
import shutil
import tempfile
import unittest

from pvault import config, crypto, merge as mergelib, paths as pathsmod
from pvault.session import Vault

PW = "мастер-фраза проверки"


class SessionTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pvsess-")
        self.appdata = os.path.join(self.root, "appdata")
        os.makedirs(self.appdata, exist_ok=True)
        self._old_appdata = os.environ.get("APPDATA")
        os.environ["APPDATA"] = self.appdata

        self.dir = os.path.join(self.root, "vault")
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "vault.pmv")

    def tearDown(self):
        if self._old_appdata is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = self._old_appdata
        shutil.rmtree(self.root, ignore_errors=True)

    # Настоящие 256 МиБ Argon2id в тестах гонять незачем: проверяется формат
    # контейнера и логика вокруг него, а не стойкость самого KDF.
    FAST_ARGON2 = dict(time_cost=1, memory_kib=8 * 1024, parallelism=1)

    def fast_params(self):
        return crypto.KdfParams.new_argon2id(**self.FAST_ARGON2)

    def fresh(self):
        v = Vault(self.path)
        v.create(PW, self.fast_params())
        return v

    def legacy_vault(self, password=PW):
        """Хранилище в старом формате PMVAULT1 — как их писали версии 1.x и 2.x.

        Программа такие файлы больше не создаёт, поэтому изготавливаем вручную:
        проверять переезд на Argon2id не на чем, если старый файл не из чего
        получить.
        """
        v = Vault(self.path)
        v.create(password, crypto.KdfParams.new_pbkdf2(iterations=20_000))
        return v

    def reopen(self, password=PW):
        v = Vault(self.path)
        v.open(password)
        return v

    # ------------------------------------------------------------------
    def test_create_open_roundtrip(self):
        v = self.fresh()
        e = v.new_entry()
        e["title"] = "Почта"
        e["password"] = "секрет"
        v.save()

        again = self.reopen()
        self.assertEqual(len(again.entries), 1)
        self.assertEqual(again.entries[0]["title"], "Почта")
        self.assertEqual(again.entries[0]["password"], "секрет")

    def test_wrong_password_counts_towards_lockout(self):
        self.fresh()
        v = Vault(self.path)
        for _ in range(2):
            with self.assertRaises(crypto.VaultError):
                v.open("неверный")
        self.assertEqual(v.guard.failures(), 2)
        self.assertFalse(v.guard.is_locked())

        with self.assertRaises(crypto.VaultError):
            v.open("неверный")
        self.assertTrue(v.guard.is_locked())

    def test_successful_open_clears_lockout(self):
        self.fresh()
        v = Vault(self.path)
        for _ in range(3):
            with self.assertRaises(crypto.VaultError):
                v.open("неверный")
        self.assertTrue(v.guard.is_locked())
        v.guard.record_success()
        v.open(PW)
        self.assertEqual(v.guard.failures(), 0)

    def test_backups_live_next_to_the_vault_by_default(self):
        """Копии кладутся рядом с хранилищем, а не в профиль пользователя."""
        v = self.fresh()
        v.new_entry()
        v.save()
        v.save()
        v.snapshot("premerge")
        self.assertEqual(sorted(os.listdir(self.dir)),
                         ["vault.pmv", "vault.pmv.prev", "vault_backups"])
        self.assertTrue(os.listdir(os.path.join(self.dir, "vault_backups")))
        self.assertEqual(os.path.normcase(v.paths.backups),
                         os.path.normcase(os.path.join(self.dir, "vault_backups")))

    def test_backup_dir_can_be_moved(self):
        v = self.fresh()
        v.new_entry()
        v.save()
        v.snapshot("premerge")
        before = [os.path.basename(s.path) for s in v.backups.list_snapshots()]
        self.assertTrue(before)

        elsewhere = os.path.join(self.root, "мои копии")
        v.move_backups_to(elsewhere)
        v.save()

        self.assertEqual(os.path.normcase(v.paths.backups),
                         os.path.normcase(elsewhere))
        after = [os.path.basename(s.path) for s in v.backups.list_snapshots()]
        for name in before:
            self.assertIn(name, after)
        self.assertFalse(os.path.isdir(os.path.join(self.dir, "vault_backups")))

    def test_backup_dir_survives_reopen(self):
        v = self.fresh()
        elsewhere = os.path.join(self.root, "копии2")
        v.move_backups_to(elsewhere)
        v.save()

        again = self.reopen()
        self.assertEqual(os.path.normcase(again.paths.backups),
                         os.path.normcase(elsewhere))

    def test_empty_backup_dir_means_default(self):
        v = self.fresh()
        v.move_backups_to(os.path.join(self.dir, "vault_backups"))
        self.assertEqual(v.app_settings["backup_dir"],
                         os.path.join(self.dir, "vault_backups"))
        v.move_backups_to("")
        self.assertEqual(os.path.normcase(v.paths.backups),
                         os.path.normcase(v.paths.default_backups))

    def test_snapshot_captures_unsaved_edits(self):
        """«Снимок перед слиянием» обязан снять то, что на экране, а не то,
        что успело лечь на диск."""
        v = self.fresh()
        e = v.new_entry()
        e["title"] = "До слияния"
        v.mark_dirty()
        snap = v.snapshot("premerge")
        self.assertIsNotNone(snap)

        with open(snap.path, "rb") as f:
            restored = crypto.decrypt_with_key(f.read(), v.key)
        self.assertEqual(restored["entries"][0]["title"], "До слияния")
        self.assertFalse(v.dirty)

    def test_change_password_reencrypts(self):
        v = self.fresh()
        v.new_entry()["title"] = "Х"
        v.save()
        self.assertTrue(v.change_password(PW, "новая длинная фраза"))

        with self.assertRaises(crypto.VaultError):
            Vault(self.path).open(PW)
        again = self.reopen("новая длинная фраза")
        self.assertEqual(len(again.entries), 1)

    def test_change_password_rejects_wrong_current(self):
        v = self.fresh()
        self.assertFalse(v.change_password("не тот", "новый"))
        self.reopen()               # старый пароль всё ещё работает

    # ------------------------------------------------------------------
    # Переезд со старого PBKDF2 на Argon2id
    # ------------------------------------------------------------------
    def test_new_vault_is_argon2(self):
        """Новое хранилище создаётся сильным KDF, а не слабым по умолчанию."""
        v = Vault(self.path)
        v.create(PW)
        self.assertFalse(v.params.is_legacy)
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(8), crypto.MAGIC_V2)

    def test_legacy_vault_still_opens(self):
        """Разбор PMVAULT1 обязан жить вечно.

        Выброси его — и каждое существующее хранилище, каждый .prev и каждый
        снимок в архиве станут нечитаемыми. Это и есть цена «просто убрать
        слабое шифрование».
        """
        v = self.legacy_vault()
        v.new_entry()["title"] = "Ценное"
        v.save()

        again = Vault(self.path)
        again.open(PW)
        self.assertEqual(again.entries[0]["title"], "Ценное")

    def test_legacy_vault_is_upgraded_on_open(self):
        v = self.legacy_vault()
        v.new_entry()["title"] = "Ценное"
        v.save()
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(8), crypto.MAGIC_V1)

        again = Vault(self.path)
        notes = again.open(PW)

        self.assertFalse(again.params.is_legacy, "формат не обновился")
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(8), crypto.MAGIC_V2)
        self.assertTrue(any("Argon2id" in n for n in notes),
                        "пользователю не сказали о переводе: %r" % (notes,))
        self.assertEqual(again.entries[0]["title"], "Ценное")

    def test_upgraded_vault_opens_with_the_same_password(self):
        """Пароль при переезде не меняется — это главное, что важно человеку."""
        v = self.legacy_vault()
        v.new_entry()["title"] = "Ценное"
        v.save()
        Vault(self.path).open(PW)

        after = Vault(self.path)
        after.open(PW)
        self.assertFalse(after.params.is_legacy)
        self.assertEqual(after.entries[0]["title"], "Ценное")

    def test_upgrade_keeps_a_readable_copy_of_the_old_format(self):
        """Снимок перед переездом зашифрован ПРЕЖНИМ способом.

        Если перешифровка не доедет, у человека обязана остаться копия,
        которую можно открыть.
        """
        v = self.legacy_vault()
        v.new_entry()["title"] = "До переезда"
        v.save()

        again = Vault(self.path)
        again.open(PW)

        snaps = [s for s in again.backups.list_snapshots() if s.tag == "preformat"]
        self.assertTrue(snaps, "снимок перед переездом не сделан")
        with open(snaps[0].path, "rb") as f:
            blob = f.read()
        self.assertTrue(blob.startswith(crypto.MAGIC_V1),
                        "копия обязана остаться в старом формате")
        data, _key, _p = crypto.decrypt_vault(blob, PW)
        self.assertEqual(data["entries"][0]["title"], "До переезда")

    def test_upgrade_happens_only_once(self):
        v = self.legacy_vault()
        v.save()
        Vault(self.path).open(PW)

        second = Vault(self.path)
        notes = second.open(PW)
        self.assertFalse(any("Argon2id" in n for n in notes),
                         "переезд повторился на уже обновлённом хранилище")
        self.assertEqual(
            len([s for s in second.backups.list_snapshots()
                 if s.tag == "preformat"]), 1)

    def test_unknown_fields_survive_the_upgrade(self):
        """Переезд не имеет права ничего потерять по дороге."""
        v = self.legacy_vault()
        e = v.new_entry()
        e["title"] = "С полем из будущего"
        e["totp"] = "JBSWY3DPEHPK3PXP"
        v.save()

        again = Vault(self.path)
        again.open(PW)
        self.assertFalse(again.params.is_legacy)
        self.assertEqual(again.entries[0]["totp"], "JBSWY3DPEHPK3PXP")

    def test_first_open_fills_the_empty_archive(self):
        """Архив не должен оставаться пустым до первой правки.

        Иначе из всех резервных копий существует только vault.pmv.prev — шаг
        назад на одно сохранение.
        """
        v = Vault(self.path)
        v.create(PW, self.fast_params())
        for s in v.backups.list_snapshots():
            os.remove(s.path)
        self.assertEqual(v.backups.list_snapshots(), [])

        again = Vault(self.path)
        again.open(PW)
        self.assertTrue(again.backups.list_snapshots(),
                        "после открытия в архиве обязан быть хотя бы один снимок")

    def test_snapshot_is_openable_with_old_password(self):
        """Снимок «перед сменой пароля» зашифрован прежним паролем."""
        v = self.fresh()
        v.new_entry()["title"] = "До смены"
        v.save()
        v.change_password(PW, "новая длинная фраза")

        snaps = [s for s in v.backups.list_snapshots() if s.tag == "prepassword"]
        self.assertTrue(snaps)
        with open(snaps[0].path, "rb") as f:
            data, _k, _p = crypto.decrypt_vault(f.read(), PW)
        self.assertEqual(data["entries"][0]["title"], "До смены")

    def test_restore_from_snapshot_is_a_merge(self):
        """Вернуть вчерашнюю запись, не потеряв сегодняшние."""
        v = self.fresh()
        old = v.new_entry()
        old["title"] = "Вчерашняя"
        v.save()
        snap = v.snapshot("prerestore")

        v.delete_entry(old["id"])
        today = v.new_entry()
        today["title"] = "Сегодняшняя"
        v.save()

        data = v.read_foreign(snap.path)
        plan = v.plan_merge(v.entries_of(data))
        v.apply_merge(plan, [mergelib.INCOMING] * len(plan.conflicts))
        v.save()

        titles = {e["title"] for e in v.entries if not e.get("deleted")}
        self.assertIn("Вчерашняя", titles)
        self.assertIn("Сегодняшняя", titles)

    def test_import_only_adds(self):
        v = self.fresh()
        keep = v.new_entry()
        keep["title"] = "Своя"
        added = v.add_entries([{"id": "x", "title": "Чужая",
                                "created": "2026-01-01T00:00:00Z",
                                "modified": "2026-01-01T00:00:00Z"}])
        self.assertEqual(added, 1)
        self.assertEqual(len(v.entries), 2)
        self.assertEqual(v.entry(keep["id"])["title"], "Своя")

    def test_import_resolves_id_collision(self):
        v = self.fresh()
        mine = v.new_entry()
        v.add_entries([{"id": mine["id"], "title": "Чужая с тем же id"}])
        ids = [e["id"] for e in v.entries]
        self.assertEqual(len(set(ids)), 2)

    def test_recovery_offered_when_vault_vanishes(self):
        v = self.fresh()
        v.new_entry()["title"] = "Ценное"
        v.save()
        v.save()                        # чтобы появилась previous.pmv
        os.remove(self.path)

        found = Vault(self.path).recovery_candidates()
        self.assertTrue(found, "должны найтись копии, а не предложение создать новое")

    def test_recent_vaults_remembered(self):
        self.fresh()
        self.assertEqual(os.path.normcase(config.last_vault()),
                         os.path.normcase(self.path))
        self.assertIn(os.path.normcase(self.path),
                      [os.path.normcase(p) for p in config.recent_vaults()])

    def test_legacy_bak_is_adopted_not_lost(self):
        v = self.fresh()
        v.save()

        shutil.copy2(self.path, self.path + ".bak")
        old_backups = os.path.join(self.dir, "vault_backups")
        os.makedirs(old_backups, exist_ok=True)
        shutil.copy2(self.path, os.path.join(old_backups, "snap-20260101-101010.pmv"))

        reopened = self.reopen()
        self.assertFalse(os.path.exists(self.path + ".bak"))
        snaps = reopened.backups.list_snapshots()
        names = [os.path.basename(s.path) for s in snaps]
        self.assertIn("snap-20260101-101010.pmv", names)
        # Перенесённая копия обязана быть ВИДНА в архиве, а не просто лежать
        # где-то под нераспознаваемым именем.
        self.assertTrue(any(s.tag == "legacybak" for s in snaps))

    def test_backups_from_old_appdata_layout_are_pulled_back(self):
        """Копии, уехавшие в профиль прошлой сборкой, возвращаются к хранилищу."""
        v = self.fresh()
        v.save()
        state = pathsmod.legacy_state_dir(self.path)
        self.assertIsNotNone(state, "на Windows старое место должно вычисляться")
        old_dir = os.path.join(state, "backups")
        os.makedirs(old_dir, exist_ok=True)
        shutil.copy2(self.path, os.path.join(old_dir, "snap-20260101-101010.pmv"))
        shutil.copy2(self.path, os.path.join(state, "previous.pmv"))

        reopened = self.reopen()
        names = [os.path.basename(s.path) for s in reopened.backups.list_snapshots()]
        self.assertIn("snap-20260101-101010.pmv", names)
        self.assertFalse(os.path.isdir(old_dir))
        self.assertFalse(os.path.isdir(state), "старая папка должна исчезнуть")

    def test_nothing_is_written_to_appdata(self):
        """Строгое требование: в профиль пользователя программа не пишет."""
        appdata_vaults = os.path.join(self.appdata, "PassVault")
        v = self.fresh()
        v.new_entry()
        v.save()
        v.snapshot("premerge")
        v.guard.record_failure()
        self.assertFalse(os.path.exists(appdata_vaults),
                         "в %APPDATA% не должно появляться ничего")

    def test_service_files_sit_next_to_the_vault(self):
        v = self.fresh()
        v.new_entry()
        v.save()
        v.save()
        v.guard.record_failure()
        v.lock.acquire()
        names = sorted(os.listdir(self.dir))
        v.lock.release()
        self.assertEqual(names, ["vault.pmv", "vault.pmv.att", "vault.pmv.lock",
                                 "vault.pmv.prev", "vault_backups"])

    def test_purge_only_touches_old_tombstones(self):
        v = self.fresh()
        e = v.new_entry()
        v.delete_entry(e["id"])
        self.assertEqual(v.purge_tombstones(), 0)
        self.assertEqual(len(v.entries), 1)
