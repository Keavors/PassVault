# -*- coding: utf-8 -*-
import os
import shutil
import tempfile
import unittest

from pvault import crypto, storage
from pvault.paths import VaultPaths

PW = "мастер-фраза проверки"


def sample(marker="ценное"):
    return {"version": 1, "entries": [{"id": "a1", "title": "Почта",
                                       "password": marker}],
            "settings": {}}


class TempVault(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pvtest-")
        self.side = tempfile.mkdtemp(prefix="pvside-")
        self.vault = os.path.join(self.dir, "vault.pmv")
        self.prev = os.path.join(self.side, "previous.pmv")
        self.params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        self.key = crypto.derive_key(PW, self.params)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.side, ignore_errors=True)

    def blob(self, marker):
        return crypto.encrypt_with_key(sample(marker), self.key, self.params)

    def write(self, marker, **kw):
        storage.atomic_write(self.vault, self.blob(marker),
                             verify_key=self.key, prev_path=self.prev, **kw)

    def content(self, path):
        with open(path, "rb") as f:
            return crypto.decrypt_with_key(f.read(), self.key)


class AtomicWriteTest(TempVault):
    def test_first_write_has_no_previous(self):
        self.write("первый")
        self.assertTrue(os.path.isfile(self.vault))
        self.assertFalse(os.path.exists(self.prev))

    def test_second_write_keeps_previous(self):
        self.write("первый")
        self.write("второй")
        self.assertEqual(self.content(self.vault)["entries"][0]["password"], "второй")
        self.assertEqual(self.content(self.prev)["entries"][0]["password"], "первый")

    def test_no_leftovers_next_to_vault(self):
        """Рядом с хранилищем не должно оставаться ничего служебного."""
        self.write("первый")
        self.write("второй")
        self.assertEqual(os.listdir(self.dir), ["vault.pmv"])

    def test_corrupted_write_is_rejected_and_original_survives(self):
        self.write("ценное")
        garbage = crypto.MAGIC_V1 + b"\x00\x00\x4e\x20" + b"\x00" * 200
        with self.assertRaises(storage.StorageError):
            storage.atomic_write(self.vault, garbage, verify_key=self.key,
                                 prev_path=self.prev)
        self.assertEqual(self.content(self.vault)["entries"][0]["password"], "ценное")
        self.assertFalse(os.path.exists(self.vault + ".tmp"))


class SurviveCrashTest(TempVault):
    """Тест, которого не было, — и потому баг с потерей данных дожил до релиза.

    Питание «выдёргивается» в каждой точке записи. Требование во всех случаях
    одно: хранилище остаётся читаемым, и уж точно не исчезает.
    """

    class Boom(Exception):
        pass

    def crash_at(self, step, marker="второй"):
        def explode():
            raise self.Boom()
        with self.assertRaises(self.Boom):
            self.write(marker, hooks={step: explode})

    def test_crash_after_tmp(self):
        self.write("первый")
        self.crash_at("after_tmp")
        self.assertTrue(os.path.isfile(self.vault))
        self.assertEqual(self.content(self.vault)["entries"][0]["password"], "первый")

    def test_crash_after_verify(self):
        self.write("первый")
        self.crash_at("after_verify")
        self.assertTrue(os.path.isfile(self.vault))
        self.assertEqual(self.content(self.vault)["entries"][0]["password"], "первый")

    def test_crash_after_prev_copy(self):
        """Самое опасное место: старый порядок записи здесь терял vault.pmv."""
        self.write("первый")
        self.crash_at("after_prev")
        self.assertTrue(os.path.isfile(self.vault))
        self.assertEqual(self.content(self.vault)["entries"][0]["password"], "первый")
        self.assertEqual(self.content(self.prev)["entries"][0]["password"], "первый")

    def test_new_data_recoverable_from_tmp_after_crash(self):
        """Даже недописанное сохранение остаётся кандидатом на восстановление."""
        self.write("первый")
        self.crash_at("after_verify", marker="второй")
        os.remove(self.vault)
        paths = VaultPaths(self.vault)
        paths.prev = self.prev
        paths.backups = os.path.join(self.side, "backups")
        found = storage.recovery_candidates(self.vault, paths)
        markers = {self.content(c.path)["entries"][0]["password"] for c in found}
        self.assertIn("второй", markers)


class RecoveryTest(TempVault):
    def paths(self):
        p = VaultPaths(self.vault)
        p.prev = self.prev
        p.backups = os.path.join(self.side, "backups")
        return p

    def test_candidates_found_when_vault_disappears(self):
        self.write("первый")
        self.write("второй")
        os.remove(self.vault)
        found = storage.recovery_candidates(self.vault, self.paths())
        self.assertTrue(found)
        self.assertEqual(self.content(found[0].path)["entries"][0]["password"], "первый")

    def test_foreign_files_ignored(self):
        with open(self.prev, "w", encoding="utf-8") as f:
            f.write("это не хранилище")
        self.assertEqual(storage.recovery_candidates(self.vault, self.paths()), [])

    def test_legacy_sidecars_are_still_offered(self):
        """Копии от версий 1.x лежат рядом с файлом — их нельзя не заметить."""
        self.write("первый")
        shutil.copy2(self.vault, self.vault + ".bak")
        os.remove(self.vault)
        found = storage.recovery_candidates(self.vault, self.paths())
        self.assertTrue(any(c.kind == "bak" for c in found))

    def test_snapshots_are_offered(self):
        self.write("первый")
        backups = os.path.join(self.side, "backups")
        os.makedirs(backups, exist_ok=True)
        shutil.copy2(self.vault, os.path.join(backups, "snap-20260101-101010.pmv"))
        os.remove(self.vault)
        found = storage.recovery_candidates(self.vault, self.paths())
        self.assertTrue(any(c.kind == "snapshot" for c in found))


class LockTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pvlock-")
        self.path = os.path.join(self.dir, "vault.lock")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_acquire_and_release(self):
        lock = storage.VaultLock(self.path)
        self.assertTrue(lock.acquire())
        self.assertTrue(os.path.isfile(self.path))
        lock.release()
        self.assertFalse(os.path.exists(self.path))

    def test_second_holder_is_refused(self):
        first = storage.VaultLock(self.path)
        first.acquire()
        second = storage.VaultLock(self.path)
        with self.assertRaises(storage.AlreadyLocked):
            second.acquire()
        first.release()

    def test_stale_lock_is_reclaimed(self):
        """После падения программы хранилище не должно остаться запертым."""
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("999999\nмёртвый-хост\n")
        lock = storage.VaultLock(self.path)
        self.assertTrue(lock.acquire())
        lock.release()

    def test_force_takes_over(self):
        first = storage.VaultLock(self.path)
        first.acquire()
        second = storage.VaultLock(self.path)
        self.assertTrue(second.force())
        second.release()
