# -*- coding: utf-8 -*-
r"""Совместимость с Android-версией — на настоящих файлах, в обе стороны.

Расхождение форматов между устройствами не падает с ошибкой: оно молча
съедает данные при каждой синхронизации. Поэтому проверяется не «мы думаем,
что формат тот же», а конкретные файлы, записанные другой стороной.

ПК → Android
    Эталон пишет tools/make_android_fixture.py, читает его тест
    PcCompatibilityTest в Android-проекте.

Android → ПК
    Android-тест PcCompatibilityTest.writesFileForPcToRead кладёт файл в
    app\build\interop\android_vault.pmv, и его читают тесты ниже.

Если Android-тесты не запускали, проверки пропускаются: сборка ПК не должна
зависеть от наличия Android-тулчейна.
"""

import os
import unittest

from pvault import crypto, model
from pvault.generator import DEFAULT_GEN
from pvault.session import DEFAULT_APP_SETTINGS

# Путь к Android-проекту можно задать переменной PASSVAULT_ANDROID_PROJECT.
# Раньше он был жёстко вшит и работал ровно на одной машине.
ANDROID_PROJECT = os.environ.get("PASSVAULT_ANDROID_PROJECT",
                                 r"D:\vscode_projects\PassVaultAndroid")
ANDROID_FILE = os.path.join(ANDROID_PROJECT, "app", "build", "interop",
                            "android_vault.pmv")
ANDROID_PASSWORD = "тестовая мастер-фраза"


@unittest.skipUnless(os.path.isfile(ANDROID_FILE),
                     "Android-тесты не запускались — файла обмена нет")
class AndroidToPcTest(unittest.TestCase):
    """Читаем файл, записанный кодом телефона."""

    def setUp(self):
        with open(ANDROID_FILE, "rb") as f:
            self.blob = f.read()

    def test_opens_and_is_argon2_container(self):
        """Телефон, как и ПК, пишет только PMVAULT2."""
        self.assertTrue(self.blob.startswith(crypto.MAGIC_V2),
                        "телефон обязан писать PMVAULT2")
        data, _key, params = crypto.decrypt_vault(self.blob, ANDROID_PASSWORD)
        self.assertEqual(data.get("version"), 1)
        self.assertFalse(params.is_legacy)
        self.assertFalse(params.needs_upgrade)

    def test_entries_normalize_without_loss(self):
        data, _key, _p = crypto.decrypt_vault(self.blob, ANDROID_PASSWORD)
        out = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.assertTrue(out["entries"])
        for e in out["entries"]:
            self.assertTrue(e["id"])
            self.assertIsNotNone(model.parse_ts(e["modified"]),
                                 "метка времени с телефона должна разбираться")

    def test_phone_history_is_understood(self):
        data, _key, _p = crypto.decrypt_vault(self.blob, ANDROID_PASSWORD)
        out = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        with_history = [e for e in out["entries"] if e.get("history")]
        self.assertTrue(with_history, "запись с историей паролей ожидалась")
        self.assertTrue(with_history[0]["history"][0]["password"])

    def test_phone_tombstone_is_understood(self):
        data, _key, _p = crypto.decrypt_vault(self.blob, ANDROID_PASSWORD)
        out = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.assertTrue(any(e.get("deleted") for e in out["entries"]),
                        "надгробие с телефона должно распознаваться")

    def test_settings_from_phone_survive(self):
        data, _key, _p = crypto.decrypt_vault(self.blob, ANDROID_PASSWORD)
        out = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.assertIn("autolock_minutes", out["settings"]["app"])


class FixtureShapeTest(unittest.TestCase):
    """Эталон для Android собирается тем же кодом, что и настоящие файлы."""

    def test_fixture_builds_and_roundtrips(self):
        import importlib.util
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(here, "tools", "make_android_fixture.py")
        spec = importlib.util.spec_from_file_location("mkfix", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        data = mod.build_data()
        params = crypto.KdfParams.new_argon2id(**mod.FAST_ARGON2)
        blob, _key, _p = crypto.create_encrypted(data, mod.PASSWORD, params)
        back, _k, _p2 = crypto.decrypt_vault(blob, mod.PASSWORD)

        self.assertEqual(len(back["entries"]), 3)
        first = back["entries"][0]
        self.assertIn("future_field", first)
        self.assertEqual(len(first["history"]), 2)
        self.assertTrue(any(e.get("deleted") for e in back["entries"]))
        # Старый формат метки времени обязан оставаться читаемым.
        legacy = next(e for e in back["entries"] if e["id"] == "cccc3333dddd4444")
        self.assertIsNotNone(model.parse_ts(legacy["modified"]))

    def test_unknown_field_survives_our_own_normalization(self):
        import importlib.util
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(here, "tools", "make_android_fixture.py")
        spec = importlib.util.spec_from_file_location("mkfix", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        out = model.normalize_data(mod.build_data(), DEFAULT_GEN,
                                   DEFAULT_APP_SETTINGS)
        first = next(e for e in out["entries"] if e["id"] == "aaaa1111bbbb2222")
        self.assertEqual(first["future_field"]["nested"], [1, 2, 3])
