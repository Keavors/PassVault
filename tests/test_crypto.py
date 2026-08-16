# -*- coding: utf-8 -*-
import struct
import unittest

from pvault import crypto


SAMPLE = {
    "version": 1,
    "entries": [{"id": "x1", "title": "Тестовая запись", "login": "user",
                 "password": "пАроль Йц1!", "url": "https://e.com",
                 "notes": "заметки ёЁ"}],
    "settings": {"generator": {}, "app": {}},
}


class WriteFormatTest(unittest.TestCase):
    """Программа пишет ровно один формат — PMVAULT2. И читает оба."""

    def test_default_is_argon2(self):
        self.assertFalse(crypto.KdfParams.default().is_legacy)

    def test_create_encrypted_without_params_is_argon2(self):
        """Раньше здесь по умолчанию стоял PBKDF2, и каждое новое хранилище
        получало слабейший из двух вариантов."""
        blob, _key, params = crypto.create_encrypted(SAMPLE, "мастер-фраза")
        self.assertTrue(blob.startswith(crypto.MAGIC_V2))
        self.assertFalse(params.is_legacy)

    def test_legacy_container_is_still_readable(self):
        """Чтение PMVAULT1 обязано жить вечно: иначе все существующие
        хранилища, откаты и снимки в архивах становятся мусором."""
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        blob, _k, _p = crypto.create_encrypted(SAMPLE, "фраза", params)
        self.assertTrue(blob.startswith(crypto.MAGIC_V1))
        back, _k2, p2 = crypto.decrypt_vault(blob, "фраза")
        self.assertEqual(back, SAMPLE)
        self.assertTrue(p2.is_legacy)
        self.assertTrue(p2.needs_upgrade)

    def test_argon2_container_needs_no_upgrade(self):
        params = crypto.KdfParams.new_argon2id(time_cost=1, memory_kib=8 * 1024,
                                               parallelism=1)
        _blob, _k, p = crypto.create_encrypted(SAMPLE, "фраза", params)
        self.assertFalse(p.needs_upgrade)

    def test_container_description_does_not_lie_about_android(self):
        """Три версии подряд программа красным текстом сообщала, что телефон
        PMVAULT2 не откроет. Телефон его открывает — на это есть тесты с обеих
        сторон."""
        argon2 = crypto.KdfParams.new_argon2id()
        legacy = crypto.KdfParams.new_pbkdf2()
        for text in (argon2.describe_container(), legacy.describe_container()):
            self.assertNotIn("Android", text)
            self.assertNotIn("не откроет", text)

    def test_argon2_is_mandatory(self):
        """Без argon2-cffi программа не работает, а не «работает похуже»."""
        self.assertTrue(crypto.argon2_available(),
                        "argon2-cffi обязательна: pip install argon2-cffi")


class ContainerTest(unittest.TestCase):
    def test_roundtrip_v1_keeps_cyrillic(self):
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        blob, key, p = crypto.create_encrypted(SAMPLE, "мастер-фраза", params)
        self.assertTrue(blob.startswith(crypto.MAGIC_V1))
        back, key2, p2 = crypto.decrypt_vault(blob, "мастер-фраза")
        self.assertEqual(back, SAMPLE)
        self.assertEqual(key2, key)
        self.assertEqual(p2.iterations, 20_000)
        self.assertTrue(p2.is_legacy)

    def test_wrong_password_rejected(self):
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        blob, _k, _p = crypto.create_encrypted(SAMPLE, "правильная", params)
        for bad in ("правильная2", "", "ПРАВИЛЬНАЯ"):
            with self.assertRaises(crypto.VaultError):
                crypto.decrypt_vault(blob, bad)

    def test_tampering_detected(self):
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        blob, _k, _p = crypto.create_encrypted(SAMPLE, "фраза", params)
        broken = bytearray(blob)
        broken[-1] ^= 0xFF
        with self.assertRaises(crypto.VaultError):
            crypto.decrypt_vault(bytes(broken), "фраза")

    def test_garbage_rejected(self):
        for junk in (b"", b"not a vault at all", b"PMVAULT1short"):
            with self.assertRaises(crypto.VaultError):
                crypto.parse_container(junk)

    def test_absurd_iterations_rejected(self):
        """Заголовок с максимальным uint32 замораживал программу на минуты."""
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        blob, _k, _p = crypto.create_encrypted(SAMPLE, "фраза", params)
        evil = bytearray(blob)
        evil[8:12] = struct.pack(">I", 0xFFFFFFFF)
        with self.assertRaises(crypto.VaultError) as ctx:
            crypto.parse_container(bytes(evil))
        self.assertIn("итераций", str(ctx.exception))

    def test_oversized_file_rejected(self):
        with self.assertRaises(crypto.VaultError):
            crypto.parse_container(b"\0" * (crypto.MAX_VAULT_BYTES + 1))

    def test_decrypt_with_key_skips_kdf(self):
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        blob, key, _p = crypto.create_encrypted(SAMPLE, "фраза", params)
        self.assertEqual(crypto.decrypt_with_key(blob, key), SAMPLE)
        with self.assertRaises(crypto.VaultError):
            crypto.decrypt_with_key(blob, b"\0" * 32)

    def test_key_matches_is_exact(self):
        params = crypto.KdfParams.new_pbkdf2(iterations=20_000)
        _blob, key, p = crypto.create_encrypted(SAMPLE, "фраза", params)
        self.assertTrue(crypto.key_matches("фраза", key, p))
        self.assertFalse(crypto.key_matches("не фраза", key, p))

    def test_serialize_is_canonical(self):
        """Отпечаток содержимого не должен зависеть от порядка ключей."""
        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        self.assertEqual(crypto.serialize(a), crypto.serialize(b))


class Argon2Test(unittest.TestCase):
    # Пропуска по «argon2-cffi не установлена» здесь больше нет: это
    # единственный формат записи, и если библиотеки нет — тесты обязаны
    # падать, а не молча пропускаться.
    #
    # Параметры уменьшены: настоящие 256 МиБ в тестах ни к чему.
    def params(self):
        return crypto.KdfParams.new_argon2id(time_cost=1, memory_kib=8 * 1024,
                                             parallelism=1)

    def test_roundtrip_v2(self):
        blob, _k, p = crypto.create_encrypted(SAMPLE, "фраза", self.params())
        self.assertTrue(blob.startswith(crypto.MAGIC_V2))
        self.assertFalse(p.is_legacy)
        back, _k2, p2 = crypto.decrypt_vault(blob, "фраза")
        self.assertEqual(back, SAMPLE)
        self.assertEqual(p2.time_cost, 1)
        self.assertEqual(p2.memory_kib, 8 * 1024)
        self.assertEqual(p2.parallelism, 1)

    def test_v2_wrong_password(self):
        blob, _k, _p = crypto.create_encrypted(SAMPLE, "фраза", self.params())
        with self.assertRaises(crypto.VaultError):
            crypto.decrypt_vault(blob, "другая")

    def test_absurd_memory_rejected(self):
        blob, _k, _p = crypto.create_encrypted(SAMPLE, "фраза", self.params())
        evil = bytearray(blob)
        evil[13:17] = struct.pack(">I", 0xFFFFFFFF)
        with self.assertRaises(crypto.VaultError) as ctx:
            crypto.parse_container(bytes(evil))
        self.assertIn("памяти", str(ctx.exception))

    def test_real_world_2_0_parameters_open(self):
        """Файлы версии 2.0 писались с 3/256 МиБ/4 — они обязаны открываться."""
        p = crypto.KdfParams(crypto.KDF_ARGON2ID, b"\x01" * 16,
                             time_cost=3, memory_kib=256 * 1024, parallelism=4)
        header = crypto._header(p)
        parsed, _nonce, _ct = crypto.parse_container(
            header + b"\x02" * crypto.NONCE_LEN + b"\x03" * 32)
        self.assertEqual(parsed.time_cost, 3)
        self.assertEqual(parsed.memory_kib, 256 * 1024)
        self.assertEqual(parsed.parallelism, 4)
