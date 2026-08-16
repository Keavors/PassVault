# -*- coding: utf-8 -*-
import unittest
from datetime import datetime, timedelta, timezone

from pvault import model
from pvault.generator import DEFAULT_GEN
from pvault.session import DEFAULT_APP_SETTINGS


class TimestampTest(unittest.TestCase):
    def test_parses_both_formats(self):
        self.assertIsNotNone(model.parse_ts("2026-01-31T11:05:42Z"))
        self.assertIsNotNone(model.parse_ts("2026-01-31 14:05"))      # версия 1.x
        self.assertIsNotNone(model.parse_ts("2026-01-31T14:05:00+03:00"))
        self.assertIsNone(model.parse_ts("не дата"))
        self.assertIsNone(model.parse_ts(None))

    def test_timezone_aware_comparison(self):
        msk = "2026-01-31T14:05:00+03:00"      # 11:05 UTC
        utc = "2026-01-31T12:00:00Z"           # на 55 минут позже
        self.assertTrue(model.is_newer(utc, msk))
        self.assertFalse(model.is_newer(msk, utc))

    def test_seconds_resolution(self):
        self.assertTrue(model.is_newer("2026-01-31T11:05:43Z",
                                       "2026-01-31T11:05:42Z"))

    def test_unparsable_sorts_last(self):
        self.assertTrue(model.is_newer("2026-01-31T11:05:42Z", "мусор"))

    def test_now_iso_roundtrips(self):
        self.assertIsNotNone(model.parse_ts(model.now_iso()))


class NormalizeTest(unittest.TestCase):
    def test_unknown_fields_survive(self):
        """Главная гарантия совместимости: незнакомое поле остаётся в записи."""
        e = {"id": "x", "title": "Т", "totp": "JBSWY3DPEHPK3PXP",
             "tags": ["работа"], "created": "2026-01-01T00:00:00Z",
             "modified": "2026-01-01T00:00:00Z"}
        out = model.normalize_entry(e)
        self.assertEqual(out["totp"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(out["tags"], ["работа"])

    def test_broken_entry_is_repaired_not_fatal(self):
        e = model.normalize_entry({"title": 42})
        self.assertEqual(e["title"], "42")
        self.assertTrue(e["id"])
        self.assertIsNotNone(model.parse_ts(e["created"]))

    def test_non_dict_rejected(self):
        self.assertIsNone(model.normalize_entry("строка"))
        self.assertIsNone(model.normalize_entry(None))

    def test_false_deleted_is_dropped(self):
        e = model.normalize_entry({"id": "x", "deleted": False})
        self.assertNotIn("deleted", e)

    def test_duplicate_ids_are_split(self):
        """Дубликаты id ломают слияние: правки второй записи не доезжают никогда."""
        data = {"version": 1, "entries": [{"id": "same"}, {"id": "same"}]}
        out = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        ids = [e["id"] for e in out["entries"]]
        self.assertEqual(len(set(ids)), 2)

    def test_newer_schema_refused(self):
        with self.assertRaises(ValueError):
            model.normalize_data({"version": 99, "entries": []},
                                 DEFAULT_GEN, DEFAULT_APP_SETTINGS)

    def test_settings_filled_with_defaults(self):
        out = model.normalize_data({"version": 1, "entries": []},
                                   DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.assertIn("use_lower", out["settings"]["generator"])
        self.assertIn("autolock_minutes", out["settings"]["app"])

    def test_partial_generator_settings_are_topped_up(self):
        data = {"version": 1, "entries": [],
                "settings": {"generator": {"exact_len": 18}}}
        out = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.assertEqual(out["settings"]["generator"]["exact_len"], 18)
        self.assertTrue(out["settings"]["generator"]["use_lower"])


class HistoryTest(unittest.TestCase):
    def test_push_and_cap(self):
        e = model.new_entry()
        for i in range(model.MAX_HISTORY + 5):
            model.push_history(e, "пароль-%d" % i)
        self.assertEqual(len(e["history"]), model.MAX_HISTORY)
        self.assertEqual(e["history"][0]["password"],
                         "пароль-%d" % (model.MAX_HISTORY + 4))

    def test_empty_password_not_stored(self):
        e = model.new_entry()
        model.push_history(e, "")
        self.assertNotIn("history", e)

    def test_same_password_not_duplicated(self):
        e = model.new_entry()
        model.push_history(e, "один")
        model.push_history(e, "один")
        self.assertEqual(len(e["history"]), 1)

    def test_touch_records_previous_password(self):
        e = model.new_entry()
        e["password"] = "старый"
        e["password"] = "новый"
        model.touch(e, old_password="старый")
        self.assertEqual(e["history"][0]["password"], "старый")


class TombstoneTest(unittest.TestCase):
    def test_soft_delete_leaves_tombstone(self):
        e = model.new_entry()
        model.soft_delete(e)
        self.assertTrue(e["deleted"])
        model.restore(e)
        self.assertNotIn("deleted", e)

    def test_purge_only_old_ones(self):
        now = datetime.now(timezone.utc)
        old = model.new_entry()
        model.soft_delete(old)
        old["modified"] = (now - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        fresh = model.new_entry()
        model.soft_delete(fresh)
        alive = model.new_entry()

        entries = [old, fresh, alive]
        removed = model.purge_tombstones(entries, now=now)
        self.assertEqual(removed, 1)
        self.assertEqual(len(entries), 2)
        self.assertNotIn(old, entries)

    def test_purge_keeps_live_entries(self):
        entries = [model.new_entry() for _ in range(3)]
        self.assertEqual(model.purge_tombstones(entries), 0)
        self.assertEqual(len(entries), 3)
