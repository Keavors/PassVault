# -*- coding: utf-8 -*-
import unittest

from pvault import merge as mergelib
from pvault import model


def entry(eid, title, password, modified, deleted=False, history=None):
    e = {"id": eid, "title": title, "login": "", "password": password,
         "url": "", "notes": "", "created": "2026-01-01T00:00:00Z",
         "modified": modified}
    if deleted:
        e["deleted"] = True
    if history:
        e["history"] = history
    return e


class PlanTest(unittest.TestCase):
    def test_plan_and_apply(self):
        local = [
            entry("same", "Одинаковая", "pw", "2026-01-02T10:00:00Z"),
            entry("conf", "Почта", "OLD", "2026-01-03T10:00:00Z"),
            entry("onlyLocal", "Только тут", "1", "2026-01-01T10:00:00Z"),
        ]
        incoming = [
            entry("same", "Одинаковая", "pw", "2026-01-04T11:00:00Z"),
            entry("conf", "Почта", "NEW", "2026-01-04T10:00:00Z"),
            entry("onlyIncoming", "С телефона", "2", "2026-01-06T10:00:00Z"),
        ]
        plan = mergelib.plan_merge(local, incoming)
        self.assertEqual([e["id"] for e in plan.to_add], ["onlyIncoming"])
        self.assertEqual([c.local["id"] for c in plan.conflicts], ["conf"])
        self.assertEqual(plan.conflicts[0].suggestion(), mergelib.INCOMING)

        stats = mergelib.apply_merge(local, plan, plan.suggestions())
        self.assertEqual(stats["added"], 1)
        self.assertEqual(stats["took_incoming"], 1)
        self.assertEqual(next(e for e in local if e["id"] == "conf")["password"], "NEW")

    def test_identical_content_is_not_a_conflict(self):
        """Разные даты правки при одинаковом содержимом — не повод спрашивать."""
        local = [entry("a", "А", "1", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "А", "1", "2026-06-01T00:00:00Z")]
        self.assertTrue(mergelib.plan_merge(local, incoming).is_empty)

    def test_second_pass_is_clean(self):
        local = [entry("a", "А", "1", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "А", "2", "2026-01-02T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, plan.suggestions())
        again = mergelib.plan_merge(local, [dict(e) for e in local])
        self.assertTrue(again.is_empty)

    def test_keep_both_makes_distinct_copy(self):
        local = [entry("a", "А", "1", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "А", "2", "2026-01-02T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, [mergelib.BOTH])
        self.assertEqual(len(local), 2)
        self.assertNotEqual(local[0]["id"], local[1]["id"])
        self.assertTrue(local[1]["title"].endswith("(копия)"))
        self.assertEqual(local[1]["password"], "2")

    def test_deletion_propagates(self):
        local = [entry("a", "А", "1", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "А", "1", "2026-01-05T00:00:00Z", deleted=True)]
        plan = mergelib.plan_merge(local, incoming)
        self.assertEqual(len(plan.conflicts), 1)
        mergelib.apply_merge(local, plan, plan.suggestions())
        self.assertTrue(local[0]["deleted"])

    def test_same_timestamp_is_flagged_ambiguous(self):
        local = [entry("a", "А", "1", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "Б", "2", "2026-01-01T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        self.assertTrue(plan.conflicts[0].same_timestamp)
        self.assertEqual(plan.ambiguous_count, 1)

    def test_decision_count_must_match(self):
        local = [entry("a", "А", "1", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "А", "2", "2026-01-02T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        with self.assertRaises(ValueError):
            mergelib.apply_merge(local, plan, [])

    def test_duplicate_ids_inside_the_incoming_file_are_split(self):
        """Две записи с одним id в чужом файле нельзя принимать как есть.

        Раньше добавлялись обе, и дальше они затеняли друг друга при каждой
        синхронизации: правка на втором устройстве не доезжала никогда, и
        понять почему было невозможно.
        """
        local = []
        incoming = [entry("dup", "Первая", "1", "2026-01-01T00:00:00Z"),
                    entry("dup", "Вторая", "2", "2026-01-02T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, plan.suggestions())

        self.assertEqual(len(local), 2)
        self.assertEqual(len({e["id"] for e in local}), 2,
                         "в хранилище оказались две записи с одним id")
        self.assertEqual({e["title"] for e in local}, {"Первая", "Вторая"})

    def test_duplicate_id_does_not_collide_with_local(self):
        local = [entry("dup", "Своя", "L", "2026-01-01T00:00:00Z")]
        incoming = [entry("dup", "Чужая", "I", "2026-01-02T00:00:00Z"),
                    entry("dup", "Чужая вторая", "I2", "2026-01-03T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, plan.suggestions())

        ids = [e["id"] for e in local]
        self.assertEqual(len(ids), len(set(ids)))

    def test_incoming_dict_is_not_mutated(self):
        """Чужой словарь правим не на месте: он может быть чьим-то ещё."""
        incoming_first = entry("dup", "Первая", "1", "2026-01-01T00:00:00Z")
        incoming_second = entry("dup", "Вторая", "2", "2026-01-02T00:00:00Z")
        mergelib.plan_merge([], [incoming_first, incoming_second])
        self.assertEqual(incoming_second["id"], "dup")

    def test_entry_without_id_is_skipped(self):
        local = []
        incoming = [{"title": "без id"}]
        self.assertTrue(mergelib.plan_merge(local, incoming).is_empty)


class HistoryOnMergeTest(unittest.TestCase):
    """Единственный штатный путь, на котором пароль раньше пропадал бесследно."""

    def test_taking_incoming_saves_local_password_to_history(self):
        local = [entry("a", "Почта", "ЛОКАЛЬНЫЙ", "2026-01-01T00:00:00Z")]
        incoming = [entry("a", "Почта", "ИЗ_ФАЙЛА", "2026-01-02T00:00:00Z")]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, [mergelib.INCOMING])

        self.assertEqual(local[0]["password"], "ИЗ_ФАЙЛА")
        passwords = [h["password"] for h in local[0].get("history", [])]
        self.assertIn("ЛОКАЛЬНЫЙ", passwords)

    def test_histories_are_merged_not_dropped(self):
        local = [entry("a", "Почта", "L", "2026-01-01T00:00:00Z",
                       history=[{"password": "старый-локальный",
                                 "changed": "2025-12-01T00:00:00Z"}])]
        incoming = [entry("a", "Почта", "I", "2026-01-02T00:00:00Z",
                          history=[{"password": "старый-входящий",
                                    "changed": "2025-11-01T00:00:00Z"}])]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, [mergelib.INCOMING])

        passwords = [h["password"] for h in local[0]["history"]]
        self.assertIn("старый-локальный", passwords)
        self.assertIn("старый-входящий", passwords)
        self.assertIn("L", passwords)

    def test_keeping_local_still_absorbs_incoming_history(self):
        local = [entry("a", "Почта", "L", "2026-01-02T00:00:00Z")]
        incoming = [entry("a", "Почта", "I", "2026-01-01T00:00:00Z",
                          history=[{"password": "чужой-прошлый",
                                    "changed": "2025-11-01T00:00:00Z"}])]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, [mergelib.LOCAL])

        self.assertEqual(local[0]["password"], "L")
        self.assertIn("чужой-прошлый",
                      [h["password"] for h in local[0]["history"]])

    def test_history_stays_capped(self):
        hist_a = [{"password": "a%d" % i, "changed": "2025-01-%02dT00:00:00Z" % (i + 1)}
                  for i in range(10)]
        hist_b = [{"password": "b%d" % i, "changed": "2024-01-%02dT00:00:00Z" % (i + 1)}
                  for i in range(10)]
        local = [entry("a", "П", "L", "2026-01-01T00:00:00Z", history=hist_a)]
        incoming = [entry("a", "П", "I", "2026-01-02T00:00:00Z", history=hist_b)]
        plan = mergelib.plan_merge(local, incoming)
        mergelib.apply_merge(local, plan, [mergelib.INCOMING])
        self.assertLessEqual(len(local[0]["history"]), model.MAX_HISTORY)

    def test_incoming_unknown_fields_survive(self):
        local = [entry("a", "П", "L", "2026-01-01T00:00:00Z")]
        inc = entry("a", "П", "I", "2026-01-02T00:00:00Z")
        inc["totp"] = "SECRET"
        plan = mergelib.plan_merge(local, [inc])
        mergelib.apply_merge(local, plan, [mergelib.INCOMING])
        self.assertEqual(local[0]["totp"], "SECRET")
        self.assertEqual(local[0]["id"], "a")
