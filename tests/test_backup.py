# -*- coding: utf-8 -*-
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

from pvault import backup


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="pvbak-")
        self.mgr = backup.BackupManager(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def fabricate(self, at, tag=None):
        os.makedirs(self.dir, exist_ok=True)
        name = "snap-%s%s.pmv" % (at.strftime("%Y%m%d-%H%M%S"),
                                  ("-" + tag) if tag else "")
        with open(os.path.join(self.dir, name), "wb") as f:
            f.write(b"PMVAULT1" + b"\0" * 60)

    # ------------------------------------------------------------------
    def test_digest_depends_on_content_not_key_order(self):
        self.assertEqual(backup.plaintext_digest({"a": 1, "b": 2}),
                         backup.plaintext_digest({"b": 2, "a": 1}))
        self.assertNotEqual(backup.plaintext_digest({"a": 1}),
                            backup.plaintext_digest({"a": 2}))

    def test_snapshot_written_from_given_bytes(self):
        blob = b"PMVAULT1" + b"\x11" * 60
        snap = self.mgr.write_snapshot(blob, "digest-1", tag="premerge")
        self.assertIsNotNone(snap)
        with open(snap.path, "rb") as f:
            self.assertEqual(f.read(), blob)
        self.assertTrue(snap.is_event)
        self.assertIn("перед слиянием", snap.label())

    def test_two_events_in_one_second_do_not_collide(self):
        now = datetime(2026, 8, 8, 12, 0, 0)
        a = self.mgr.write_snapshot(b"PMVAULT1" + b"\0" * 60, "d1",
                                    tag="premerge", now=now)
        b = self.mgr.write_snapshot(b"PMVAULT1" + b"\1" * 60, "d2",
                                    tag="premerge", now=now)
        self.assertNotEqual(a.path, b.path)
        self.assertEqual(len(self.mgr.list_snapshots()), 2)

    def test_unchanged_content_makes_no_snapshot(self):
        blob = b"PMVAULT1" + b"\0" * 60
        self.assertIsNotNone(self.mgr.maybe_snapshot(blob, "same"))
        self.assertIsNone(self.mgr.maybe_snapshot(blob, "same"))

    def test_interval_throttles_snapshots(self):
        now = datetime(2026, 8, 8, 12, 0, 0)
        blob = b"PMVAULT1" + b"\0" * 60
        self.assertIsNotNone(self.mgr.maybe_snapshot(blob, "d1", now=now))
        self.assertIsNone(self.mgr.maybe_snapshot(blob, "d2",
                                                  now=now + timedelta(seconds=30)))
        self.assertIsNotNone(self.mgr.maybe_snapshot(blob, "d3",
                                                     now=now + timedelta(minutes=6)))

    def test_event_snapshot_keeps_digest_in_sync(self):
        """Событийный снимок не должен «съедать» следующий штатный.

        Прошлая версия писала отпечаток из памяти, а файл копировала с диска;
        после этого ближайшее сохранение решало, что менять нечего.
        """
        now = datetime(2026, 8, 8, 12, 0, 0)
        self.mgr.write_snapshot(b"PMVAULT1" + b"\0" * 60, "d1",
                                tag="premerge", now=now)
        later = now + timedelta(minutes=10)
        self.assertIsNotNone(
            self.mgr.maybe_snapshot(b"PMVAULT1" + b"\1" * 60, "d2", now=later))

    def test_note_digest_suppresses_pointless_first_snapshot(self):
        blob = b"PMVAULT1" + b"\0" * 60
        self.mgr.note_digest("opened")
        self.assertIsNone(self.mgr.maybe_snapshot(blob, "opened"))

    # ------------------------------------------------------------------
    def test_gfs_retention_keeps_long_history(self):
        now = datetime(2026, 8, 7, 12, 0, 0)
        t = now
        for _ in range(3 * 24 * 6):          # трое суток каждые 10 минут
            self.fabricate(t)
            t -= timedelta(minutes=10)
        for d in range(4, 400):
            self.fabricate(now - timedelta(days=d))

        before = len(self.mgr.list_snapshots())
        self.mgr.prune(now=now)
        kept = self.mgr.list_snapshots()

        self.assertLess(len(kept), before)
        self.assertLessEqual(len(kept), backup.KEEP_RECENT + backup.KEEP_HOURLY
                             + backup.KEEP_DAILY + backup.KEEP_MONTHLY)
        oldest = min(s.dt for s in kept)
        self.assertGreater((now - oldest).days, 300,
                           "история за месяцы должна оставаться")

    def test_event_snapshots_kept_separately(self):
        now = datetime(2026, 8, 7, 12, 0, 0)
        for d in range(1, 6):
            self.fabricate(now - timedelta(days=d), "premerge")
        for d in range(1, 200):
            self.fabricate(now - timedelta(days=d))
        self.mgr.prune(now=now)
        self.assertEqual(sum(1 for s in self.mgr.list_snapshots() if s.is_event), 5)

    def test_event_snapshots_capped(self):
        now = datetime(2026, 8, 7, 12, 0, 0)
        for d in range(1, backup.KEEP_EVENT + 6):
            self.fabricate(now - timedelta(days=d), "premerge")
        self.mgr.prune(now=now)
        self.assertEqual(sum(1 for s in self.mgr.list_snapshots() if s.is_event),
                         backup.KEEP_EVENT)

    def test_foreign_names_ignored(self):
        os.makedirs(self.dir, exist_ok=True)
        for name in ("readme.txt", "snap-bad.pmv", "vault.pmv"):
            with open(os.path.join(self.dir, name), "wb") as f:
                f.write(b"x")
        self.assertEqual(self.mgr.list_snapshots(), [])

    def test_missing_dir_is_not_fatal(self):
        mgr = backup.BackupManager(os.path.join(self.dir, "нет-такой"))
        self.assertEqual(mgr.list_snapshots(), [])
        self.assertEqual(mgr.total_size(), 0)
