# -*- coding: utf-8 -*-
"""Архив снимков хранилища — настоящее резервное копирование.

Схема версии 1.x (один vault.pmv.bak, перезаписываемый при каждом сохранении)
резервной копией не была: автосохранение срабатывает через секунду после
правки, поэтому .bak всегда отставал ровно на одно сохранение. Восстановить
вчерашнее состояние было невозможно в принципе.

Здесь снимки копятся по схеме «дед-отец-сын»:

    последние       12 снимков независимо от возраста
    почасовые       по одному на час за последние 24 часа
    дневные         по одному на день за 30 дней
    месячные        по одному на месяц за 12 месяцев
    событийные      перед слиянием, сменой пароля, сменой формата,
                    восстановлением и чисткой — последние 10

Итого около 80 файлов; при типичном размере хранилища в 20 КБ это меньше двух
мегабайт. Снимки лежат в том же зашифрованном формате, что и само хранилище,
поэтому открываются штатным «Открыть другой файл…» и сливаются обычным
слиянием.

Снимок пишется ИЗ ТЕХ ЖЕ БАЙТОВ, что только что легли в vault.pmv. Прошлая
версия копировала файл с диска, а отпечаток считала по данным в памяти, и эти
двое расходились: после событийного снимка ближайшее сохранение решало, что
«ничего не менялось», и штатный снимок пропускался. Байты и отпечаток теперь
приходят одной парой и разойтись не могут.

Снимок делается только при изменении СОДЕРЖИМОГО: шифртекст меняется при
каждой записи из-за нового nonce, и сравнивать надо открытый текст, иначе
архив забьётся десятками одинаковых снимков.
"""

import hashlib
import os
import re
from datetime import datetime, timedelta

BACKUP_DIRNAME = "backups"

KEEP_RECENT = 12
KEEP_HOURLY = 24
KEEP_DAILY = 30
KEEP_MONTHLY = 12
KEEP_EVENT = 10

MIN_INTERVAL_SECONDS = 5 * 60

_NAME_RE = re.compile(r"^snap-(\d{8})-(\d{6})(?:-([a-z0-9]+))?\.pmv$", re.I)

EVENT_LABELS = {
    "premerge": "перед слиянием",
    "prepassword": "перед сменой пароля",
    "preformat": "перед сменой формата",
    "prerestore": "перед восстановлением",
    "prepurge": "перед чисткой",
    "preimport": "перед импортом",
    "legacybak": "копия от версии 1.x",
    "legacyprev": "откат от прежней версии",
    "legacytmp": "недописанный файл прежней версии",
}


def plaintext_digest(blob_or_data):
    """Отпечаток СОДЕРЖИМОГО хранилища (не шифртекста).

    Принимает либо готовые байты открытого текста, либо словарь — тогда он
    сериализуется канонически, чтобы отпечаток не зависел от порядка ключей.
    """
    if isinstance(blob_or_data, (bytes, bytearray)):
        raw = bytes(blob_or_data)
    else:
        from .crypto import serialize
        raw = serialize(blob_or_data)
    return hashlib.sha256(raw).hexdigest()


class Snapshot:
    __slots__ = ("path", "dt", "tag")

    def __init__(self, path, dt, tag=None):
        self.path = path
        self.dt = dt
        self.tag = tag

    @property
    def is_event(self):
        return self.tag is not None

    @property
    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def label(self):
        base = self.dt.strftime("%Y-%m-%d %H:%M:%S")
        if self.tag is None:
            return base
        return "%s  ·  %s" % (base, EVENT_LABELS.get(self.tag, self.tag))


class BackupManager:
    def __init__(self, backup_dir):
        self.dir = os.path.abspath(backup_dir)
        self._last_digest = None
        self._last_snapshot_at = None

    # ------------------------------------------------------------------
    def ensure_dir(self):
        try:
            os.makedirs(self.dir, exist_ok=True)
            return True
        except OSError:
            return False

    def list_snapshots(self):
        """Снимки, новые первыми."""
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        out = []
        for name in names:
            m = _NAME_RE.match(name)
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
            except ValueError:
                continue
            tag = m.group(3).lower() if m.group(3) else None
            out.append(Snapshot(os.path.join(self.dir, name), dt, tag))
        out.sort(key=lambda s: s.dt, reverse=True)
        return out

    def total_size(self):
        return sum(s.size for s in self.list_snapshots())

    # ------------------------------------------------------------------
    def note_digest(self, digest):
        """Запомнить содержимое как «уже снятое», не создавая файла.

        Нужно сразу после открытия хранилища: снимать копию того, что и так
        лежит на диске нетронутым, смысла нет.
        """
        self._last_digest = digest

    def should_snapshot(self, digest, now=None):
        if digest == self._last_digest:
            return False
        if self._last_snapshot_at is not None:
            now = now or datetime.now()
            if (now - self._last_snapshot_at).total_seconds() < MIN_INTERVAL_SECONDS:
                return False
        return True

    def maybe_snapshot(self, blob, digest, now=None):
        """Штатный снимок при сохранении: не чаще раза в 5 минут и только
        если содержимое действительно изменилось."""
        if not self.should_snapshot(digest, now):
            self._last_digest = digest
            return None
        return self.write_snapshot(blob, digest, tag=None, now=now)

    def write_snapshot(self, blob, digest, tag=None, now=None):
        """Пишет снимок из переданных байтов. Возвращает Snapshot или None."""
        if not self.ensure_dir():
            return None
        now = now or datetime.now()

        path, stamp_dt = self._free_name(now, tag)
        if path is None:
            return None

        tmp = path + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return None

        self._last_digest = digest
        self._last_snapshot_at = now
        self.prune(now=now)
        return Snapshot(path, stamp_dt, tag)

    def _free_name(self, now, tag):
        """Свободное имя. Два события в одну секунду сдвигаются на секунду
        вперёд, а не затирают друг друга."""
        suffix = ("-%s" % tag) if tag else ""
        for shift in range(60):
            dt = now + timedelta(seconds=shift)
            name = "snap-%s%s.pmv" % (dt.strftime("%Y%m%d-%H%M%S"), suffix)
            path = os.path.join(self.dir, name)
            if not os.path.exists(path):
                return path, dt
        return None, None

    # ------------------------------------------------------------------
    def prune(self, now=None):
        """Удаляет лишние снимки по схеме «дед-отец-сын». Возвращает число удалённых."""
        snaps = self.list_snapshots()
        if not snaps:
            return 0

        keep = set()
        events = [s for s in snaps if s.is_event]
        auto = [s for s in snaps if not s.is_event]

        for s in events[:KEEP_EVENT]:
            keep.add(s.path)
        for s in auto[:KEEP_RECENT]:
            keep.add(s.path)

        def keep_buckets(fmt, limit):
            seen = set()
            for s in auto:
                bucket = s.dt.strftime(fmt)
                if bucket in seen:
                    continue
                seen.add(bucket)
                keep.add(s.path)
                if len(seen) >= limit:
                    break

        keep_buckets("%Y%m%d%H", KEEP_HOURLY)
        keep_buckets("%Y%m%d", KEEP_DAILY)
        keep_buckets("%Y%m", KEEP_MONTHLY)

        removed = 0
        for s in snaps:
            if s.path in keep:
                continue
            try:
                os.remove(s.path)
                removed += 1
            except OSError:
                pass
        return removed
