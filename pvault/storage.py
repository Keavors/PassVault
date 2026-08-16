# -*- coding: utf-8 -*-
"""Запись хранилища на диск и защита от одновременного доступа.

Здесь чинится баг, из-за которого данные терялись безвозвратно.

Порядок записи в версии 1.x был такой:

    os.replace(vault, vault + ".bak")   # <-- в этот момент vault НЕ СУЩЕСТВУЕТ
    os.replace(tmp, vault)

Крах между этими строками оставлял систему без vault.pmv. Программа при
следующем запуске показывала «Хранилище ещё не создано», пользователь создавал
новое, и первое же автосохранение ротировало пустое хранилище в .bak, затирая
единственную уцелевшую копию. Две операции от сбоя до полной потери.

Что делается вместо этого:

 1. новый файл пишется во временный, с fsync;
 2. временный тут же проверяется расшифровкой — ключ уже в памяти, KDF гонять
    не нужно, проверка стоит около миллисекунды;
 3. предыдущая версия КОПИРУЕТСЯ (не переименовывается) в служебную папку;
 4. и только теперь временный файл атомарно занимает место основного.

vault.pmv не исчезает с диска ни на мгновение. Если сбой случится на любом из
шагов, на диске останется либо прежняя версия, либо прежняя версия плюс
временный файл — и оба варианта восстановимы.

Тест, который выдёргивает питание ровно между шагами, лежит в
tests/test_storage.py. Именно его отсутствие и стоило прошлой версии данных.
"""

import os
import shutil
import tempfile

from .crypto import MAGIC_V1, MAGIC_V2, VaultError, decrypt_with_key
from .paths import (BACKUP_DIRNAME, BAK_SUFFIX, VaultPaths, legacy_state_dir)

TMP_SUFFIX = ".tmp"


class StorageError(OSError):
    """Ошибка записи или чтения файла хранилища."""


class AlreadyLocked(Exception):
    def __init__(self, pid, host):
        self.pid = pid
        self.host = host
        super().__init__("Хранилище уже открыто (процесс %s на %s)" % (pid, host))


def _quiet_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _fsync_dir(path):
    """Делает долговечной саму запись каталога. На Windows не поддерживается."""
    if os.name != "posix":
        return
    fd = os.open(os.path.dirname(os.path.abspath(path)) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Атомарная запись
# ---------------------------------------------------------------------------
def atomic_write(path, blob, verify_key=None, prev_path=None, hooks=None):
    """Записывает blob по пути path, не теряя предыдущую версию ни на миг.

    verify_key — ключ AES для проверки записанного расшифровкой. Передавать
    настоятельно рекомендуется: это ловит порчу прямо при записи, пока прежняя
    версия ещё цела.

    prev_path — куда положить предыдущую версию. Намеренно отдельный параметр:
    складывать её рядом с хранилищем нельзя, иначе папка пользователя (часто
    рабочий стол или облачный диск) обрастает служебными файлами.

    hooks — словарь {имя_шага: callable} для тестов. Единственный способ
    проверить «а что если питание выдернут вот здесь» — дать тесту вклиниться
    в конкретную точку. Шаги: after_tmp, after_verify, after_prev.
    """
    path = os.path.abspath(path)
    tmp = path + TMP_SUFFIX
    hooks = hooks or {}

    try:
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        _quiet_remove(tmp)
        raise StorageError("Не удалось записать временный файл:\n%s" % e)

    if "after_tmp" in hooks:
        hooks["after_tmp"]()

    if verify_key is not None:
        try:
            with open(tmp, "rb") as f:
                written = f.read()
            decrypt_with_key(written, verify_key)
        except (OSError, VaultError) as e:
            _quiet_remove(tmp)
            raise StorageError(
                "Записанный файл не проходит проверку целостности, сохранение "
                "отменено (прежняя версия цела):\n%s" % e)

    if "after_verify" in hooks:
        hooks["after_verify"]()

    if prev_path and os.path.exists(path):
        prev_tmp = prev_path + TMP_SUFFIX
        try:
            os.makedirs(os.path.dirname(prev_path), exist_ok=True)
            shutil.copy2(path, prev_tmp)
            os.replace(prev_tmp, prev_path)
        except OSError:
            # Не смогли обновить предыдущую версию — неприятно, но не повод
            # терять само сохранение. Актуальные данные важнее отката.
            _quiet_remove(prev_tmp)

    if "after_prev" in hooks:
        hooks["after_prev"]()

    try:
        os.replace(tmp, path)
    except OSError as e:
        _quiet_remove(tmp)
        raise StorageError("Не удалось заменить файл хранилища:\n%s" % e)

    try:
        _fsync_dir(path)
    except OSError:
        pass


def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise StorageError("Не удалось прочитать файл:\n%s" % e)


def looks_like_vault(path):
    try:
        with open(path, "rb") as f:
            return f.read(8) in (MAGIC_V1, MAGIC_V2)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Поиск уцелевших копий
# ---------------------------------------------------------------------------
class Candidate:
    """Файл, из которого потенциально можно восстановить хранилище."""

    __slots__ = ("path", "mtime", "kind", "note")

    def __init__(self, path, kind, note):
        self.path = path
        self.kind = kind
        self.note = note
        try:
            self.mtime = os.path.getmtime(path)
        except OSError:
            self.mtime = 0.0

    @property
    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0


def recovery_candidates(vault_path, paths=None):
    """Все файлы, из которых можно попытаться восстановить хранилище.

    Вызывается, когда vault.pmv отсутствует. Раньше в этой ситуации
    предлагалось создать новое хранилище — и это был прямой путь к потере.

    Просматриваются и старые места: файлы, оставшиеся рядом с хранилищем от
    версий 1.x и 2.0, для восстановления годятся ровно так же.
    """
    paths = paths or VaultPaths(vault_path)
    vault_path = os.path.abspath(vault_path)

    singles = [
        (paths.prev, "prev", "предыдущая версия"),
        (vault_path + TMP_SUFFIX, "tmp", "недописанный файл последнего сохранения"),
        (vault_path + BAK_SUFFIX, "bak", "копия от прежней версии программы"),
    ]

    dirs = [
        (paths.backups, "снимок из архива"),
        (os.path.join(os.path.dirname(vault_path), BACKUP_DIRNAME),
         "снимок из архива (рядом с хранилищем)"),
    ]
    legacy = legacy_state_dir(vault_path)
    if legacy:
        dirs.append((os.path.join(legacy, "backups"),
                     "снимок из архива (старое место)"))

    found = [Candidate(p, kind, note) for p, kind, note in singles
             if p and os.path.isfile(p)]

    for directory, note in dirs:
        if not os.path.isdir(directory):
            continue
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            full = os.path.join(directory, name)
            if os.path.isfile(full) and name.lower().endswith(".pmv"):
                found.append(Candidate(full, "snapshot", note))

    good, seen = [], set()
    for c in found:
        key = os.path.normcase(os.path.abspath(c.path))
        if key in seen:
            continue
        seen.add(key)
        if looks_like_vault(c.path):
            good.append(c)
    good.sort(key=lambda c: c.mtime, reverse=True)
    return good


# ---------------------------------------------------------------------------
# Блокировка хранилища
# ---------------------------------------------------------------------------
def _pid_alive(pid):
    if pid is None or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        except Exception:
            return True                     # не смогли выяснить — считаем живым
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


class VaultLock:
    """Файл-замок, не дающий двум копиям программы затирать правки друг друга.

    Без него две запущенные копии на одном хранилище с автосохранением раз в
    секунду гарантированно теряют данные: побеждает тот, кто записал последним,
    и вторая копия даже не узнает, что её правки стёрли.

    Замок от «мёртвого» процесса (программа упала, файл остался) распознаётся
    по PID и снимается автоматически — иначе после первого же падения
    хранилище оказалось бы заперто навсегда.
    """

    def __init__(self, lock_path):
        self.lock_path = os.path.abspath(lock_path)
        self.acquired = False

    def read_owner(self):
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                parts = f.read().strip().split("\n")
            return int(parts[0].strip()), (parts[1].strip() if len(parts) > 1 else "?")
        except (OSError, ValueError, IndexError):
            return None, None

    def acquire(self, steal_stale=True):
        """Берёт замок. Бросает AlreadyLocked, если хранилище занято живым процессом.

        Возвращает False, если файловая система не даёт создать замок вообще
        (сетевой диск, флешка только на чтение). Это не повод отказывать в
        работе: замок — удобство, а не безопасность.
        """
        import platform
        if self.acquired:
            return True
        try:
            os.makedirs(os.path.dirname(self.lock_path), exist_ok=True)
        except OSError:
            return False

        payload = ("%d\n%s\n" % (os.getpid(), platform.node())).encode("utf-8")
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            pid, host = self.read_owner()
            if pid is not None and _pid_alive(pid):
                raise AlreadyLocked(pid, host)
            if not steal_stale:
                raise AlreadyLocked(pid, host)
            _quiet_remove(self.lock_path)            # замок протух
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except OSError:
                raise AlreadyLocked(pid, host)
        except OSError:
            return False
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        self.acquired = True
        return True

    def force(self):
        """Снимает чужой замок по явному решению пользователя."""
        _quiet_remove(self.lock_path)
        self.acquired = False
        try:
            return self.acquire(steal_stale=True)
        except AlreadyLocked:
            return False

    def release(self):
        if not self.acquired:
            return
        pid, _ = self.read_owner()
        if pid == os.getpid():
            _quiet_remove(self.lock_path)
        self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc):
        self.release()
        return False


def writable_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, delete=True):
            pass
        return True
    except OSError:
        return False
