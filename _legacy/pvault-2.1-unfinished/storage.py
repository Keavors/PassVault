# -*- coding: utf-8 -*-
"""Запись хранилища на диск и защита от одновременного доступа.

Здесь чинится баг, из-за которого данные терялись безвозвратно.

Прежний порядок записи был такой:

    os.replace(vault, vault + ".bak")   # <-- в этот момент vault НЕ СУЩЕСТВУЕТ
    os.replace(tmp, vault)

Крах между этими строками оставлял систему без vault.pmv. Приложение при
следующем запуске показывало «Хранилище ещё не создано», пользователь создавал
новое, и первое же автосохранение ротировало пустое хранилище в .bak, затирая
единственную уцелевшую копию. Две операции от сбоя до полной потери.

Теперь предыдущая версия СКОПИРУЕТСЯ, а не переименуется, поэтому vault.pmv не
исчезает с диска ни на мгновение. Плюс записанный файл сразу проверяется
расшифровкой: ключ уже в памяти, KDF гонять не нужно, проверка стоит около
миллисекунды — для менеджера паролей это более чем окупается.

Служебные файлы (предыдущая версия, блокировка, снимки) лежат НЕ рядом с
хранилищем, а в отдельной папке — см. pvault/paths.py. Рядом с файлом
пользователя на мгновение появляется только временный файл, без которого
атомарная замена невозможна.
"""

import os
import tempfile

from .crypto import decrypt_with_key, VaultError
from .paths import (VaultPaths, app_dir, user_data_dir, default_vault_path,
                    VAULT_FILENAME, LEGACY_BACKUP_DIRNAME)

TMP_SUFFIX = ".tmp"
LEGACY_PREV_SUFFIX = ".prev"
LEGACY_BAK_SUFFIX = ".bak"
LEGACY_LOCK_SUFFIX = ".lock"

__all__ = [
    "StorageError", "atomic_write", "read_file", "recovery_candidates",
    "Candidate", "VaultLock", "AlreadyLocked", "VaultPaths",
    "app_dir", "user_data_dir", "default_vault_path", "writable_dir",
    "VAULT_FILENAME",
]


class StorageError(OSError):
    """Ошибка записи или чтения файла хранилища."""


# ---------------------------------------------------------------------------
# Атомарная запись
# ---------------------------------------------------------------------------
def _fsync_dir(path):
    """Делает долговечной саму запись каталога. На Windows не поддерживается."""
    if os.name != "posix":
        return
    fd = os.open(os.path.dirname(os.path.abspath(path)) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _quiet_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def atomic_write(path, blob, verify_key=None, prev_path=None, keep_prev=True):
    """Записывает blob по пути path, не теряя предыдущую версию ни на миг.

    verify_key — ключ AES для проверки записанного расшифровкой. Настоятельно
    рекомендуется передавать: это ловит порчу данных прямо при записи, пока
    прежняя версия ещё цела.

    prev_path — куда положить предыдущую версию. Намеренно отдельный параметр:
    складывать её рядом с хранилищем нельзя, иначе папка пользователя (часто
    рабочий стол) обрастает служебными файлами.
    """
    path = os.path.abspath(path)
    tmp = path + TMP_SUFFIX

    try:
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        _quiet_remove(tmp)
        raise StorageError("Не удалось записать временный файл:\n%s" % e)

    if verify_key is not None:
        try:
            with open(tmp, "rb") as f:
                written = f.read()
            decrypt_with_key(written, verify_key)
        except (OSError, VaultError) as e:
            _quiet_remove(tmp)
            raise StorageError(
                "Записанный файл не проходит проверку целостности, "
                "сохранение отменено (прежняя версия цела):\n%s" % e)

    if keep_prev and prev_path and os.path.exists(path):
        import shutil
        prev_tmp = prev_path + TMP_SUFFIX
        try:
            os.makedirs(os.path.dirname(prev_path), exist_ok=True)
            shutil.copy2(path, prev_tmp)
            os.replace(prev_tmp, prev_path)
        except OSError:
            # Не смогли обновить предыдущую версию — это неприятно, но не
            # повод терять само сохранение. Актуальные данные важнее.
            _quiet_remove(prev_tmp)

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


def recovery_candidates(vault_path, backup_dir=None, prev_path=None):
    """Все файлы, из которых можно попытаться восстановить хранилище.

    Вызывается, когда vault.pmv отсутствует. Раньше в этой ситуации
    предлагалось создать новое хранилище — и это был прямой путь к потере.

    Просматриваются и старые места: файлы, оставшиеся рядом с хранилищем от
    прежних версий, тоже годятся для восстановления.
    """
    from .crypto import MAGIC_V1, MAGIC_V2

    paths_to_check = []
    if prev_path:
        paths_to_check.append((prev_path, "prev", "предыдущая версия"))
    paths_to_check += [
        (vault_path + TMP_SUFFIX, "tmp", "недописанный файл последнего сохранения"),
        (vault_path + LEGACY_PREV_SUFFIX, "prev", "предыдущая версия (старое место)"),
        (vault_path + LEGACY_BAK_SUFFIX, "bak", "копия от прежней версии программы"),
    ]

    out = []
    for path, kind, note in paths_to_check:
        if path and os.path.isfile(path):
            out.append(Candidate(path, kind, note))

    dirs = []
    if backup_dir:
        dirs.append((backup_dir, "снимок из архива"))
    legacy_dir = os.path.join(os.path.dirname(os.path.abspath(vault_path)),
                              LEGACY_BACKUP_DIRNAME)
    dirs.append((legacy_dir, "снимок из архива (старое место)"))

    for d, note in dirs:
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for name in names:
            full = os.path.join(d, name)
            if os.path.isfile(full) and name.lower().endswith(".pmv"):
                out.append(Candidate(full, "snapshot", note))

    good = []
    seen = set()
    for c in out:
        key = os.path.normcase(os.path.abspath(c.path))
        if key in seen:
            continue
        seen.add(key)
        try:
            with open(c.path, "rb") as f:
                head = f.read(8)
            if head in (MAGIC_V1, MAGIC_V2):
                good.append(c)
        except OSError:
            pass
    good.sort(key=lambda c: c.mtime, reverse=True)
    return good


# ---------------------------------------------------------------------------
# Блокировка хранилища
# ---------------------------------------------------------------------------
def _pid_alive(pid):
    if pid <= 0:
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
            return True          # не смогли выяснить — считаем живым
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


class AlreadyLocked(Exception):
    def __init__(self, pid, host):
        self.pid = pid
        self.host = host
        super().__init__("Хранилище уже открыто (процесс %s на %s)" % (pid, host))


class VaultLock:
    """Файл-блокировка, не дающий двум копиям программы затирать друг друга.

    Без неё две запущенные копии на одном хранилище с автосохранением раз в
    секунду гарантированно теряют данные: побеждает тот, кто записал последним.

    Блокировка от «мёртвого» процесса (программа упала, файл остался)
    распознаётся по PID и снимается автоматически.
    """

    def __init__(self, lock_path):
        self.lock_path = os.path.abspath(lock_path)
        self.acquired = False

    def _read(self):
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                parts = f.read().strip().split("\n")
            pid = int(parts[0].strip())
            host = parts[1].strip() if len(parts) > 1 else "?"
            return pid, host
        except (OSError, ValueError, IndexError):
            return None, None

    def acquire(self, steal_stale=True):
        import platform
        if self.acquired:
            return True
        try:
            os.makedirs(os.path.dirname(self.lock_path), exist_ok=True)
        except OSError:
            return False
        payload = "%d\n%s\n" % (os.getpid(), platform.node())
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            pid, host = self._read()
            # Живой процесс держит хранилище — в том числе если это мы сами:
            # одна программа не должна открывать одно хранилище дважды.
            if pid is not None and _pid_alive(pid):
                raise AlreadyLocked(pid, host)
            if not steal_stale:
                raise AlreadyLocked(pid, host)
            _quiet_remove(self.lock_path)            # блокировка протухла
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except OSError:
                raise AlreadyLocked(pid, host)
        except OSError:
            return False                             # ФС не даёт — работаем без блокировки
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        self.acquired = True
        return True

    def release(self):
        if not self.acquired:
            return
        pid, _ = self._read()
        if pid == os.getpid():
            _quiet_remove(self.lock_path)
        self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def writable_dir(path):
    """Проверяет, что в каталог можно писать."""
    try:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, delete=True):
            pass
        return True
    except OSError:
        return False
