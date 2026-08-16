# -*- coding: utf-8 -*-
r"""Где лежат хранилище и служебные файлы к нему.

Всё живёт рядом с хранилищем:

    vault.pmv
    vault.pmv.prev        предыдущая версия
    vault.pmv.lock        признак «открыто», снимается при выходе
    vault.pmv.att         счётчик неверных паролей
    vault_backups\        архив снимков (папку можно перенести в настройках)

Список последних открытых файлов — рядом с программой, в config.json.

В профиль пользователя (%APPDATA%) программа не пишет ничего. Если рядом с
программой писать нельзя, список последних файлов просто не сохраняется —
это неудобство, а не повод раскладывать файлы там, где их не ждут.
"""

import os
import re
import shutil
import sys

VAULT_FILENAME = "vault.pmv"
CONFIG_NAME = "config.json"

PREV_SUFFIX = ".prev"
LOCK_SUFFIX = ".lock"
ATTEMPTS_SUFFIX = ".att"
BAK_SUFFIX = ".bak"
TMP_SUFFIX = ".tmp"
BACKUP_DIRNAME = "vault_backups"

_SLUG_RE = re.compile(r"[^\w.-]+", re.UNICODE)


def app_dir():
    """Папка программы: рядом с ней лежит config.json и ищется хранилище.

    PASSVAULT_HOME перекрывает её. Нужно это автотестам: без переопределения
    они писали список недавних хранилищ в config.json рабочей папки и затирали
    пользователю настоящий список путями к своим временным файлам.
    """
    override = os.environ.get("PASSVAULT_HOME")
    if override:
        return os.path.abspath(override)
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def config_path():
    return os.path.join(app_dir(), CONFIG_NAME)


def writable_dir(path):
    import tempfile
    try:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, delete=True):
            pass
        return True
    except OSError:
        return False


def legacy_state_dir(vault_path):
    r"""Папка, куда служебные файлы складывала прежняя сборка (%APPDATA%).

    Нужна ровно для одного: забрать оттуда уцелевшее и больше туда не ходить.
    """
    base = os.environ.get("APPDATA") if os.name == "nt" else None
    if not base:
        return None
    import hashlib
    stem = os.path.splitext(os.path.basename(vault_path))[0] or "vault"
    stem = _SLUG_RE.sub("_", stem)[:32].strip("_") or "vault"
    digest = hashlib.sha256(
        os.path.normcase(os.path.abspath(vault_path)).encode("utf-8")
    ).hexdigest()[:10]
    return os.path.join(base, "PassVault", "vaults", "%s-%s" % (stem, digest))


class VaultPaths:
    """Все пути, связанные с одним файлом хранилища."""

    def __init__(self, vault_path, backup_dir=None):
        self.vault = os.path.abspath(vault_path)
        self.prev = self.vault + PREV_SUFFIX
        self.lock = self.vault + LOCK_SUFFIX
        self.attempts = self.vault + ATTEMPTS_SUFFIX
        self.backups = (os.path.abspath(backup_dir) if backup_dir
                        else self.default_backups)

    @property
    def folder(self):
        return os.path.dirname(self.vault)

    @property
    def default_backups(self):
        return os.path.join(self.folder, BACKUP_DIRNAME)

    def set_backup_dir(self, backup_dir):
        old = self.backups
        self.backups = (os.path.abspath(backup_dir) if backup_dir
                        else self.default_backups)
        return old

    def ensure(self):
        try:
            os.makedirs(self.backups, exist_ok=True)
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    def adopt_orphans(self):
        """Подбирает файлы от прежних версий и прежних раскладок.

        Ничего не удаляется: даже недописанный .tmp может оказаться последней
        уцелевшей копией, поэтому он уезжает в архив, а не в корзину.
        """
        moved = []
        if not self.ensure():
            return moved

        old = legacy_state_dir(self.vault)
        if old and os.path.isdir(old):
            src_prev = os.path.join(old, "previous.pmv")
            if os.path.isfile(src_prev):
                if os.path.exists(self.prev):
                    # Свой откат уже есть — чужой не выбрасываем, а кладём в
                    # архив: это отдельное состояние хранилища.
                    self._park(src_prev, "legacyprev")
                else:
                    try:
                        shutil.move(src_prev, self.prev)
                    except OSError:
                        pass
                moved.append("previous.pmv")
            moved += self.absorb_dir(os.path.join(old, "backups"))
            for junk in ("vault.lock", "attempts.json"):
                _quiet_remove(os.path.join(old, junk))
            try:
                os.rmdir(old)
            except OSError:
                pass

        bak = self.vault + BAK_SUFFIX
        if os.path.isfile(bak):
            self._park(bak, "legacybak")
            moved.append(os.path.basename(bak))

        tmp = self.vault + TMP_SUFFIX
        if os.path.isfile(tmp):
            if _looks_like_vault(tmp):
                self._park(tmp, "legacytmp")
            else:
                _quiet_remove(tmp)
            moved.append(os.path.basename(tmp))

        return moved

    def absorb_dir(self, source_dir):
        """Переносит снимки из другой папки в текущую папку архива."""
        moved = []
        if not os.path.isdir(source_dir):
            return moved
        try:
            os.makedirs(self.backups, exist_ok=True)
            for name in sorted(os.listdir(source_dir)):
                src = os.path.join(source_dir, name)
                dst = os.path.join(self.backups, name)
                if os.path.isfile(src) and not os.path.exists(dst):
                    shutil.move(src, dst)
                    moved.append(name)
            if not os.listdir(source_dir):
                os.rmdir(source_dir)
        except OSError:
            pass
        return moved

    def _park(self, path, tag):
        """Убирает файл в архив под именем, которое архив показывает."""
        from datetime import datetime, timedelta
        try:
            stamp = datetime.fromtimestamp(os.path.getmtime(path))
        except OSError:
            stamp = datetime.now()
        for shift in range(60):
            dt = stamp + timedelta(seconds=shift)
            dst = os.path.join(self.backups, "snap-%s-%s.pmv"
                               % (dt.strftime("%Y%m%d-%H%M%S"), tag))
            if not os.path.exists(dst):
                try:
                    shutil.move(path, dst)
                    return dst
                except OSError:
                    return None
        return None


def _quiet_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _looks_like_vault(path):
    from .crypto import MAGIC_V1, MAGIC_V2
    try:
        with open(path, "rb") as f:
            return f.read(8) in (MAGIC_V1, MAGIC_V2)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Поиск хранилища при запуске
# ---------------------------------------------------------------------------
def candidate_vault_paths():
    here = app_dir()
    seen, out = set(), []

    def add(p):
        if not p:
            return
        key = os.path.normcase(os.path.abspath(p))
        if key not in seen:
            seen.add(key)
            out.append(os.path.abspath(p))

    add(os.path.join(here, VAULT_FILENAME))
    add(os.path.join(os.path.dirname(here), VAULT_FILENAME))
    add(os.path.join(os.path.expanduser("~"), "Documents", VAULT_FILENAME))
    add(os.path.join(os.path.expanduser("~"), "Desktop", VAULT_FILENAME))
    return out


def find_existing_vault():
    for p in candidate_vault_paths():
        if os.path.isfile(p):
            return p
    return None


def default_vault_path():
    found = find_existing_vault()
    if found:
        return found
    return os.path.join(app_dir(), VAULT_FILENAME)
