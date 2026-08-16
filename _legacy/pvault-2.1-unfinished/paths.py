# -*- coding: utf-8 -*-
"""Где что лежит: хранилище пользователя и служебные файлы к нему.

Ключевое правило: РЯДОМ С ХРАНИЛИЩЕМ НЕ ДОЛЖНО ПОЯВЛЯТЬСЯ НИЧЕГО, кроме
самого файла. Хранилище часто кладут на рабочий стол или в облачную папку, и
превращать это место в свалку из .prev, .lock и каталога снимков нельзя.

Поэтому всё служебное уезжает в отдельную папку на каждое хранилище:

    %APPDATA%\\PassVault\\vaults\\<имя>-<хэш пути>\\
        previous.pmv     предыдущая версия (мгновенный откат)
        vault.lock       признак «открыто», снимается при выходе
        attempts.json    счётчик неверных паролей
        backups\\         архив снимков

Папка привязана к полному пути хранилища: у двух разных файлов свои снимки,
и они не перемешиваются. Единственное, что на мгновение появляется рядом с
хранилищем при сохранении, — временный файл, без которого нельзя заменить
файл атомарно; он тут же исчезает.
"""

import os
import re
import sys
import hashlib
import shutil

APP_DIRNAME = "PassVault"
VAULT_FILENAME = "vault.pmv"

PREV_NAME = "previous.pmv"
LOCK_NAME = "vault.lock"
ATTEMPTS_NAME = "attempts.json"
BACKUPS_DIRNAME = "backups"
CONFIG_NAME = "config.json"

# Имена, которыми прежние версии сорили рядом с хранилищем.
LEGACY_SIDECARS = (".prev", ".lock", ".bak", ".tmp")
LEGACY_BACKUP_DIRNAME = "vault_backups"

_SLUG_RE = re.compile(r"[^\w.-]+", re.UNICODE)


def app_dir():
    """Папка рядом с программой (учитывает сборку в .exe через PyInstaller)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def user_data_dir():
    """%APPDATA%\\PassVault (или ~/.passvault вне Windows)."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, APP_DIRNAME)
    return os.path.join(os.path.expanduser("~"), ".passvault")


def config_path():
    return os.path.join(user_data_dir(), CONFIG_NAME)


def _slug(vault_path):
    """Читаемое имя папки: понятное человеку плюс хэш от полного пути."""
    stem = os.path.splitext(os.path.basename(vault_path))[0] or "vault"
    stem = _SLUG_RE.sub("_", stem)[:32].strip("_") or "vault"
    digest = hashlib.sha256(
        os.path.normcase(os.path.abspath(vault_path)).encode("utf-8")
    ).hexdigest()[:10]
    return "%s-%s" % (stem, digest)


class VaultPaths:
    """Все пути, связанные с одним файлом хранилища."""

    def __init__(self, vault_path):
        self.vault = os.path.abspath(vault_path)
        self.sidecar = os.path.join(user_data_dir(), "vaults", _slug(self.vault))
        self.prev = os.path.join(self.sidecar, PREV_NAME)
        self.lock = os.path.join(self.sidecar, LOCK_NAME)
        self.attempts = os.path.join(self.sidecar, ATTEMPTS_NAME)
        self.backups = os.path.join(self.sidecar, BACKUPS_DIRNAME)

    @property
    def folder(self):
        return os.path.dirname(self.vault)

    def ensure(self):
        """Создаёт служебную папку. Возвращает False, если не вышло."""
        try:
            os.makedirs(self.sidecar, exist_ok=True)
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    def legacy_items(self):
        """Служебные файлы прежних версий, лежащие рядом с хранилищем."""
        found = []
        for suffix in LEGACY_SIDECARS:
            p = self.vault + suffix
            if os.path.isfile(p):
                found.append(p)
        old_backups = os.path.join(self.folder, LEGACY_BACKUP_DIRNAME)
        if os.path.isdir(old_backups):
            found.append(old_backups)
        return found

    def migrate_legacy(self):
        """Переносит служебные файлы прежних версий в служебную папку.

        Делается один раз при открытии хранилища: рядом с файлом пользователя
        не должно оставаться ничего лишнего, но и выбрасывать чужие данные
        нельзя — снимки переносятся, а не удаляются.
        """
        items = self.legacy_items()
        if not items:
            return []
        if not self.ensure():
            return []

        moved = []
        for path in items:
            name = os.path.basename(path)
            try:
                if os.path.isdir(path):
                    os.makedirs(self.backups, exist_ok=True)
                    for entry in os.listdir(path):
                        src = os.path.join(path, entry)
                        dst = os.path.join(self.backups, entry)
                        if os.path.isfile(src) and not os.path.exists(dst):
                            shutil.move(src, dst)
                    if not os.listdir(path):
                        os.rmdir(path)
                    moved.append(name)
                elif path.endswith(".prev"):
                    shutil.move(path, self.prev)
                    moved.append(name)
                elif path.endswith(".bak"):
                    # Копия от версии 1.x — сохраняем как снимок, чтобы она
                    # осталась доступной для восстановления.
                    os.makedirs(self.backups, exist_ok=True)
                    dst = os.path.join(self.backups, "snap-legacy-bak.pmv")
                    if not os.path.exists(dst):
                        shutil.move(path, dst)
                    else:
                        os.remove(path)
                    moved.append(name)
                else:
                    os.remove(path)               # .lock и .tmp просто мусор
                    moved.append(name)
            except OSError:
                pass
        return moved


def default_vault_path():
    """Хранилище по умолчанию, если ничего не запомнено.

    Переносимый режим (файл рядом с программой) идёт первым, чтобы уже
    сложившиеся установки продолжали работать как раньше.
    """
    beside = os.path.join(app_dir(), VAULT_FILENAME)
    if os.path.isfile(beside):
        return beside

    in_userdir = os.path.join(user_data_dir(), VAULT_FILENAME)
    if os.path.isfile(in_userdir):
        return in_userdir

    return beside if _writable(app_dir()) else in_userdir


def _writable(path):
    import tempfile
    try:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, delete=True):
            pass
        return True
    except OSError:
        return False
