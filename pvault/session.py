# -*- coding: utf-8 -*-
"""Открытое хранилище: всё, что происходит между вводом пароля и блокировкой.

Слой существует ради того, чтобы интерфейс не занимался ничем, кроме
интерфейса. Сохранение, снимки, смена пароля, смена формата и слияние — это
операции над данными, и проверять их надо тестами, а не кликами по окнам.
В прошлой версии эта логика жила прямо в классе окна, и покрыть её было
физически нечем.
"""

import os

from . import backup, config, crypto, merge as mergelib, model, storage
from .generator import DEFAULT_GEN
from .paths import VaultPaths
from .throttle import AttemptGuard

DEFAULT_APP_SETTINGS = {
    "autolock_minutes": 5,
    # Через сколько секунд стереть скопированный пароль из буфера обмена.
    # 0 — не стирать. Настройка была заведена ещё в файлах версии 2.0, но её
    # никто не читал: пароль оставался в буфере навсегда.
    "clipboard_seconds": 30,
    # Пусто = папка vault_backups рядом с хранилищем. Настройка живёт в самом
    # хранилище, поэтому переезжает вместе с файлом.
    "backup_dir": "",
}


class Vault:
    """Одно открытое хранилище."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.paths = VaultPaths(self.path)
        self.backups = backup.BackupManager(self.paths.backups)
        self.guard = AttemptGuard(self.paths.attempts)
        self.lock = storage.VaultLock(self.paths.lock)

        self.data = None
        self.key = None
        self.params = None
        self.dirty = False

    # ------------------------------------------------------------------
    # Состояние
    # ------------------------------------------------------------------
    @property
    def is_open(self):
        return self.data is not None and self.key is not None

    @property
    def entries(self):
        return self.data["entries"]

    @property
    def settings(self):
        return self.data["settings"]

    @property
    def gen_settings(self):
        return self.data["settings"]["generator"]

    @property
    def app_settings(self):
        return self.data["settings"]["app"]

    def exists(self):
        return os.path.isfile(self.path)

    def recovery_candidates(self):
        return storage.recovery_candidates(self.path, self.paths)

    # ------------------------------------------------------------------
    # Открытие и создание
    # ------------------------------------------------------------------
    def open(self, password):
        """Открывает файл мастер-паролем. Бросает VaultError/StorageError.

        Успешное открытие сбрасывает счётчик неверных попыток, неуспешное —
        пополняет его. Возвращает список коротких сообщений для статусной
        строки: что перенесено, что обновлено, что не получилось.
        """
        blob = storage.read_file(self.path)
        try:
            data, key, params = crypto.decrypt_vault(blob, password)
        except crypto.VaultError:
            self.guard.record_failure()
            raise

        self.guard.record_success()
        self.data = model.normalize_data(data, DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.key = key
        self.params = params
        self.dirty = False

        self.apply_backup_dir(self.app_settings.get("backup_dir"))
        moved = self.paths.adopt_orphans()
        self.backups.note_digest(self._digest())
        config.remember_vault(self.path)

        notes = []
        if moved:
            notes.append("Служебные файлы прежней версии перенесены: "
                         + ", ".join(moved))
        notes += self._upgrade_kdf_if_needed(password)
        notes += self._first_snapshot_if_archive_empty()
        return notes

    def _upgrade_kdf_if_needed(self, password):
        """Переводит хранилище со старого PBKDF2 на Argon2id.

        Происходит один раз, само, при первом открытии старого файла. Спрашивать
        тут нечего: слабый вариант из программы убран, а оставлять хранилище на
        нём — значит оставлять его слабым молча.

        Порядок важен. Снимок делается ДО смены ключа и попадает в архив
        зашифрованным ПРЕЖНИМ способом: если перешифровка не доедет, у человека
        останется читаемая копия. При любой ошибке записи ключ и параметры
        откатываются, и работа продолжается на старом формате — потерять доступ
        к открытому хранилищу из-за неудачного апгрейда недопустимо.
        """
        if not self.is_open or not self.params.needs_upgrade:
            return []

        try:
            self.snapshot("preformat")
        except (storage.StorageError, OSError) as e:
            return ["Хранилище не переведено на Argon2id (не удалось сделать "
                    "копию): %s" % str(e).split("\n")[0]]

        old_key, old_params = self.key, self.params
        self.params = crypto.KdfParams.default()
        self.key = crypto.derive_key(password, self.params)
        try:
            self.save()
        except (storage.StorageError, OSError) as e:
            self.key, self.params = old_key, old_params
            return ["Хранилище НЕ переведено на Argon2id: %s"
                    % str(e).split("\n")[0]]
        return ["Хранилище переведено на усиленное шифрование (Argon2id). "
                "Мастер-пароль прежний."]

    def _first_snapshot_if_archive_empty(self):
        """Первый снимок, если архив пуст.

        Штатный снимок делается только при изменении содержимого, поэтому на
        свежей установке архив оставался пустым до первой правки: из всех
        резервных копий существовал только vault.pmv.prev — шаг назад на одно
        сохранение. Испортись файл до первой правки, откатываться было бы
        некуда.
        """
        if not self.is_open or self.backups.list_snapshots():
            return []
        try:
            snap = self.snapshot()
        except (storage.StorageError, OSError):
            return []
        return ["Создан первый снимок в архиве копий"] if snap else []

    def apply_backup_dir(self, backup_dir):
        """Переключает папку архива на ту, что записана в настройках."""
        self.paths.set_backup_dir(backup_dir or None)
        self.backups = backup.BackupManager(self.paths.backups)
        self.paths.ensure()

    def move_backups_to(self, backup_dir):
        """Меняет папку архива и переносит туда уже сделанные снимки."""
        old = self.paths.backups
        self.app_settings["backup_dir"] = backup_dir or ""
        self.apply_backup_dir(backup_dir)
        if os.path.normcase(old) != os.path.normcase(self.paths.backups):
            self.paths.absorb_dir(old)
        self.dirty = True
        return self.paths.backups

    def create(self, password, params=None):
        """Создаёт новое пустое хранилище и сразу пишет его на диск.

        Без явных параметров — Argon2id. Раньше здесь стоял PBKDF2, и каждое
        новое хранилище получало слабейший из двух вариантов по умолчанию.
        """
        self.data = model.default_data(DEFAULT_GEN, DEFAULT_APP_SETTINGS)
        self.params = params or crypto.KdfParams.default()
        self.key = crypto.derive_key(password, self.params)
        self.dirty = True
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.paths.ensure()
        self.save()
        config.remember_vault(self.path)

    def close(self):
        self.data = None
        self.key = None
        self.params = None
        self.dirty = False

    # ------------------------------------------------------------------
    # Сохранение
    # ------------------------------------------------------------------
    def _digest(self):
        return backup.plaintext_digest(self.data)

    def save(self, snapshot_tag=None):
        """Записывает хранилище. Бросает StorageError.

        Снимок пишется теми же байтами, что легли в vault.pmv, — отпечаток и
        содержимое файла не могут разойтись.
        """
        if not self.is_open:
            return
        blob = crypto.encrypt_with_key(self.data, self.key, self.params)
        digest = self._digest()

        storage.atomic_write(self.path, blob, verify_key=self.key,
                             prev_path=self.paths.prev)
        self.dirty = False

        if snapshot_tag:
            self.backups.write_snapshot(blob, digest, tag=snapshot_tag)
        else:
            self.backups.maybe_snapshot(blob, digest)

    def snapshot(self, tag=None):
        """Событийный снимок. Сначала сохраняет отложенные правки.

        Без сохранения «снимок перед слиянием» снял бы состояние файла на
        диске, а не то, что пользователь видит на экране, — и обещание
        «откатимся, если что» оказалось бы враньём.
        """
        if not self.is_open:
            return None
        blob = crypto.encrypt_with_key(self.data, self.key, self.params)
        digest = self._digest()
        storage.atomic_write(self.path, blob, verify_key=self.key,
                             prev_path=self.paths.prev)
        self.dirty = False
        return self.backups.write_snapshot(blob, digest, tag=tag)

    def mark_dirty(self):
        self.dirty = True

    # ------------------------------------------------------------------
    # Мастер-пароль и формат
    # ------------------------------------------------------------------
    def password_matches(self, password):
        return crypto.key_matches(password, self.key, self.params)

    def change_password(self, current, new_password):
        """Меняет мастер-пароль. Возвращает False, если текущий неверен.

        При неудачной записи ключ в памяти откатывается: иначе он разъедется
        с ключом файла, и следующее автосохранение молча перешифрует хранилище
        паролем, о котором пользователь думает, что не применил его.
        """
        if not self.password_matches(current):
            return False
        self.snapshot("prepassword")

        old_key, old_params = self.key, self.params
        self.params = self.params.with_new_salt()
        self.key = crypto.derive_key(new_password, self.params)
        try:
            self.save()
        except Exception:
            self.key, self.params = old_key, old_params
            raise
        return True

    # Метода convert_format здесь больше нет, и кнопки «Формат шифрования»
    # тоже. Выбирать было не из чего: PBKDF2 слабее Argon2id при любых
    # настройках, а держать в менеджере паролей переключатель «сделать себе
    # хуже» — плохая идея сама по себе. Перевод старых файлов делает
    # _upgrade_kdf_if_needed при открытии, молча и один раз.

    # ------------------------------------------------------------------
    # Чужие файлы и слияние
    # ------------------------------------------------------------------
    def read_foreign(self, path, password=None):
        """Расшифровывает чужой файл: сначала текущим ключом, потом паролем.

        Чаще всего это свой же снимок или копия с телефона под тем же паролем —
        тогда спрашивать пароль повторно незачем.
        """
        blob = storage.read_file(path)
        if password is None:
            if self.key is None:
                raise crypto.VaultError("Нужен пароль")
            return crypto.decrypt_with_key(blob, self.key)
        data, _key, _params = crypto.decrypt_vault(blob, password)
        return data

    @staticmethod
    def entries_of(data):
        """Записи из чужого хранилища, приведённые к нашему виду."""
        raw = data.get("entries") if isinstance(data, dict) else None
        out = []
        for item in raw if isinstance(raw, list) else []:
            e = model.normalize_entry(item)
            if e is not None:
                out.append(e)
        return out

    def plan_merge(self, incoming_entries):
        return mergelib.plan_merge(self.entries, incoming_entries)

    def apply_merge(self, plan, decisions):
        stats = mergelib.apply_merge(self.entries, plan, decisions)
        self.dirty = True
        return stats

    def add_entries(self, entries):
        """Импорт: только добавляет, существующие записи не трогает."""
        ids = {e.get("id") for e in self.entries}
        added = 0
        for e in entries:
            while e.get("id") in ids:
                e["id"] = model.new_id()
            ids.add(e["id"])
            self.entries.append(e)
            added += 1
        if added:
            self.dirty = True
        return added

    # ------------------------------------------------------------------
    # Записи
    # ------------------------------------------------------------------
    def new_entry(self):
        e = model.new_entry()
        self.entries.append(e)
        self.dirty = True
        return e

    def entry(self, eid):
        return model.entry_by_id(self.entries, eid)

    def delete_entry(self, eid):
        e = self.entry(eid)
        if e is None:
            return False
        model.soft_delete(e)
        self.dirty = True
        return True

    def purge_tombstones(self):
        n = model.purge_tombstones(self.entries)
        if n:
            self.dirty = True
        return n
