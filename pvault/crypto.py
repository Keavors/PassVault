# -*- coding: utf-8 -*-
"""Контейнер файла хранилища, получение ключа и шифрование.

Программа ПИШЕТ ровно один формат — PMVAULT2 (Argon2id). PMVAULT1 (PBKDF2)
по-прежнему ЧИТАЕТСЯ и будет читаться всегда, но не создаётся никогда.

PMVAULT2 — единственный формат записи:

    8  байт   magic = b"PMVAULT2"
    1  байт   идентификатор алгоритма (2 = Argon2id)
    4  байта  time_cost, uint32 BE
    4  байта  memory_cost в КиБ, uint32 BE
    1  байт   parallelism
    16 байт   соль
    12 байт   nonce (AES-GCM)
    далее     шифртекст AES-256-GCM (тег аутентичности 16 байт в конце)

PMVAULT1 — только чтение, для файлов версий 1.x, 2.x и старых снимков:

    8  байт   magic = b"PMVAULT1"
    4  байта  число итераций PBKDF2, uint32 big-endian
    16 байт   соль
    12 байт   nonce
    далее     шифртекст AES-256-GCM

Почему выброшен PBKDF2
----------------------
PBKDF2 считается процессором и почти не требует памяти. Видеокарта — это
тысячи маленьких вычислителей; раз память не нужна, злоумышленник гоняет на
одной карте тысячи попыток параллельно, и перебор идёт на порядки быстрее,
чем на процессоре владельца файла.

Argon2id требует 256 МиБ на КАЖДУЮ попытку. Карта с 24 ГБ памяти удержит
меньше сотни попыток вместо тысяч — преимущество видеокарты исчезает. Для
хранилища паролей это единственный разумный выбор, а держать рядом второй,
заведомо более слабый вариант — значит предлагать пользователю выбрать
похуже. Выбор убран вместе с кнопкой «Формат шифрования».

Почему чтение PMVAULT1 остаётся навсегда
----------------------------------------
Формат записан в первых восьми байтах файла. Выброси разбор PMVAULT1 — и
каждое существующее хранилище, каждый vault.pmv.prev и каждый снимок в архиве
станут нечитаемыми: программа увидит незнакомый magic и откажется. Поэтому
PMVAULT1 читается, а при первом же открытии хранилище само переезжает на
PMVAULT2 (session.Vault.open), сняв перед этим копию в архив.

Android-версия открывает оба формата: Argon2id там считается чистой Java
(BouncyCastle), нативная библиотека не нужна.

GCM даёт не только шифрование, но и аутентификацию: повреждение, подмена и
неверный пароль дают ошибку расшифровки, а не правдоподобный мусор.

Все числа, прочитанные ИЗ ЗАГОЛОВКА, проверяются на разумность. Файл может
быть чужим, повреждённым или подделанным, и верить его заголовку нельзя: без
проверки подсунутый файл с максимальным uint32 в поле итераций замораживал
программу на минуты без возможности отмены.
"""

import hashlib
import hmac
import json
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_V1 = b"PMVAULT1"
MAGIC_V2 = b"PMVAULT2"

KDF_PBKDF2 = 1
KDF_ARGON2ID = 2

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
GCM_TAG_LEN = 16

# Использовалось при записи PMVAULT1. Программа таких файлов больше не создаёт;
# число оставлено для старых файлов, у которых итерации записаны в заголовке.
KDF_ITERATIONS = 600_000

# Границы для значений из заголовка файла.
MIN_ITERATIONS = 10_000
MAX_ITERATIONS = 20_000_000

# Параметры Argon2id. Совпадают с тем, что писала версия 2.0, поэтому её файлы
# открываются и переоткрываются без сюрпризов. 256 МиБ — намеренно много: это
# и есть то, что обесценивает перебор на видеокартах.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 256 * 1024        # 256 МиБ
ARGON2_PARALLELISM = 4

MAX_ARGON2_TIME_COST = 64
MAX_ARGON2_MEMORY_KIB = 2 * 1024 * 1024   # 2 ГиБ — дальше начинается отказ в обслуживании
MIN_ARGON2_MEMORY_KIB = 8
MAX_ARGON2_PARALLELISM = 64

# Хранилище паролей столько не весит. Ограничение нужно, чтобы случайно
# выбранный многогигабайтный файл не был целиком прочитан в память.
MAX_VAULT_BYTES = 64 * 1024 * 1024


class VaultError(ValueError):
    """Ошибка формата, пароля или целостности файла хранилища."""


ARGON2_MISSING = ("Не найдена библиотека argon2-cffi, без неё PassVault не "
                  "может ни создать хранилище, ни открыть его.\n"
                  "Установи её командой:  pip install argon2-cffi")


def argon2_available():
    """Установлена ли argon2-cffi.

    Раньше она была необязательной, и без неё программа просто не предлагала
    «усиленный» формат. Теперь Argon2id — единственный формат записи, поэтому
    отсутствие библиотеки это не ограничение возможностей, а неработающая
    программа: она обязана сказать об этом сразу, а не в момент, когда человек
    попробует сохранить хранилище. Проверка стоит на старте (passvault.py).
    В собранном exe библиотека всегда внутри — её кладёт build.py.
    """
    try:
        import argon2.low_level  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Параметры получения ключа
# ---------------------------------------------------------------------------
class KdfParams:
    """Описание того, как из мастер-пароля получается ключ AES."""

    __slots__ = ("kdf_id", "salt", "iterations",
                 "time_cost", "memory_kib", "parallelism")

    def __init__(self, kdf_id, salt, iterations=KDF_ITERATIONS,
                 time_cost=ARGON2_TIME_COST, memory_kib=ARGON2_MEMORY_KIB,
                 parallelism=ARGON2_PARALLELISM):
        self.kdf_id = kdf_id
        self.salt = salt
        self.iterations = iterations
        self.time_cost = time_cost
        self.memory_kib = memory_kib
        self.parallelism = parallelism

    @staticmethod
    def default():
        """Параметры для ЛЮБОЙ новой записи. Единственный формат программы."""
        return KdfParams.new_argon2id()

    @staticmethod
    def new_pbkdf2(iterations=KDF_ITERATIONS):
        """Устаревшие параметры PMVAULT1.

        Программа такие файлы НЕ СОЗДАЁТ. Метод нужен, чтобы собрать параметры
        для чтения старого файла и чтобы тесты могли изготовить такой файл и
        проверить, что он открывается и переезжает на Argon2id.
        """
        return KdfParams(KDF_PBKDF2, secrets.token_bytes(SALT_LEN),
                         iterations=iterations)

    @staticmethod
    def new_argon2id(time_cost=ARGON2_TIME_COST, memory_kib=ARGON2_MEMORY_KIB,
                     parallelism=ARGON2_PARALLELISM):
        return KdfParams(KDF_ARGON2ID, secrets.token_bytes(SALT_LEN),
                         time_cost=time_cost, memory_kib=memory_kib,
                         parallelism=parallelism)

    @property
    def is_legacy(self):
        """True для PMVAULT1 — старого формата, который только читается."""
        return self.kdf_id == KDF_PBKDF2

    @property
    def needs_upgrade(self):
        """Файл записан устаревшим KDF и подлежит переводу на Argon2id."""
        return self.is_legacy

    @property
    def magic(self):
        return MAGIC_V1 if self.is_legacy else MAGIC_V2

    def with_new_salt(self):
        """Те же параметры, но новая соль — для смены мастер-пароля."""
        p = KdfParams(self.kdf_id, secrets.token_bytes(SALT_LEN),
                      iterations=self.iterations, time_cost=self.time_cost,
                      memory_kib=self.memory_kib, parallelism=self.parallelism)
        return p

    def describe(self):
        if self.is_legacy:
            return "PBKDF2-HMAC-SHA256, %d итераций" % self.iterations
        return ("Argon2id, %d прохода, %d МиБ памяти, %d потока"
                % (self.time_cost, self.memory_kib // 1024, self.parallelism))

    def describe_container(self):
        """Короткая пометка формата для статусной строки.

        Прежний текст обещал, что PMVAULT2 «Android-версия не откроет». Это
        было неправдой: телефон считает Argon2id через BouncyCastle и открывает
        оба формата — на это есть тесты и на ПК, и на Android. Надпись
        осталась от версии 2.0 и пугала пользователя на ровном месте.
        """
        if self.is_legacy:
            return "PMVAULT1 · старый формат, будет обновлён"
        return "PMVAULT2 · Argon2id"

    def __eq__(self, other):
        if not isinstance(other, KdfParams):
            return NotImplemented
        return all(getattr(self, f) == getattr(other, f) for f in self.__slots__)

    def __repr__(self):   # pragma: no cover — только для отладки
        return "<KdfParams %s>" % self.describe()


# ---------------------------------------------------------------------------
# Получение ключа
# ---------------------------------------------------------------------------
def derive_key(password, params):
    """Мастер-пароль -> 32-байтный ключ AES."""
    raw = password.encode("utf-8")

    if params.kdf_id == KDF_PBKDF2:
        return hashlib.pbkdf2_hmac("sha256", raw, params.salt,
                                   params.iterations, dklen=KEY_LEN)

    if params.kdf_id == KDF_ARGON2ID:
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            raise VaultError(ARGON2_MISSING)
        return hash_secret_raw(
            secret=raw, salt=params.salt,
            time_cost=params.time_cost, memory_cost=params.memory_kib,
            parallelism=params.parallelism, hash_len=KEY_LEN, type=Type.ID)

    raise VaultError("Неизвестный алгоритм получения ключа (id=%d)" % params.kdf_id)


# ---------------------------------------------------------------------------
# Разбор и сборка контейнера
# ---------------------------------------------------------------------------
def parse_container(blob):
    """Разбирает заголовок. Возвращает (KdfParams, nonce, ciphertext).

    Заголовку файла нельзя верить на слово: он может быть чужим, повреждённым
    или подделанным. Каждое прочитанное число проверяется на разумность.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise VaultError("Ожидались байты файла хранилища")
    blob = bytes(blob)

    if len(blob) > MAX_VAULT_BYTES:
        raise VaultError("Файл слишком велик для хранилища PassVault (%d байт)"
                         % len(blob))

    if blob.startswith(MAGIC_V1):
        min_len = len(MAGIC_V1) + 4 + SALT_LEN + NONCE_LEN + GCM_TAG_LEN
        if len(blob) < min_len:
            raise VaultError("Файл хранилища обрезан или повреждён")
        off = len(MAGIC_V1)
        iterations = struct.unpack(">I", blob[off:off + 4])[0]
        off += 4
        if not (MIN_ITERATIONS <= iterations <= MAX_ITERATIONS):
            raise VaultError(
                "Недопустимое число итераций в заголовке файла (%d). "
                "Файл повреждён или подделан." % iterations)
        salt = blob[off:off + SALT_LEN]
        off += SALT_LEN
        nonce = blob[off:off + NONCE_LEN]
        off += NONCE_LEN
        return KdfParams(KDF_PBKDF2, salt, iterations=iterations), nonce, blob[off:]

    if blob.startswith(MAGIC_V2):
        min_len = len(MAGIC_V2) + 1 + 4 + 4 + 1 + SALT_LEN + NONCE_LEN + GCM_TAG_LEN
        if len(blob) < min_len:
            raise VaultError("Файл хранилища обрезан или повреждён")
        off = len(MAGIC_V2)
        kdf_id = blob[off]
        off += 1
        if kdf_id != KDF_ARGON2ID:
            raise VaultError("Неизвестный алгоритм получения ключа (id=%d)" % kdf_id)
        time_cost = struct.unpack(">I", blob[off:off + 4])[0]
        off += 4
        memory_kib = struct.unpack(">I", blob[off:off + 4])[0]
        off += 4
        parallelism = blob[off]
        off += 1
        if not (1 <= time_cost <= MAX_ARGON2_TIME_COST):
            raise VaultError("Недопустимый параметр time_cost в заголовке (%d)"
                             % time_cost)
        if not (MIN_ARGON2_MEMORY_KIB <= memory_kib <= MAX_ARGON2_MEMORY_KIB):
            raise VaultError("Недопустимый объём памяти в заголовке (%d КиБ)"
                             % memory_kib)
        if not (1 <= parallelism <= MAX_ARGON2_PARALLELISM):
            raise VaultError("Недопустимый параметр parallelism в заголовке (%d)"
                             % parallelism)
        salt = blob[off:off + SALT_LEN]
        off += SALT_LEN
        nonce = blob[off:off + NONCE_LEN]
        off += NONCE_LEN
        params = KdfParams(KDF_ARGON2ID, salt, time_cost=time_cost,
                           memory_kib=memory_kib, parallelism=parallelism)
        return params, nonce, blob[off:]

    raise VaultError("Это не файл хранилища PassVault (или он повреждён)")


def _header(params):
    if params.is_legacy:
        return MAGIC_V1 + struct.pack(">I", params.iterations) + params.salt
    return (MAGIC_V2 + bytes([KDF_ARGON2ID])
            + struct.pack(">I", params.time_cost)
            + struct.pack(">I", params.memory_kib)
            + bytes([params.parallelism])
            + params.salt)


def serialize(data):
    """Открытый текст хранилища в каноническом виде.

    sort_keys нужен не для красоты: отпечаток содержимого, по которому архив
    снимков решает «менялось ли что-нибудь», должен зависеть от данных, а не
    от случайного порядка ключей в словаре.
    """
    return json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def encrypt_with_key(data, key, params):
    """Шифрует хранилище готовым ключом. Новый случайный nonce на каждую запись."""
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, serialize(data), None)
    return _header(params) + nonce + ciphertext


def create_encrypted(data, password, params=None):
    """Первое шифрование. Возвращает (blob, key, params).

    Без явных параметров — всегда Argon2id. Раньше здесь по умолчанию стоял
    PBKDF2, и каждое новое хранилище создавалось слабейшим из двух вариантов.
    """
    params = params or KdfParams.default()
    key = derive_key(password, params)
    return encrypt_with_key(data, key, params), key, params


def _decode(plaintext):
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise VaultError("Содержимое хранилища повреждено (не читается как JSON)")


def decrypt_with_key(blob, key):
    """Расшифровывает БЕЗ прогона KDF — ключ уже есть.

    Стоит около миллисекунды, поэтому применимо для проверки только что
    записанного файла при каждом сохранении: порча ловится, пока предыдущая
    версия ещё цела.
    """
    _params, nonce, ciphertext = parse_container(blob)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise VaultError("Файл не расшифровывается этим ключом "
                         "(повреждён или подменён)")
    return _decode(plaintext)


def decrypt_vault(blob, password):
    """Расшифровывает файл мастер-паролем. Возвращает (data, key, params)."""
    params, nonce, ciphertext = parse_container(blob)
    key = derive_key(password, params)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise VaultError("Неверный мастер-пароль (или файл повреждён/подменён)")
    return _decode(plaintext), key, params


def key_matches(password, key, params):
    """Проверка мастер-пароля за постоянное время (для смены пароля)."""
    return hmac.compare_digest(derive_key(password, params), key)
