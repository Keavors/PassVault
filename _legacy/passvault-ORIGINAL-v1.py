#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PassVault — офлайн-хранилище и генератор паролей (версия для ПК).

Запуск:        python passvault.py
Самопроверка:  python passvault.py --test
Зависимость:   pip install cryptography

ФОРМАТ ФАЙЛА vault.pmv (версия 1) — важно: Android-версия использует
байт-в-байт тот же формат, поэтому синхронизация = простое копирование файла.

    8  байт   magic = b"PMVAULT1"
    4  байта  iterations PBKDF2, uint32 big-endian
    16 байт   salt
    12 байт   nonce (AES-GCM)
    остальное ciphertext AES-256-GCM (16-байтный тег аутентичности в конце)

Ключ:            PBKDF2-HMAC-SHA256(мастер-пароль в UTF-8, salt, iterations) -> 32 байта
Открытый текст:  JSON UTF-8 {"version":1, "entries":[...], "settings":{...}}

GCM не только шифрует, но и проверяет целостность: любое повреждение или
подмена файла, а также неверный мастер-пароль дают ошибку расшифровки.
"""

import os
import sys
import json
import time
import math
import hmac
import struct
import hashlib
import secrets
import random

# ----------------------------------------------------------------------------
# 1. Блокировка сети изнутри программы.
#    Программа и так не делает ни одного сетевого вызова, но на всякий случай
#    отключаем сетевые функции Python целиком: любая попытка (в т.ч. случайно
#    затянутой библиотекой) открыть соединение упадёт с ошибкой.
#    Гарантия уровня ОС — правило брандмауэра (см. README).
# ----------------------------------------------------------------------------
import socket as _socket


def _network_blocked(*_args, **_kwargs):
    raise OSError("PassVault: доступ к сети заблокирован этим приложением")


for _name in ("socket", "socketpair", "create_connection", "create_server",
              "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
    if hasattr(_socket, _name):
        setattr(_socket, _name, _network_blocked)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.stderr.write("Не найдена библиотека cryptography.\n"
                     "Установи её командой:  pip install cryptography\n")
    raise

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception:  # окружение без GUI — доступен только режим --test
    tk = None

# ----------------------------------------------------------------------------
# Константы
# ----------------------------------------------------------------------------
MAGIC = b"PMVAULT1"
KDF_ITERATIONS = 600_000          # замедляет перебор мастер-пароля
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
GCM_TAG_LEN = 16

VAULT_FILENAME = "vault.pmv"
AUTO_LOCK_SECONDS = 5 * 60        # автоблокировка при бездействии
CLIPBOARD_CLEAR_MS = 30_000       # автоочистка буфера обмена
AUTOSAVE_DELAY_MS = 900           # автосохранение после последней правки

GROUP_LOWER = "abcdefghijklmnopqrstuvwxyz"
GROUP_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
GROUP_DIGITS = "0123456789"
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?"
AMBIGUOUS = "Il1O0o"              # похожие друг на друга символы

DEFAULT_GEN = {
    "use_lower": True,
    "use_upper": True,
    "use_digits": True,
    "use_symbols": True,
    "symbols": DEFAULT_SYMBOLS,   # набор спецсимволов можно править
    "require_each": True,         # минимум по одному из каждой выбранной группы
    "exact_mode": True,           # True = точная длина, False = диапазон
    "exact_len": 16,
    "min_len": 12,
    "max_len": 20,
    "required_chars": "",         # эти символы обязаны попасть в пароль
    "excluded_chars": "",         # эти символы никогда не попадут в пароль
    "no_ambiguous": False,        # исключить I l 1 O 0 o
}


# ----------------------------------------------------------------------------
# 2. Криптография
# ----------------------------------------------------------------------------
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Мастер-пароль -> 32-байтный ключ AES (PBKDF2-HMAC-SHA256)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt, iterations, dklen=KEY_LEN)


def encrypt_with_key(data: dict, key: bytes, salt: bytes, iterations: int) -> bytes:
    """Шифрует хранилище уже готовым ключом (новый случайный nonce на каждую запись)."""
    nonce = secrets.token_bytes(NONCE_LEN)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + struct.pack(">I", iterations) + salt + nonce + ciphertext


def create_encrypted(data: dict, password: str, iterations: int = KDF_ITERATIONS):
    """Первое шифрование: новая соль -> новый ключ. Возвращает (blob, key, salt, iterations)."""
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt, iterations)
    return encrypt_with_key(data, key, salt, iterations), key, salt, iterations


def parse_container(blob: bytes):
    """Разбирает заголовок файла. Возвращает (iterations, salt, nonce, ciphertext)."""
    min_len = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN + GCM_TAG_LEN
    if len(blob) < min_len or not blob.startswith(MAGIC):
        raise ValueError("Это не файл хранилища PassVault (или он повреждён)")
    off = len(MAGIC)
    iterations = struct.unpack(">I", blob[off:off + 4])[0]
    off += 4
    salt = blob[off:off + SALT_LEN]
    off += SALT_LEN
    nonce = blob[off:off + NONCE_LEN]
    off += NONCE_LEN
    return iterations, salt, nonce, blob[off:]


def decrypt_vault(blob: bytes, password: str):
    """Расшифровывает файл. Возвращает (data, key, salt, iterations).
    Неверный пароль / подмена / повреждение -> ValueError."""
    iterations, salt, nonce, ciphertext = parse_container(blob)
    key = derive_key(password, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Неверный мастер-пароль (или файл повреждён/подменён)")
    return json.loads(plaintext.decode("utf-8")), key, salt, iterations


# ----------------------------------------------------------------------------
# 3. Генератор паролей (криптографический ГСЧ операционной системы)
# ----------------------------------------------------------------------------
def generate_password(o: dict):
    """Генерирует пароль по настройкам o (см. DEFAULT_GEN).
    Возвращает (пароль, размер_алфавита). Ошибки настроек -> ValueError."""
    rng = random.SystemRandom()  # источник — os.urandom, криптографически стойкий

    excluded = set(o.get("excluded_chars", ""))
    if o.get("no_ambiguous"):
        excluded |= set(AMBIGUOUS)

    selected_groups = []
    if o.get("use_lower"):
        selected_groups.append(GROUP_LOWER)
    if o.get("use_upper"):
        selected_groups.append(GROUP_UPPER)
    if o.get("use_digits"):
        selected_groups.append(GROUP_DIGITS)
    if o.get("use_symbols"):
        selected_groups.append(o.get("symbols") or "")

    pools = []
    for g in selected_groups:
        p = [c for c in dict.fromkeys(g) if c not in excluded]
        if p:
            pools.append(p)
        elif g:
            raise ValueError("Одна из выбранных групп целиком попала в исключения — "
                             "убери исключения или сними галочку с этой группы")

    # обязательные символы: пробелы игнорируем, повторы схлопываем
    required = [c for c in dict.fromkeys(o.get("required_chars", "")) if not c.isspace()]
    conflict = [c for c in required if c in excluded]
    if conflict:
        raise ValueError("Символы «%s» одновременно и обязательны, и исключены"
                         % "".join(conflict))

    pool = sorted(set(c for p in pools for c in p) | set(required))
    if not pool:
        raise ValueError("Набор символов пуст: включи хотя бы одну группу "
                         "или впиши обязательные символы")

    if o.get("exact_mode", True):
        length = int(o.get("exact_len", 16))
    else:
        lo, hi = int(o.get("min_len", 12)), int(o.get("max_len", 20))
        if lo > hi:
            lo, hi = hi, lo
        length = rng.randint(lo, hi)  # SystemRandom.randint — без смещения
    length = max(1, min(512, length))

    guaranteed = list(required)
    if o.get("require_each"):
        guaranteed += [rng.choice(p) for p in pools]
    if len(guaranteed) > length:
        raise ValueError("Обязательных символов (%d) больше, чем длина пароля (%d) — "
                         "увеличь длину" % (len(guaranteed), length))

    chars = guaranteed + [rng.choice(pool) for _ in range(length - len(guaranteed))]
    rng.shuffle(chars)  # тоже на криптографическом ГСЧ
    return "".join(chars), len(pool)


# ----------------------------------------------------------------------------
# 4. Мелкие помощники
# ----------------------------------------------------------------------------
def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M")


def new_entry_dict() -> dict:
    t = now_str()
    return {"id": secrets.token_hex(8), "title": "Новая запись", "login": "",
            "password": "", "notes": "", "created": t, "modified": t}


def app_dir() -> str:
    """Папка рядом с программой (учитывает сборку в .exe через PyInstaller)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


# ----------------------------------------------------------------------------
# 5. Самопроверка:  python passvault.py --test
# ----------------------------------------------------------------------------
def run_selftest():
    print("Самопроверка PassVault...")

    # --- шифрование / расшифровка ---
    data = {"version": 1,
            "entries": [{"id": "x1", "title": "Тестовая запись", "login": "user",
                         "password": "пАроль Йц1!", "notes": "заметки ёЁ"}],
            "settings": {"generator": dict(DEFAULT_GEN)}}
    blob, key, salt, iters = create_encrypted(data, "мастер-фраза проверки", iterations=20_000)
    data2, key2, salt2, iters2 = decrypt_vault(blob, "мастер-фраза проверки")
    assert data2 == data and key2 == key and salt2 == salt and iters2 == 20_000
    print("  [ok] шифрование и расшифровка (кириллица в данных сохраняется)")

    for wrong in ("мастер-фраза проверки2", "", "MASTER"):
        try:
            decrypt_vault(blob, wrong)
            raise AssertionError("файл открылся с неверным паролем!")
        except ValueError:
            pass
    print("  [ok] неверный мастер-пароль отклоняется")

    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF
    try:
        decrypt_vault(bytes(tampered), "мастер-фраза проверки")
        raise AssertionError("подмена файла не замечена!")
    except ValueError:
        pass
    try:
        decrypt_vault(b"not a vault at all", "x")
        raise AssertionError("мусор принят за хранилище!")
    except ValueError:
        pass
    print("  [ok] подмена/повреждение файла обнаруживается (GCM)")

    # --- генератор: точная длина, обязательные и исключённые символы ---
    o = dict(DEFAULT_GEN)
    o.update(exact_mode=True, exact_len=20, required_chars="Ж#",
             excluded_chars="abcdef", no_ambiguous=True, require_each=True)
    for _ in range(300):
        p, pool = generate_password(o)
        assert len(p) == 20
        assert "Ж" in p and "#" in p
        assert not (set("abcdef") | set(AMBIGUOUS)) & set(p)
        assert any(c in GROUP_LOWER for c in p)
        assert any(c in GROUP_UPPER for c in p)
        assert any(c in GROUP_DIGITS for c in p)
        assert any(c in DEFAULT_SYMBOLS for c in p)
    print("  [ok] точная длина, обязательные/исключённые символы, по одному из групп")

    # --- генератор: диапазон длины ---
    o2 = dict(DEFAULT_GEN)
    o2.update(exact_mode=False, min_len=10, max_len=14)
    lengths = set()
    for _ in range(300):
        p, _ = generate_password(o2)
        assert 10 <= len(p) <= 14
        lengths.add(len(p))
    assert len(lengths) >= 3, "длина в диапазоне должна варьироваться"
    print("  [ok] диапазон длины работает, длины варьируются:", sorted(lengths))

    # --- генератор: только обязательные символы, без групп ---
    o3 = dict(DEFAULT_GEN)
    o3.update(use_lower=False, use_upper=False, use_digits=False, use_symbols=False,
              required_chars="XY", exact_mode=True, exact_len=8, require_each=False)
    p, _ = generate_password(o3)
    assert len(p) == 8 and set(p) <= {"X", "Y"} and "X" in p and "Y" in p
    print("  [ok] режим «только заданные символы»")

    # --- генератор: ошибки настроек ---
    def expect_error(opts):
        try:
            generate_password(opts)
            raise AssertionError("ожидалась ошибка настроек")
        except ValueError:
            pass

    bad = dict(DEFAULT_GEN)
    bad.update(use_lower=False, use_upper=False, use_digits=False,
               use_symbols=False, required_chars="")
    expect_error(bad)                                   # пустой алфавит

    bad = dict(DEFAULT_GEN)
    bad.update(exact_mode=True, exact_len=3, required_chars="ABCDE", require_each=False)
    expect_error(bad)                                   # обязательных больше длины

    bad = dict(DEFAULT_GEN)
    bad.update(required_chars="a", excluded_chars="a")
    expect_error(bad)                                   # конфликт обязательный/исключённый
    print("  [ok] противоречивые настройки отклоняются с понятной ошибкой")

    # --- сеть заблокирована ---
    try:
        _socket.socket()
        raise AssertionError("сокет создался, а не должен был")
    except OSError:
        pass
    print("  [ok] сетевые функции Python заблокированы")

    print("\nВсе проверки пройдены ✔")


# ----------------------------------------------------------------------------
# 6. Графический интерфейс (tkinter)
# ----------------------------------------------------------------------------
if tk is not None:

    MONO = ("Consolas", 11)

    class GeneratorDialog(tk.Toplevel):
        """Окно генератора со всеми настройками. Настройки сохраняются в хранилище."""

        def __init__(self, app, settings: dict, on_use=None):
            super().__init__(app)
            self.app = app
            self.on_use = on_use          # callback «вставить в запись» (или None)
            self.settings = settings      # живой dict из data["settings"]["generator"]
            self.title("Генератор паролей")
            self.resizable(False, False)
            self.transient(app)
            self.grab_set()

            s = settings
            self.v_lower = tk.BooleanVar(value=s.get("use_lower", True))
            self.v_upper = tk.BooleanVar(value=s.get("use_upper", True))
            self.v_digits = tk.BooleanVar(value=s.get("use_digits", True))
            self.v_symbols = tk.BooleanVar(value=s.get("use_symbols", True))
            self.v_symbols_set = tk.StringVar(value=s.get("symbols", DEFAULT_SYMBOLS))
            self.v_require = tk.BooleanVar(value=s.get("require_each", True))
            self.v_noamb = tk.BooleanVar(value=s.get("no_ambiguous", False))
            self.v_mode = tk.StringVar(value="exact" if s.get("exact_mode", True) else "range")
            self.v_exact = tk.IntVar(value=int(s.get("exact_len", 16)))
            self.v_min = tk.IntVar(value=int(s.get("min_len", 12)))
            self.v_max = tk.IntVar(value=int(s.get("max_len", 20)))
            self.v_reqchars = tk.StringVar(value=s.get("required_chars", ""))
            self.v_exclchars = tk.StringVar(value=s.get("excluded_chars", ""))
            self.v_result = tk.StringVar()

            frm = ttk.Frame(self, padding=12)
            frm.grid(sticky="nsew")

            # --- длина ---
            lf = ttk.LabelFrame(frm, text="Длина", padding=8)
            lf.grid(row=0, column=0, sticky="ew")
            ttk.Radiobutton(lf, text="Точная:", variable=self.v_mode,
                            value="exact", command=self._sync).grid(row=0, column=0, sticky="w")
            self.sp_exact = ttk.Spinbox(lf, from_=1, to=256, width=5, textvariable=self.v_exact)
            self.sp_exact.grid(row=0, column=1, padx=(4, 24))
            ttk.Radiobutton(lf, text="Диапазон:", variable=self.v_mode,
                            value="range", command=self._sync).grid(row=0, column=2, sticky="w")
            self.sp_min = ttk.Spinbox(lf, from_=1, to=256, width=5, textvariable=self.v_min)
            self.sp_min.grid(row=0, column=3, padx=4)
            ttk.Label(lf, text="—").grid(row=0, column=4)
            self.sp_max = ttk.Spinbox(lf, from_=1, to=256, width=5, textvariable=self.v_max)
            self.sp_max.grid(row=0, column=5, padx=4)

            # --- группы символов ---
            gf = ttk.LabelFrame(frm, text="Группы символов", padding=8)
            gf.grid(row=1, column=0, sticky="ew", pady=(8, 0))
            ttk.Checkbutton(gf, text="Строчные латинские (a–z)",
                            variable=self.v_lower).grid(row=0, column=0, columnspan=2, sticky="w")
            ttk.Checkbutton(gf, text="Заглавные латинские (A–Z)",
                            variable=self.v_upper).grid(row=1, column=0, columnspan=2, sticky="w")
            ttk.Checkbutton(gf, text="Цифры (0–9)",
                            variable=self.v_digits).grid(row=2, column=0, columnspan=2, sticky="w")
            ttk.Checkbutton(gf, text="Спецсимволы:",
                            variable=self.v_symbols).grid(row=3, column=0, sticky="w")
            ttk.Entry(gf, textvariable=self.v_symbols_set, width=28,
                      font=MONO).grid(row=3, column=1, sticky="w", padx=(4, 0))
            ttk.Checkbutton(gf, text="Минимум по одному символу из каждой выбранной группы",
                            variable=self.v_require).grid(row=4, column=0, columnspan=2,
                                                          sticky="w", pady=(6, 0))
            ttk.Checkbutton(gf, text="Исключить похожие символы (I l 1 O 0 o)",
                            variable=self.v_noamb).grid(row=5, column=0, columnspan=2, sticky="w")

            # --- тонкая настройка ---
            ef = ttk.LabelFrame(frm, text="Тонкая настройка", padding=8)
            ef.grid(row=2, column=0, sticky="ew", pady=(8, 0))
            ef.columnconfigure(1, weight=1)
            ttk.Label(ef, text="Обязательно включить:").grid(row=0, column=0, sticky="e", padx=(0, 4))
            ttk.Entry(ef, textvariable=self.v_reqchars, font=MONO).grid(row=0, column=1, sticky="ew")
            ttk.Label(ef, text="Исключить символы:").grid(row=1, column=0, sticky="e",
                                                          padx=(0, 4), pady=(4, 0))
            ttk.Entry(ef, textvariable=self.v_exclchars, font=MONO).grid(row=1, column=1,
                                                                         sticky="ew", pady=(4, 0))
            ttk.Label(ef, text="Можно вписывать любые символы, включая кириллицу.",
                      foreground="#888").grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

            # --- результат ---
            rf = ttk.Frame(frm)
            rf.grid(row=3, column=0, sticky="ew", pady=(10, 0))
            rf.columnconfigure(0, weight=1)
            ttk.Entry(rf, textvariable=self.v_result, font=("Consolas", 12),
                      width=42).grid(row=0, column=0, sticky="ew")
            self.lb_entropy = ttk.Label(rf, text="", foreground="#555")
            self.lb_entropy.grid(row=1, column=0, sticky="w", pady=(3, 0))

            # --- кнопки ---
            bf = ttk.Frame(frm)
            bf.grid(row=4, column=0, sticky="ew", pady=(10, 0))
            ttk.Button(bf, text="Сгенерировать", command=self.do_generate).pack(side="left")
            ttk.Button(bf, text="Копировать", command=self.do_copy).pack(side="left", padx=6)
            if self.on_use:
                ttk.Button(bf, text="Вставить в запись", command=self.do_use).pack(side="left")
            ttk.Button(bf, text="Закрыть", command=self.destroy).pack(side="right")

            self._sync()
            self.bind("<Return>", lambda e: self.do_generate())
            self.bind("<Escape>", lambda e: self.destroy())
            self.geometry("+%d+%d" % (app.winfo_rootx() + 60, app.winfo_rooty() + 60))

        def _sync(self):
            exact = self.v_mode.get() == "exact"
            self.sp_exact.config(state="normal" if exact else "disabled")
            state = "disabled" if exact else "normal"
            self.sp_min.config(state=state)
            self.sp_max.config(state=state)

        @staticmethod
        def _int(var, default):
            try:
                return int(var.get())
            except (tk.TclError, ValueError):
                return default

        def _collect(self) -> dict:
            return {
                "use_lower": self.v_lower.get(),
                "use_upper": self.v_upper.get(),
                "use_digits": self.v_digits.get(),
                "use_symbols": self.v_symbols.get(),
                "symbols": self.v_symbols_set.get(),
                "require_each": self.v_require.get(),
                "exact_mode": self.v_mode.get() == "exact",
                "exact_len": self._int(self.v_exact, 16),
                "min_len": self._int(self.v_min, 12),
                "max_len": self._int(self.v_max, 20),
                "required_chars": self.v_reqchars.get(),
                "excluded_chars": self.v_exclchars.get(),
                "no_ambiguous": self.v_noamb.get(),
            }

        def do_generate(self):
            opts = self._collect()
            try:
                pwd, pool_size = generate_password(opts)
            except ValueError as e:
                messagebox.showerror("Генератор", str(e), parent=self)
                return
            self.v_result.set(pwd)
            bits = len(pwd) * math.log2(pool_size) if pool_size > 1 else 0.0
            rating = ("слабый" if bits < 45 else
                      "средний" if bits < 64 else
                      "хороший" if bits < 80 else "отличный")
            self.lb_entropy.config(text="Стойкость: ≈%.0f бит — %s" % (bits, rating))
            # запоминаем настройки в хранилище (уедут и в файл, и потом на телефон)
            self.settings.clear()
            self.settings.update(opts)
            self.app.settings_changed()

        def do_copy(self):
            if self.v_result.get():
                self.app.copy_secret(self.v_result.get())

        def do_use(self):
            pwd = self.v_result.get()
            if pwd and self.on_use:
                self.on_use(pwd)
                self.destroy()

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("PassVault — офлайн-хранилище паролей")
            self.geometry("980x600")
            self.minsize(780, 480)

            self.vault_path = os.path.join(app_dir(), VAULT_FILENAME)
            self.data = None
            self.key = None
            self.salt = None
            self.iterations = KDF_ITERATIONS
            self.current_id = None
            self.view_ids = []
            self._save_job = None
            self._loading = False
            self.last_activity = time.time()
            self.status_var = tk.StringVar(value="")

            self.bind_all("<Any-KeyPress>", self._touch, add="+")
            self.bind_all("<Button>", self._touch, add="+")
            self.protocol("WM_DELETE_WINDOW", self._on_close)

            self.show_unlock()
            self.after(15_000, self._autolock_tick)

        # ------------------------------------------------ служебное
        def _touch(self, *_):
            self.last_activity = time.time()

        def _autolock_tick(self):
            if self.data is not None and time.time() - self.last_activity > AUTO_LOCK_SECONDS:
                self.lock("Заблокировано после %d минут бездействия" % (AUTO_LOCK_SECONDS // 60))
            self.after(15_000, self._autolock_tick)

        def _busy(self, on=True):
            try:
                self.config(cursor="watch" if on else "")
                self.update_idletasks()
            except tk.TclError:
                pass

        def _clear_window(self):
            self.config(menu="")
            for w in self.winfo_children():
                w.destroy()

        def status_msg(self, text):
            self.status_var.set(text)

        # ------------------------------------------------ экран входа
        def show_unlock(self, msg=None):
            self._clear_window()
            box = ttk.Frame(self, padding=24)
            box.place(relx=0.5, rely=0.42, anchor="center")

            ttk.Label(box, text="PassVault", font=("Segoe UI", 20, "bold")
                      ).grid(row=0, column=0, columnspan=2, pady=(0, 4))
            ttk.Label(box, text="Файл: " + self.vault_path, foreground="#666",
                      wraplength=480).grid(row=1, column=0, columnspan=2, pady=(0, 14))

            self._pw1 = tk.StringVar()
            self._pw2 = tk.StringVar()
            exists = os.path.exists(self.vault_path)

            if exists:
                ttk.Label(box, text="Мастер-пароль:").grid(row=2, column=0, sticky="e", padx=6, pady=4)
                e1 = ttk.Entry(box, textvariable=self._pw1, show="•", width=32, font=MONO)
                e1.grid(row=2, column=1, pady=4)
                ttk.Button(box, text="Открыть", command=self._unlock
                           ).grid(row=3, column=1, sticky="ew", pady=8)
                e1.bind("<Return>", lambda e: self._unlock())
                e1.focus_set()
            else:
                ttk.Label(box, justify="left",
                          text="Хранилище ещё не создано.\n"
                               "Придумай мастер-пароль — лучше фразу из 4–5 слов:"
                          ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 6))
                ttk.Label(box, text="Мастер-пароль:").grid(row=3, column=0, sticky="e", padx=6, pady=4)
                e1 = ttk.Entry(box, textvariable=self._pw1, show="•", width=32, font=MONO)
                e1.grid(row=3, column=1, pady=4)
                ttk.Label(box, text="Ещё раз:").grid(row=4, column=0, sticky="e", padx=6, pady=4)
                e2 = ttk.Entry(box, textvariable=self._pw2, show="•", width=32, font=MONO)
                e2.grid(row=4, column=1, pady=4)
                ttk.Button(box, text="Создать хранилище", command=self._create
                           ).grid(row=5, column=1, sticky="ew", pady=8)
                e2.bind("<Return>", lambda e: self._create())
                e1.focus_set()

            ttk.Button(box, text="Открыть другой файл…", command=self._pick_file
                       ).grid(row=9, column=1, sticky="e", pady=(16, 0))
            if msg:
                ttk.Label(box, text=msg, foreground="#b00000", wraplength=480
                          ).grid(row=10, column=0, columnspan=2, pady=(10, 0))

        def _pick_file(self):
            p = filedialog.askopenfilename(
                title="Файл хранилища",
                filetypes=[("Хранилище PassVault", "*.pmv"), ("Все файлы", "*.*")])
            if p:
                self.vault_path = p
                self.show_unlock()

        def _unlock(self):
            pw = self._pw1.get()
            if not pw:
                return
            try:
                with open(self.vault_path, "rb") as f:
                    blob = f.read()
            except OSError as e:
                messagebox.showerror("PassVault", "Не удалось прочитать файл:\n%s" % e, parent=self)
                return
            self._busy(True)
            try:
                data, key, salt, iters = decrypt_vault(blob, pw)
            except ValueError as e:
                self._busy(False)
                self.show_unlock(str(e))
                return
            self._busy(False)
            self.data, self.key, self.salt, self.iterations = data, key, salt, iters
            self.data.setdefault("entries", [])
            gen = dict(DEFAULT_GEN)
            gen.update(self.data.get("settings", {}).get("generator", {}) or {})
            self.data.setdefault("settings", {})["generator"] = gen
            self.show_main()

        def _create(self):
            p1, p2 = self._pw1.get(), self._pw2.get()
            if not p1:
                return
            if p1 != p2:
                messagebox.showerror("PassVault", "Пароли не совпадают", parent=self)
                return
            if len(p1) < 12 and not messagebox.askyesno(
                    "PassVault",
                    "Мастер-пароль короче 12 символов — его проще подобрать перебором.\n"
                    "Всё равно использовать?", parent=self):
                return
            self._busy(True)
            self.data = {"version": 1, "entries": [],
                         "settings": {"generator": dict(DEFAULT_GEN)}}
            blob, self.key, self.salt, self.iterations = create_encrypted(self.data, p1)
            try:
                self._write_blob(blob)
            except OSError as e:
                self._busy(False)
                self.data = self.key = self.salt = None
                messagebox.showerror("PassVault", "Не удалось записать файл:\n%s" % e, parent=self)
                return
            self._busy(False)
            self.show_main()

        # ------------------------------------------------ запись на диск
        def _write_blob(self, blob: bytes):
            """Атомарная запись + резервная копия предыдущей версии (.bak)."""
            tmp = self.vault_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(self.vault_path):
                try:
                    os.replace(self.vault_path, self.vault_path + ".bak")
                except OSError:
                    pass
            os.replace(tmp, self.vault_path)

        def save_to_disk(self):
            blob = encrypt_with_key(self.data, self.key, self.salt, self.iterations)
            self._write_blob(blob)

        def schedule_save(self):
            if self._save_job:
                self.after_cancel(self._save_job)
            self._save_job = self.after(AUTOSAVE_DELAY_MS, self._flush_save)

        def _flush_save(self):
            self._save_job = None
            if self.data is None or self.key is None:
                return
            try:
                self.save_to_disk()
                self.status_msg("Сохранено " + time.strftime("%H:%M:%S"))
            except OSError as e:
                messagebox.showerror("PassVault", "Не удалось сохранить файл:\n%s" % e, parent=self)

        def flush_now(self):
            if self._save_job:
                self.after_cancel(self._save_job)
                self._save_job = None
                if self.data is not None and self.key is not None:
                    try:
                        self.save_to_disk()
                    except OSError:
                        pass

        def settings_changed(self):
            self.schedule_save()

        # ------------------------------------------------ главный экран
        def show_main(self):
            self._clear_window()
            self._build_menu()

            bar = ttk.Frame(self, relief="groove", padding=(8, 2))
            bar.pack(side="bottom", fill="x")
            ttk.Label(bar, textvariable=self.status_var, foreground="#444").pack(side="left")

            outer = ttk.Frame(self)
            outer.pack(side="top", fill="both", expand=True)

            # левая колонка: поиск + список
            left = ttk.Frame(outer, padding=(10, 10, 6, 10))
            left.pack(side="left", fill="y")
            self.search_var = tk.StringVar()
            se = ttk.Entry(left, textvariable=self.search_var)
            se.pack(fill="x")
            se.bind("<KeyRelease>", lambda e: self.refresh_list())
            ttk.Label(left, text="поиск по названию, логину и заметкам",
                      foreground="#888", font=("Segoe UI", 8)).pack(anchor="w")

            lb_fr = ttk.Frame(left)
            lb_fr.pack(fill="both", expand=True, pady=(6, 6))
            self.listbox = tk.Listbox(lb_fr, width=32, exportselection=False, activestyle="dotbox")
            sb = ttk.Scrollbar(lb_fr, command=self.listbox.yview)
            self.listbox.config(yscrollcommand=sb.set)
            self.listbox.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            self.listbox.bind("<<ListboxSelect>>", self._on_select)

            btns = ttk.Frame(left)
            btns.pack(fill="x")
            ttk.Button(btns, text="＋ Новая запись", command=self.new_entry
                       ).pack(side="left", expand=True, fill="x", padx=(0, 3))
            ttk.Button(btns, text="Удалить", command=self.delete_entry
                       ).pack(side="left", expand=True, fill="x", padx=(3, 0))

            # правая колонка: поля записи
            right = ttk.Frame(outer, padding=(6, 10, 12, 10))
            right.pack(side="left", fill="both", expand=True)
            right.columnconfigure(1, weight=1)

            self.title_var = tk.StringVar()
            self.login_var = tk.StringVar()
            self.pass_var = tk.StringVar()
            self.meta_var = tk.StringVar()
            self.show_pw = tk.BooleanVar(value=False)

            r = 0
            ttk.Label(right, text="Название:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
            self.e_title = ttk.Entry(right, textvariable=self.title_var)
            self.e_title.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
            r += 1
            ttk.Label(right, text="Логин:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
            self.e_login = ttk.Entry(right, textvariable=self.login_var)
            self.e_login.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
            r += 1
            ttk.Label(right, text="Пароль:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
            self.e_pass = ttk.Entry(right, textvariable=self.pass_var, show="•", font=MONO)
            self.e_pass.grid(row=r, column=1, sticky="ew", pady=4)
            ttk.Checkbutton(right, text="показать", variable=self.show_pw,
                            command=self._toggle_pw).grid(row=r, column=2, padx=4)
            pwb = ttk.Frame(right)
            pwb.grid(row=r, column=3, padx=(2, 0))
            ttk.Button(pwb, text="Копировать", command=self.copy_password).pack(side="left", padx=2)
            ttk.Button(pwb, text="Сгенерировать…",
                       command=self.open_generator_for_entry).pack(side="left", padx=2)
            r += 1
            ttk.Label(right, text="Заметки:").grid(row=r, column=0, sticky="ne", padx=6, pady=4)
            nf = ttk.Frame(right)
            nf.grid(row=r, column=1, columnspan=3, sticky="nsew", pady=4)
            right.rowconfigure(r, weight=1)
            self.t_notes = tk.Text(nf, wrap="word", height=8, undo=True)
            nsb = ttk.Scrollbar(nf, command=self.t_notes.yview)
            self.t_notes.config(yscrollcommand=nsb.set)
            self.t_notes.pack(side="left", fill="both", expand=True)
            nsb.pack(side="right", fill="y")
            r += 1
            ttk.Label(right, textvariable=self.meta_var, foreground="#888"
                      ).grid(row=r, column=1, columnspan=3, sticky="w")

            for w in (self.e_title, self.e_login, self.e_pass):
                w.bind("<KeyRelease>", self._on_field_change)
                w.bind("<FocusOut>", self._on_field_change)
            self.t_notes.bind("<KeyRelease>", self._on_field_change)
            self.t_notes.bind("<FocusOut>", self._on_field_change)

            self._set_fields_state(False)
            self.current_id = None
            self.refresh_list()
            self.status_msg("Хранилище открыто. Записей: %d" % len(self.data["entries"]))

        def _build_menu(self):
            m = tk.Menu(self)
            fm = tk.Menu(m, tearoff=0)
            fm.add_command(label="Сохранить сейчас", command=self._flush_save, accelerator="Ctrl+S")
            fm.add_command(label="Сменить мастер-пароль…", command=self.change_master)
            fm.add_separator()
            fm.add_command(label="Заблокировать", command=lambda: self.lock(), accelerator="Ctrl+L")
            fm.add_separator()
            fm.add_command(label="Выход", command=self._on_close)
            m.add_cascade(label="Файл", menu=fm)

            tm = tk.Menu(m, tearoff=0)
            tm.add_command(label="Генератор паролей…",
                           command=lambda: GeneratorDialog(
                               self, self.data["settings"]["generator"]))
            m.add_cascade(label="Инструменты", menu=tm)

            hm = tk.Menu(m, tearoff=0)
            hm.add_command(label="О программе", command=self._about)
            m.add_cascade(label="Справка", menu=hm)

            self.config(menu=m)
            self.bind("<Control-s>", lambda e: self._flush_save())
            self.bind("<Control-l>", lambda e: self.lock())

        def _about(self):
            messagebox.showinfo(
                "О программе",
                "PassVault (офлайн)\n\n"
                "Файл: %s\n"
                "Шифрование: AES-256-GCM\n"
                "Ключ: PBKDF2-HMAC-SHA256, %d итераций\n\n"
                "Сетевые функции Python отключены внутри программы;\n"
                "для гарантии на уровне ОС добавь правило брандмауэра (см. README).\n"
                "Резервная копия предыдущей версии: %s.bak (тоже зашифрована)."
                % (self.vault_path, self.iterations, VAULT_FILENAME),
                parent=self)

        # ------------------------------------------------ список записей
        def _display_title(self, e) -> str:
            return e["title"].strip() or "(без названия)"

        def _entry_by_id(self, eid):
            return next((x for x in self.data["entries"] if x["id"] == eid), None)

        def refresh_list(self, select_id=None):
            q = self.search_var.get().lower().strip()
            self.view_ids = []
            self.listbox.delete(0, "end")
            for e in sorted(self.data["entries"], key=lambda x: x["title"].lower()):
                hay = (e["title"] + " " + e.get("login", "") + " " + e.get("notes", "")).lower()
                if q and q not in hay:
                    continue
                self.view_ids.append(e["id"])
                self.listbox.insert("end", self._display_title(e))
            if select_id is None:
                select_id = self.current_id
            if select_id in self.view_ids:
                i = self.view_ids.index(select_id)
                self.listbox.selection_set(i)
                self.listbox.see(i)

        def _on_select(self, _event=None):
            sel = self.listbox.curselection()
            if not sel:
                return
            eid = self.view_ids[sel[0]]
            if eid != self.current_id:
                self.load_entry(eid)

        def load_entry(self, eid):
            e = self._entry_by_id(eid)
            if not e:
                return
            self.current_id = eid
            self._loading = True
            self._set_fields_state(True)
            self.title_var.set(e["title"])
            self.login_var.set(e.get("login", ""))
            self.pass_var.set(e.get("password", ""))
            self.t_notes.delete("1.0", "end")
            self.t_notes.insert("1.0", e.get("notes", ""))
            self.meta_var.set("создано %s   ·   изменено %s"
                              % (e.get("created", "?"), e.get("modified", "?")))
            self.show_pw.set(False)
            self._toggle_pw()
            self._loading = False

        def _set_fields_state(self, enabled: bool):
            st = "normal" if enabled else "disabled"
            for w in (self.e_title, self.e_login, self.e_pass):
                w.config(state=st)
            self.t_notes.config(state=st)

        def _clear_fields(self):
            self._loading = True
            self._set_fields_state(True)
            self.title_var.set("")
            self.login_var.set("")
            self.pass_var.set("")
            self.t_notes.delete("1.0", "end")
            self.meta_var.set("")
            self._set_fields_state(False)
            self._loading = False

        def _on_field_change(self, _event=None):
            if self._loading or not self.current_id or self.data is None:
                return
            e = self._entry_by_id(self.current_id)
            if not e:
                return
            nt = self.title_var.get()
            nl = self.login_var.get()
            np = self.pass_var.get()
            nn = self.t_notes.get("1.0", "end-1c")
            if (nt, nl, np, nn) == (e["title"], e.get("login", ""),
                                    e.get("password", ""), e.get("notes", "")):
                return
            e["title"], e["login"], e["password"], e["notes"] = nt, nl, np, nn
            e["modified"] = now_str()
            self.meta_var.set("создано %s   ·   изменено %s" % (e.get("created", "?"), e["modified"]))
            self._update_list_title()
            self.schedule_save()

        def _update_list_title(self):
            if self.current_id in self.view_ids:
                i = self.view_ids.index(self.current_id)
                new = self._display_title(self._entry_by_id(self.current_id))
                if self.listbox.get(i) != new:
                    self.listbox.delete(i)
                    self.listbox.insert(i, new)
                    self.listbox.selection_clear(0, "end")
                    self.listbox.selection_set(i)

        def new_entry(self):
            e = new_entry_dict()
            self.data["entries"].append(e)
            self.search_var.set("")
            self.refresh_list(select_id=e["id"])
            self.load_entry(e["id"])
            self.e_title.focus_set()
            self.e_title.select_range(0, "end")
            self.schedule_save()

        def delete_entry(self):
            if not self.current_id:
                return
            e = self._entry_by_id(self.current_id)
            if not e:
                return
            if not messagebox.askyesno(
                    "Удалить запись",
                    "Удалить запись «%s»?\nЭто действие нельзя отменить." % self._display_title(e),
                    parent=self):
                return
            self.data["entries"] = [x for x in self.data["entries"] if x["id"] != self.current_id]
            self.current_id = None
            self._clear_fields()
            self.refresh_list()
            self.schedule_save()

        # ------------------------------------------------ пароль / буфер обмена
        def _toggle_pw(self):
            self.e_pass.config(show="" if self.show_pw.get() else "•")

        def copy_password(self):
            self.copy_secret(self.pass_var.get())

        def copy_secret(self, text: str):
            if not text:
                return
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_msg("Скопировано. Буфер обмена будет очищен через %d с"
                            % (CLIPBOARD_CLEAR_MS // 1000))
            self.after(CLIPBOARD_CLEAR_MS, lambda t=text: self._clip_clear_if(t))

        def _clip_clear_if(self, t):
            try:
                if self.clipboard_get() == t:
                    self.clipboard_clear()
                    self.status_msg("Буфер обмена очищен")
            except tk.TclError:
                pass

        def open_generator_for_entry(self):
            if self.data is None:
                return
            on_use = None
            if self.current_id:
                def on_use(p):
                    self.pass_var.set(p)
                    self.show_pw.set(True)
                    self._toggle_pw()
                    self._on_field_change()
                    self.status_msg("Пароль вставлен в запись")
            GeneratorDialog(self, self.data["settings"]["generator"], on_use=on_use)

        # ------------------------------------------------ блокировка / смена пароля
        def lock(self, msg=None):
            if self.data is None:
                return
            self.flush_now()
            self.data = None
            self.key = None
            self.salt = None
            self.current_id = None
            self.show_unlock(msg or "Заблокировано")

        def change_master(self):
            dlg = tk.Toplevel(self)
            dlg.title("Смена мастер-пароля")
            dlg.transient(self)
            dlg.grab_set()
            dlg.resizable(False, False)
            v0, v1, v2 = tk.StringVar(), tk.StringVar(), tk.StringVar()
            frm = ttk.Frame(dlg, padding=14)
            frm.grid()
            for i, (label, var) in enumerate((("Текущий пароль:", v0),
                                              ("Новый пароль:", v1),
                                              ("Новый ещё раз:", v2))):
                ttk.Label(frm, text=label).grid(row=i, column=0, sticky="e", padx=6, pady=4)
                ent = ttk.Entry(frm, textvariable=var, show="•", width=30, font=MONO)
                ent.grid(row=i, column=1, pady=4)
                if i == 0:
                    ent.focus_set()

            def apply():
                self._busy(True)
                ok = hmac.compare_digest(derive_key(v0.get(), self.salt, self.iterations), self.key)
                self._busy(False)
                if not ok:
                    messagebox.showerror("Смена пароля", "Текущий пароль неверен", parent=dlg)
                    return
                if not v1.get():
                    return
                if v1.get() != v2.get():
                    messagebox.showerror("Смена пароля", "Новые пароли не совпадают", parent=dlg)
                    return
                if len(v1.get()) < 12 and not messagebox.askyesno(
                        "Смена пароля",
                        "Новый пароль короче 12 символов. Всё равно использовать?", parent=dlg):
                    return
                self._busy(True)
                self.salt = secrets.token_bytes(SALT_LEN)
                self.iterations = KDF_ITERATIONS
                self.key = derive_key(v1.get(), self.salt, self.iterations)
                try:
                    self.save_to_disk()
                except OSError as e:
                    self._busy(False)
                    messagebox.showerror("Смена пароля", "Не удалось сохранить:\n%s" % e, parent=dlg)
                    return
                self._busy(False)
                dlg.destroy()
                self.status_msg("Мастер-пароль изменён, файл перешифрован")

            bf = ttk.Frame(frm)
            bf.grid(row=3, column=0, columnspan=2, pady=(10, 0))
            ttk.Button(bf, text="Применить", command=apply).pack(side="left", padx=4)
            ttk.Button(bf, text="Отмена", command=dlg.destroy).pack(side="left", padx=4)
            dlg.bind("<Return>", lambda e: apply())
            dlg.bind("<Escape>", lambda e: dlg.destroy())

        # ------------------------------------------------ выход
        def _on_close(self):
            self.flush_now()
            self.destroy()


def main():
    if tk is None:
        print("Tkinter недоступен в этой системе.\n"
              "На Windows/macOS он входит в состав Python с python.org.\n"
              "На Linux установи пакет:  sudo apt install python3-tk")
        return 1
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # чёткий шрифт на HiDPI
        except Exception:
            pass
    App().mainloop()
    return 0


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_selftest()
    else:
        sys.exit(main())
