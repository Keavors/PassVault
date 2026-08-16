# -*- coding: utf-8 -*-
"""Модель данных: записи, метки времени, история паролей, надгробия.

О метках времени
----------------
Версии 1.x писали "2026-01-31 14:05" — местное время, без секунд и без пояса.
Отсюда две беды: правки внутри одной минуты неразличимы, а при синхронизации
между устройствами в разных поясах пометка «новее» просто врёт.

Пишем ISO-8601 в UTC с секундами: "2026-01-31T11:05:42Z". Старый формат
по-прежнему читается (считаем его местным временем), поэтому существующие
хранилища открываются без конвертации. Показываем всегда в местном времени.

О незнакомых полях
------------------
normalize_entry НИЧЕГО не выбрасывает из записи. Если файл пришёл с телефона
или из более новой версии и содержит поле, о котором эта программа не знает,
поле остаётся в словаре и уезжает обратно в файл нетронутым.

Это не мелочь. Ровно на этом месте данные подтачиваются молча: устройство,
которое «не знает» поле, при первом же сохранении его стирает, и каждая
синхронизация отгрызает по куску.
"""

import re
import secrets
from datetime import datetime, timezone

from . import SCHEMA_VERSION

MAX_HISTORY = 10
TOMBSTONE_TTL_DAYS = 180

# Поля, по которым записи сравниваются при слиянии. Метки времени сюда не
# входят намеренно: одинаковое содержимое с разными датами правки — не
# конфликт, а повод промолчать.
CONTENT_FIELDS = ("title", "login", "password", "url", "notes", "deleted")

TEXT_FIELDS = ("title", "login", "password", "url", "notes")

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?"
    r"(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")


# ---------------------------------------------------------------------------
# Метки времени
# ---------------------------------------------------------------------------
def now_iso():
    """Текущий момент в UTC: 2026-01-31T11:05:42Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value):
    """Разбирает метку времени любого поддерживаемого формата.

    Возвращает datetime с поясом либо None, если разобрать не вышло. Строка
    без пояса считается местным временем — именно так её писали версии 1.x.
    """
    if not isinstance(value, str):
        return None
    m = _ISO_RE.match(value.strip())
    if not m:
        return None
    year, month, day, hour, minute, second, tz = m.groups()
    try:
        dt = datetime(int(year), int(month), int(day),
                      int(hour), int(minute), int(second or 0))
    except ValueError:
        return None

    if tz is None:
        return dt.astimezone()                      # местное время
    if tz == "Z":
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    offset_min = sign * (int(digits[:2]) * 60 + int(digits[2:]))
    from datetime import timedelta
    return dt.replace(tzinfo=timezone(timedelta(minutes=offset_min)))


def ts_sort_key(value):
    """Сопоставимый ключ «что новее». Неразобранное уходит в самый низ."""
    dt = parse_ts(value)
    return dt.timestamp() if dt else float("-inf")


def is_newer(a, b):
    """True, если метка a строго новее b (с учётом разных форматов и поясов)."""
    return ts_sort_key(a) > ts_sort_key(b)


def fmt_ts(value, fallback="?"):
    """Для показа пользователю — всегда в местном времени."""
    dt = parse_ts(value)
    if dt is None:
        return value if isinstance(value, str) and value else fallback
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Записи
# ---------------------------------------------------------------------------
def new_id():
    return secrets.token_hex(8)


def new_entry(title="Новая запись"):
    t = now_iso()
    return {"id": new_id(), "title": title, "login": "", "password": "",
            "url": "", "notes": "", "created": t, "modified": t}


def normalize_entry(e):
    """Приводит запись к ожидаемому виду. Возвращает None, если это не запись.

    Нужна потому, что файл мог быть повреждён, отредактирован руками или
    записан другой версией программы. Раньше обращение к e["title"] на такой
    записи роняло всё приложение с KeyError.

    Незнакомые поля сохраняются: словарь правится на месте, лишнее не удаляется.
    """
    if not isinstance(e, dict):
        return None

    if not isinstance(e.get("id"), str) or not e["id"]:
        e["id"] = new_id()

    for f in TEXT_FIELDS:
        v = e.get(f)
        if not isinstance(v, str):
            e[f] = "" if v is None else str(v)

    for f in ("created", "modified"):
        if not isinstance(e.get(f), str) or not e[f]:
            e[f] = now_iso()

    if "deleted" in e:
        if e["deleted"]:
            e["deleted"] = True
        else:
            del e["deleted"]              # false не пишем, файл чище

    hist = e.get("history")
    if hist is None:
        e.pop("history", None)
    elif isinstance(hist, list):
        clean = []
        for h in hist:
            if isinstance(h, dict) and isinstance(h.get("password"), str) \
                    and h["password"]:
                changed = h.get("changed")
                clean.append({"password": h["password"],
                              "changed": changed if isinstance(changed, str) else ""})
        if clean:
            e["history"] = clean[:MAX_HISTORY]
        else:
            e.pop("history", None)
    else:
        e.pop("history", None)

    return e


def default_data(generator_defaults, app_defaults):
    return {"version": SCHEMA_VERSION, "entries": [],
            "settings": {"generator": dict(generator_defaults),
                         "app": dict(app_defaults)}}


def normalize_data(data, generator_defaults, app_defaults):
    """Проверяет и чинит структуру расшифрованного хранилища.

    Бросает ValueError, если файл сделан более новой версией программы. Молча
    открыть и перезаписать такой файл — способ потерять чужие данные: всё, что
    новая версия положила в незнакомые нам места, исчезнет.
    """
    if not isinstance(data, dict):
        raise ValueError("Содержимое хранилища повреждено (ожидался объект JSON)")

    version = data.get("version", SCHEMA_VERSION)
    if not isinstance(version, int):
        raise ValueError("Повреждён номер версии хранилища")
    if version > SCHEMA_VERSION:
        raise ValueError(
            "Файл создан более новой версией PassVault (версия данных %d, эта "
            "программа понимает %d).\nОбнови программу, иначе данные можно "
            "потерять." % (version, SCHEMA_VERSION))
    data["version"] = SCHEMA_VERSION

    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raw_entries = []

    entries, seen = [], set()
    for item in raw_entries:
        e = normalize_entry(item)
        if e is None:
            continue
        # Дубликаты id ломают слияние: одна запись «затеняет» другую и правки
        # на втором устройстве не доезжают никогда.
        while e["id"] in seen:
            e["id"] = new_id()
        seen.add(e["id"])
        entries.append(e)
    data["entries"] = entries

    settings = data.get("settings")
    if not isinstance(settings, dict):
        settings = {}
        data["settings"] = settings

    gen = settings.get("generator")
    merged_gen = dict(generator_defaults)
    if isinstance(gen, dict):
        merged_gen.update(gen)
    settings["generator"] = merged_gen

    app = settings.get("app")
    merged_app = dict(app_defaults)
    if isinstance(app, dict):
        merged_app.update(app)
    settings["app"] = merged_app

    return data


# ---------------------------------------------------------------------------
# Выборки и отображение
# ---------------------------------------------------------------------------
def live_entries(entries):
    return [e for e in entries if not e.get("deleted")]


def deleted_entries(entries):
    return [e for e in entries if e.get("deleted")]


def display_title(e):
    return (e.get("title") or "").strip() or "(без названия)"


def entry_by_id(entries, eid):
    return next((e for e in entries if e.get("id") == eid), None)


def search_haystack(e):
    return " ".join((e.get("title", ""), e.get("login", ""),
                     e.get("url", ""), e.get("notes", ""))).lower()


# ---------------------------------------------------------------------------
# История паролей
# ---------------------------------------------------------------------------
def push_history(entry, old_password):
    """Кладёт прежний пароль в историю записи.

    Закрывает случай «перезаписал пароль генератором и потерял старый» —
    раньше это было невосстановимо ничем.
    """
    if not old_password:
        return
    hist = entry.get("history")
    if not isinstance(hist, list):
        hist = []
    if hist and hist[0].get("password") == old_password:
        return
    hist.insert(0, {"password": old_password, "changed": now_iso()})
    entry["history"] = hist[:MAX_HISTORY]


def touch(entry, old_password=None):
    """Отмечает запись изменённой, при необходимости пополняя историю."""
    if old_password is not None and old_password != entry.get("password", ""):
        push_history(entry, old_password)
    entry["modified"] = now_iso()


# ---------------------------------------------------------------------------
# Удаление
# ---------------------------------------------------------------------------
def soft_delete(entry):
    """Удаление = надгробие. Без него удаление не переносится при слиянии:
    второе устройство просто вернёт запись обратно как «недостающую»."""
    entry["deleted"] = True
    entry["modified"] = now_iso()


def restore(entry):
    entry.pop("deleted", None)
    entry["modified"] = now_iso()


def purgeable_tombstones(entries, ttl_days=TOMBSTONE_TTL_DAYS, now=None):
    """Надгробия, которые пора вычистить.

    Порог намеренно большой: удаление должно успеть разойтись на все
    устройства, иначе телефон при следующем слиянии воскресит запись.
    """
    now_ts = (now or datetime.now(timezone.utc)).timestamp()
    cutoff = now_ts - ttl_days * 86400
    out = []
    for e in entries:
        if not e.get("deleted"):
            continue
        k = ts_sort_key(e.get("modified"))
        if k != float("-inf") and k < cutoff:
            out.append(e)
    return out


def purge_tombstones(entries, ttl_days=TOMBSTONE_TTL_DAYS, now=None):
    """Удаляет старые надгробия из списка НА МЕСТЕ. Возвращает их количество."""
    doomed = {id(e) for e in purgeable_tombstones(entries, ttl_days, now)}
    if not doomed:
        return 0
    kept = [e for e in entries if id(e) not in doomed]
    removed = len(entries) - len(kept)
    entries[:] = kept
    return removed
