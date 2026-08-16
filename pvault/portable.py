# -*- coding: utf-8 -*-
"""Экспорт и импорт в открытых форматах — CSV и JSON.

Зачем это нужно. Пока данные достаются только самой программой и только в её
собственном формате, пользователь к ней привязан: перестанет собираться,
изменится формат, захочется другой менеджер — выхода нет. Для хранилища
паролей такая привязка недопустима.

Файлы, которые пишет этот модуль, НЕ ЗАШИФРОВАНЫ. Интерфейс обязан
предупреждать об этом прямым текстом и до, а не после.

Импорт понимает и чужие выгрузки: заголовки Bitwarden и KeePass распознаются,
так что перенести данные извне тоже можно.
"""

import csv
import io
import json
import os

from .model import display_title, new_entry, normalize_entry, now_iso

CSV_COLUMNS = ("title", "login", "password", "url", "notes", "created", "modified")

# Заголовки чужих выгрузок -> наши поля.
_ALIASES = {
    "title": "title", "name": "title", "account": "title",
    "имя": "title", "название": "title", "заголовок": "title",

    "login": "login", "username": "login", "user name": "login",
    "login name": "login", "login_username": "login", "user": "login",
    "email": "login", "e-mail": "login", "логин": "login",

    "password": "password", "login_password": "password", "пароль": "password",

    "url": "url", "uri": "url", "login_uri": "url", "web site": "url",
    "website": "url", "site": "url", "ссылка": "url", "сайт": "url", "адрес": "url",

    "notes": "notes", "note": "notes", "comment": "notes",
    "comments": "notes", "заметки": "notes", "примечания": "notes",

    "created": "created", "creation time": "created",
    "modified": "modified", "last modified": "modified",
}


class ImportError_(ValueError):
    """Не удалось разобрать импортируемый файл."""


# ---------------------------------------------------------------------------
# Экспорт
# ---------------------------------------------------------------------------
def export_csv(entries, include_deleted=False):
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for e in entries:
        if e.get("deleted") and not include_deleted:
            continue
        writer.writerow([e.get(c, "") for c in CSV_COLUMNS])
    return buf.getvalue()


def export_json(entries, include_deleted=False, include_history=False):
    out = []
    for e in entries:
        if e.get("deleted") and not include_deleted:
            continue
        item = {c: e.get(c, "") for c in CSV_COLUMNS}
        item["id"] = e.get("id", "")
        if e.get("deleted"):
            item["deleted"] = True
        if include_history and e.get("history"):
            item["history"] = e["history"]
        out.append(item)
    return json.dumps({"exported": now_iso(), "entries": out},
                      ensure_ascii=False, indent=2)


def write_export(path, text):
    """Пишет открытый текст. utf-8-sig — чтобы Excel не превратил кириллицу в кашу."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Импорт
# ---------------------------------------------------------------------------
def _map_header(name):
    return _ALIASES.get((name or "").strip().lstrip("﻿").lower())


def parse_csv(text):
    """Разбирает CSV в список записей. Бросает ImportError_ при неудаче."""
    text = text.lstrip("﻿")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), dialect))
    except csv.Error as e:
        raise ImportError_("Не удалось разобрать CSV: %s" % e)

    if not rows:
        raise ImportError_("Файл пуст")

    header = [_map_header(c) for c in rows[0]]
    if not any(header):
        raise ImportError_(
            "В первой строке не найдено знакомых заголовков.\n"
            "Ожидаются столбцы вида: title, login, password, url, notes.")

    entries = []
    for row in rows[1:]:
        if not any((c or "").strip() for c in row):
            continue
        e = new_entry("")
        for i, field in enumerate(header):
            if field and i < len(row):
                e[field] = row[i] or ""
        if not (e.get("title") or e.get("login") or e.get("password") or e.get("url")):
            continue
        if not e["title"].strip():
            e["title"] = "(без названия)"
        entries.append(normalize_entry(e))

    if not entries:
        raise ImportError_("В файле не нашлось ни одной записи")
    return entries


def parse_json(text):
    try:
        data = json.loads(text.lstrip("﻿"))
    except ValueError as e:
        raise ImportError_("Не удалось разобрать JSON: %s" % e)

    if isinstance(data, dict):
        items = data.get("entries")
    else:
        items = data
    if not isinstance(items, list):
        raise ImportError_("Ожидался список записей в поле entries")

    entries = []
    for item in items:
        if not isinstance(item, dict):
            continue
        e = new_entry("")
        for field in CSV_COLUMNS:
            v = item.get(field)
            if isinstance(v, str):
                e[field] = v
        # id из чужого файла не берём: он может столкнуться с нашим и
        # «слипнуться» с существующей записью при следующем слиянии.
        if not (e.get("title") or e.get("login") or e.get("password") or e.get("url")):
            continue
        if not e["title"].strip():
            e["title"] = "(без названия)"
        entries.append(normalize_entry(e))

    if not entries:
        raise ImportError_("В файле не нашлось ни одной записи")
    return entries


def read_import(path):
    """Читает файл, подбирая кодировку, и разбирает по расширению."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ImportError_("Не удалось прочитать файл:\n%s" % e)

    text = None
    for enc in ("utf-8-sig", "utf-8", "cp1251", "cp866", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise ImportError_("Не удалось определить кодировку файла")

    if os.path.splitext(path)[1].lower() == ".json":
        return parse_json(text)
    return parse_csv(text)


def summarize(entries):
    return ", ".join(display_title(e) for e in entries[:5]) + \
        ("…" if len(entries) > 5 else "")
