# -*- coding: utf-8 -*-
"""Настройки приложения, живущие ВНЕ хранилища.

Здесь только то, что нужно знать до ввода мастер-пароля: какой файл открывали
последним и какие вообще открывали. Никаких паролей и ничего из содержимого
хранилища тут нет и быть не может — файл лежит незашифрованным.

Путь к хранилищу — это всё-таки след того, чем человек пользуется, поэтому
файл кладётся в папку профиля пользователя, а не куда попало.
"""

import json
import os

from . import paths

MAX_RECENT = 8


def _read():
    try:
        with open(paths.config_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data):
    try:
        os.makedirs(paths.user_data_dir(), exist_ok=True)
        tmp = paths.config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, paths.config_path())
        return True
    except OSError:
        return False


def recent_vaults():
    """Недавно открывавшиеся хранилища, свежие первыми. Только существующие."""
    data = _read()
    out, seen = [], set()
    for p in data.get("recent", []):
        if not isinstance(p, str):
            continue
        key = os.path.normcase(os.path.abspath(p))
        if key in seen:
            continue
        seen.add(key)
        if os.path.isfile(p):
            out.append(p)
    return out[:MAX_RECENT]


def last_vault():
    """Последнее открытое хранилище или None.

    Возвращается даже если файл исчез: пользователю честнее показать «файл
    пропал, вот копии», чем молча предложить создать новое.
    """
    data = _read()
    p = data.get("last_vault")
    return p if isinstance(p, str) and p else None


def remember_vault(path):
    """Запоминает хранилище как последнее открытое."""
    path = os.path.abspath(path)
    data = _read()
    data["last_vault"] = path

    recent = [p for p in data.get("recent", []) if isinstance(p, str)]
    key = os.path.normcase(path)
    recent = [p for p in recent if os.path.normcase(os.path.abspath(p)) != key]
    recent.insert(0, path)
    data["recent"] = recent[:MAX_RECENT]
    return _write(data)


def forget_vault(path):
    """Убирает хранилище из списка недавних."""
    key = os.path.normcase(os.path.abspath(path))
    data = _read()
    data["recent"] = [p for p in data.get("recent", [])
                      if isinstance(p, str)
                      and os.path.normcase(os.path.abspath(p)) != key]
    if data.get("last_vault") and \
            os.path.normcase(os.path.abspath(data["last_vault"])) == key:
        data["last_vault"] = data["recent"][0] if data["recent"] else None
    return _write(data)
