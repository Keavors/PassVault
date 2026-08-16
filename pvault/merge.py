# -*- coding: utf-8 -*-
"""Слияние двух хранилищ — основа синхронизации между ПК и телефоном.

Этот же механизм отвечает за восстановление из резервной копии: снимок
подаётся как «входящий» файл. Благодаря этому «достать запись, удалённую
вчера» не сносит то, что добавлено сегодня, — в отличие от простой замены
файла копией.

Правило истории паролей при слиянии
-----------------------------------
Когда пользователь выбирает «взять из файла», локальный пароль записи
заменяется. Прежняя версия просто затирала его — и это был единственный
штатный путь, на котором пароль исчезал бесследно, при том что история
паролей существовала именно ради таких случаев. Теперь перед заменой
локальный пароль уходит в историю итоговой записи.
"""

import secrets

from .model import CONTENT_FIELDS, MAX_HISTORY, is_newer, ts_sort_key, display_title

LOCAL = "local"
INCOMING = "incoming"
BOTH = "both"


def same_content(a, b):
    """Одинаковы ли записи по содержанию. Даты правки не учитываются."""
    return all(bool(a.get(f)) == bool(b.get(f)) if f == "deleted"
               else a.get(f, "") == b.get(f, "")
               for f in CONTENT_FIELDS)


class Conflict:
    """Одна и та же запись (по id) с разным содержимым на двух сторонах."""

    __slots__ = ("local", "incoming")

    def __init__(self, local, incoming):
        self.local = local
        self.incoming = incoming

    @property
    def title(self):
        return display_title(self.local) if (self.local.get("title") or "").strip() \
            else display_title(self.incoming)

    @property
    def incoming_is_newer(self):
        return is_newer(self.incoming.get("modified"), self.local.get("modified"))

    @property
    def same_timestamp(self):
        return ts_sort_key(self.local.get("modified")) == \
            ts_sort_key(self.incoming.get("modified"))

    @property
    def involves_deletion(self):
        return bool(self.local.get("deleted")) or bool(self.incoming.get("deleted"))

    def suggestion(self):
        """Какую сторону предложить по умолчанию — берём более свежую."""
        return INCOMING if self.incoming_is_newer else LOCAL


class MergePlan:
    __slots__ = ("to_add", "conflicts")

    def __init__(self, to_add, conflicts):
        self.to_add = to_add
        self.conflicts = conflicts

    @property
    def is_empty(self):
        return not self.to_add and not self.conflicts

    @property
    def ambiguous_count(self):
        """Расхождения, где «самое свежее» определить нельзя."""
        return sum(1 for c in self.conflicts if c.same_timestamp)

    def suggestions(self):
        return [c.suggestion() for c in self.conflicts]


def _free_id(used):
    eid = secrets.token_hex(8)
    while eid in used:
        eid = secrets.token_hex(8)
    return eid


def plan_merge(local_entries, incoming_entries):
    """Готовит план слияния.

    Записи с одинаковым содержимым конфликтом не считаются, даже если даты
    правки различаются, — иначе пользователь получал бы окно на каждый чих.

    Повторяющиеся id ВНУТРИ входящего файла разводятся. Файл может быть
    повреждён или собран чужой программой, и раньше две записи с одним id
    просто добавлялись обе. Дальше они затеняли друг друга при каждой
    синхронизации: правка на втором устройстве не доезжала никогда, и понять
    почему было невозможно.
    """
    by_id = {}
    for e in local_entries:
        eid = e.get("id")
        if isinstance(eid, str) and eid:
            by_id[eid] = e

    used = set(by_id)
    seen_incoming = set()
    to_add, conflicts = [], []

    for inc in incoming_entries:
        eid = inc.get("id")
        if not isinstance(eid, str) or not eid:
            continue
        if eid in seen_incoming:
            inc = dict(inc)                 # чужой словарь не правим на месте
            eid = _free_id(used)
            inc["id"] = eid
        seen_incoming.add(eid)
        used.add(eid)

        loc = by_id.get(eid)
        if loc is None:
            to_add.append(inc)
        elif not same_content(loc, inc):
            conflicts.append(Conflict(loc, inc))
    return MergePlan(to_add, conflicts)


def _merge_history(primary, secondary, dropped_password=None):
    """Общая история двух версий записи, новые сверху, без повторов.

    Истории на разных устройствах расходятся так же, как и сами записи, и
    выбрасывать половину при слиянии незачем: она маленькая и стоит дёшево.
    """
    out, seen = [], set()
    for h in list(primary or []) + list(secondary or []):
        if not isinstance(h, dict):
            continue
        pw = h.get("password")
        if not isinstance(pw, str) or not pw or pw in seen:
            continue
        seen.add(pw)
        out.append({"password": pw,
                    "changed": h.get("changed") if isinstance(h.get("changed"), str) else ""})

    if dropped_password and dropped_password not in seen:
        from .model import now_iso
        out.insert(0, {"password": dropped_password, "changed": now_iso()})

    out.sort(key=lambda h: ts_sort_key(h["changed"]), reverse=True)
    return out[:MAX_HISTORY]


def apply_merge(local_entries, plan, decisions):
    """Применяет решения пользователя. decisions[i] ∈ {LOCAL, INCOMING, BOTH}.

    Меняет local_entries на месте. Возвращает словарь со счётчиками.
    """
    if len(decisions) != len(plan.conflicts):
        raise ValueError("Число решений (%d) не совпадает с числом конфликтов (%d)"
                         % (len(decisions), len(plan.conflicts)))

    stats = {"added": 0, "kept_local": 0, "took_incoming": 0, "kept_both": 0}
    ids = {e.get("id") for e in local_entries}

    for inc in plan.to_add:
        local_entries.append(inc)
        ids.add(inc.get("id"))
        stats["added"] += 1

    for conflict, decision in zip(plan.conflicts, decisions):
        loc, inc = conflict.local, conflict.incoming

        if decision == LOCAL:
            # Даже оставляя свою версию, забираем чужую историю паролей:
            # прошлые пароли с другого устройства пригодятся, а потерять их
            # обидно и незачем.
            merged = _merge_history(loc.get("history"), inc.get("history"))
            if merged:
                loc["history"] = merged
            stats["kept_local"] += 1

        elif decision == INCOMING:
            old_password = loc.get("password", "")
            merged = _merge_history(inc.get("history"), loc.get("history"),
                                    dropped_password=old_password
                                    if old_password != inc.get("password", "") else None)
            # Ключ записи (id) не трогаем: он и есть то, по чему стороны
            # узнают друг друга при следующей синхронизации.
            for k in list(loc.keys()):
                if k != "id":
                    del loc[k]
            for k, v in inc.items():
                if k != "id":
                    loc[k] = v
            if merged:
                loc["history"] = merged
            else:
                loc.pop("history", None)
            stats["took_incoming"] += 1

        elif decision == BOTH:
            copy = dict(inc)
            new_id = secrets.token_hex(8)
            while new_id in ids:
                new_id = secrets.token_hex(8)
            copy["id"] = new_id
            ids.add(new_id)
            copy["title"] = ((copy.get("title") or "") + " (копия)").strip()
            copy.pop("deleted", None)
            local_entries.append(copy)
            stats["kept_both"] += 1

        else:
            raise ValueError("Неизвестное решение слияния: %r" % (decision,))

    return stats
