# -*- coding: utf-8 -*-
"""Генератор паролей на криптографическом ГСЧ операционной системы.

Источник случайности — random.SystemRandom, то есть os.urandom. Важно, что на
нём же делается и перемешивание: сгенерировать стойко, а потом перетасовать
обычным random — классическая ошибка, сводящая стойкость на нет.
"""

import math
import random

GROUP_LOWER = "abcdefghijklmnopqrstuvwxyz"
GROUP_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
GROUP_DIGITS = "0123456789"
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?"

# Символы, которые путают глазами или при переписывании от руки. Набор обязан
# совпадать с Android-версией: иначе одна и та же галочка на двух устройствах
# даёт разные пароли, и «исключить похожие» перестаёт что-либо значить.
AMBIGUOUS = "Il1O0o5S2Z8B|`'\"{}[]()<>"

MAX_LENGTH = 512

DEFAULT_GEN = {
    "use_lower": True,
    "use_upper": True,
    "use_digits": True,
    "use_symbols": True,
    "symbols": DEFAULT_SYMBOLS,
    "require_each": True,
    "exact_mode": True,
    "exact_len": 16,
    "min_len": 12,
    "max_len": 20,
    "required_chars": "",
    "excluded_chars": "",
    "no_ambiguous": False,
}


class GeneratorError(ValueError):
    """Противоречивые настройки генератора."""


def _build_pools(o):
    """Готовит наборы символов. Возвращает (pools, pool, required)."""
    excluded = set(o.get("excluded_chars") or "")
    if o.get("no_ambiguous"):
        excluded |= set(AMBIGUOUS)

    selected = []
    if o.get("use_lower", True):
        selected.append(("строчные латинские", GROUP_LOWER))
    if o.get("use_upper", True):
        selected.append(("заглавные латинские", GROUP_UPPER))
    if o.get("use_digits", True):
        selected.append(("цифры", GROUP_DIGITS))
    if o.get("use_symbols", True):
        symbols = o.get("symbols")
        symbols = DEFAULT_SYMBOLS if symbols is None else symbols
        # Раньше пустой набор молча игнорировался: галочка стоит, спецсимволов
        # нет, и «минимум по одному из группы» их тоже не даёт.
        if not symbols:
            raise GeneratorError("Включены спецсимволы, но их набор пуст — "
                                 "впиши символы или сними галочку")
        selected.append(("спецсимволы", symbols))

    pools = []
    for name, group in selected:
        p = [c for c in dict.fromkeys(group) if c not in excluded]
        if not p:
            raise GeneratorError(
                "Группа «%s» целиком попала в исключения — убери исключения "
                "или сними галочку с этой группы" % name)
        pools.append(p)

    required = [c for c in dict.fromkeys(o.get("required_chars") or "")
                if not c.isspace()]
    conflict = [c for c in required if c in excluded]
    if conflict:
        raise GeneratorError("Символы «%s» одновременно и обязательны, "
                             "и исключены" % "".join(conflict))

    pool = sorted(set(c for p in pools for c in p) | set(required))
    if not pool:
        raise GeneratorError("Набор символов пуст: включи хотя бы одну группу "
                             "или впиши обязательные символы")
    return pools, pool, required


def _resolve_length(o, rng):
    if o.get("exact_mode", True):
        length = int(o.get("exact_len", 16))
    else:
        lo, hi = int(o.get("min_len", 12)), int(o.get("max_len", 20))
        if lo > hi:
            lo, hi = hi, lo
        length = rng.randint(lo, hi)      # SystemRandom.randint — без смещения
    return max(1, min(MAX_LENGTH, length))


def generate_password(o):
    """Генерирует пароль по настройкам. Возвращает (пароль, размер_алфавита)."""
    rng = random.SystemRandom()
    pools, pool, required = _build_pools(o)
    length = _resolve_length(o, rng)

    guaranteed = list(required)
    if o.get("require_each", True):
        guaranteed += [rng.choice(p) for p in pools]
    if len(guaranteed) > length:
        raise GeneratorError(
            "Обязательных символов (%d) больше, чем длина пароля (%d) — "
            "увеличь длину" % (len(guaranteed), length))

    chars = guaranteed + [rng.choice(pool) for _ in range(length - len(guaranteed))]
    rng.shuffle(chars)
    return "".join(chars), len(pool)


def estimate_bits(o, length, pool_size):
    """Осторожная нижняя оценка стойкости в битах.

    Формула length * log2(pool) завышает результат: символы из «обязательно
    включить» заданы пользователем и предсказуемы, своей доли энтропии они не
    дают. Для менеджера паролей завышать эту цифру — худшее из зол, поэтому
    обязательные символы считаем нулевыми.
    """
    if pool_size <= 1 or length <= 0:
        return 0.0
    forced = len([c for c in dict.fromkeys(o.get("required_chars") or "")
                  if not c.isspace()])
    free = max(0, length - forced)
    return free * math.log2(pool_size)


def rate_bits(bits):
    if bits < 45:
        return "слабый"
    if bits < 64:
        return "средний"
    if bits < 80:
        return "хороший"
    return "отличный"
