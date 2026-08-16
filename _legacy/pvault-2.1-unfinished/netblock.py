# -*- coding: utf-8 -*-
"""Отключение сетевых функций Python внутри процесса.

Честная оценка: это защита в глубину, а не гарантия. Подменяются публичные
имена модуля socket, поэтому код, который импортирует _socket напрямую или
дёргает ОС через ctypes, преграду обойдёт. Настоящая гарантия уровня системы —
правило брандмауэра на исполняемый файл (см. README).

Ценность в том, что случайная попытка «сходить в интернет» штатным способом
упадёт с ошибкой, а не отработает молча.

Важная тонкость реализации. Наивная подмена socket.socket обычной функцией
ломает импорт стандартных модулей: ssl объявляет `class SSLSocket(socket)`, а
унаследоваться от функции нельзя — импорт ssl (а с ним asyncio и unittest.mock)
падает с невнятной ошибкой. Поэтому socket.socket подменяется КЛАССОМ-
наследником, который отказывается создаваться: наследование продолжает
работать, а рабочий сокет получить нельзя.
"""

import socket as _socket

_BLOCKED_FUNCS = (
    "socketpair", "create_connection", "create_server",
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
)

_MESSAGE = "PassVault: доступ к сети заблокирован этим приложением"

_installed = False
_real_socket_cls = _socket.socket


def _network_blocked(*_args, **_kwargs):
    raise OSError(_MESSAGE)


class _BlockedSocket(_real_socket_cls):
    """Наследник настоящего сокета, который нельзя создать.

    Классом он остаётся намеренно — чтобы `class SSLSocket(socket)` в
    стандартной библиотеке по-прежнему импортировался.
    """

    def __new__(cls, *_args, **_kwargs):
        raise OSError(_MESSAGE)

    def __init__(self, *_args, **_kwargs):     # pragma: no cover — сюда не дойти
        raise OSError(_MESSAGE)


def install():
    """Подменяет сетевые функции. Повторный вызов безопасен."""
    global _installed
    if _installed:
        return
    _socket.socket = _BlockedSocket
    for name in _BLOCKED_FUNCS:
        if hasattr(_socket, name):
            setattr(_socket, name, _network_blocked)
    _installed = True


def is_blocked() -> bool:
    """True, если получить рабочий сокет не удаётся (используется в тестах)."""
    try:
        _socket.socket()
    except OSError:
        return True
    return False
