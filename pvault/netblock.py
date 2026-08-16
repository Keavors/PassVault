# -*- coding: utf-8 -*-
"""Отключение сетевых функций Python внутри процесса.

Честно о том, что это такое: защита в глубину, а не гарантия. Подменяются
публичные имена модуля socket, поэтому код, который импортирует _socket
напрямую или дёргает ОС через ctypes, преграду обойдёт. Гарантия уровня
системы — правило брандмауэра на исполняемый файл (см. README).

Ценность в другом: случайная попытка выйти в сеть штатным способом — своя ли,
или притащенная зависимостью — упадёт с ошибкой, а не отработает молча.

Важная тонкость реализации. Наивная подмена socket.socket обычной функцией
ломает импорт стандартной библиотеки: ssl объявляет `class SSLSocket(socket)`,
а унаследоваться от функции нельзя — импорт ssl (а с ним asyncio и
unittest.mock) падает с невнятной ошибкой. Поэтому socket.socket подменяется
КЛАССОМ-наследником, который отказывается создаваться: наследование
продолжает работать, а рабочий сокет получить нельзя.
"""

import socket as _socket

MESSAGE = "PassVault: доступ к сети заблокирован этим приложением"

# Функции, дающие соединение или разрешение имени. gethostname оставлен: он
# ничего не отправляет наружу, а VaultLock пишет им имя машины в файл-замок.
_BLOCKED_FUNCS = (
    "socketpair", "create_connection", "create_server",
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
)

_real_socket_cls = _socket.socket
_installed = False


def _network_blocked(*_args, **_kwargs):
    raise OSError(MESSAGE)


class _BlockedSocket(_real_socket_cls):
    """Наследник настоящего сокета, который нельзя создать.

    Классом он остаётся намеренно — чтобы `class SSLSocket(socket)` в
    стандартной библиотеке по-прежнему импортировался.
    """

    def __new__(cls, *_args, **_kwargs):
        raise OSError(MESSAGE)

    def __init__(self, *_args, **_kwargs):   # pragma: no cover — сюда не дойти
        raise OSError(MESSAGE)


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


def is_blocked():
    """True, если рабочий сокет получить не удаётся. Используется в тестах."""
    try:
        _socket.socket()
    except OSError:
        return True
    return False
