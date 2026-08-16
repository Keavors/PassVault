# -*- coding: utf-8 -*-
"""Отключение сетевых функций Python внутри процесса.

Защита в глубину, а не гарантия: код, работающий с ОС напрямую через ctypes
или импортирующий _socket, преграду обойдёт. Гарантию уровня системы даёт
правило брандмауэра — про это написано в README, и обещать здесь большее
нечестно.

Тесты жили в test_throttle.py по единственной причине: там было свободное
место. Ни к задержке после неверных паролей, ни к чему-либо ещё из того файла
они отношения не имеют.
"""

import unittest

from pvault import netblock


class NetblockTest(unittest.TestCase):
    def test_sockets_blocked_after_install(self):
        netblock.install()
        self.assertTrue(netblock.is_blocked())

    def test_install_is_idempotent(self):
        netblock.install()
        netblock.install()
        self.assertTrue(netblock.is_blocked())

    def test_ssl_still_imports(self):
        """Подмена socket.socket функцией ломала импорт ssl, asyncio и mock.

        ssl объявляет `class SSLSocket(socket)`, а унаследоваться от функции
        нельзя — импорт падал с невнятной ошибкой. Поэтому socket.socket
        подменяется КЛАССОМ-наследником, который отказывается создаваться.
        """
        netblock.install()
        import ssl                                    # noqa: F401
        import unittest.mock                          # noqa: F401

    def test_name_resolution_blocked(self):
        netblock.install()
        import socket
        with self.assertRaises(OSError):
            socket.getaddrinfo("example.com", 80)

    def test_hostname_still_available(self):
        """gethostname наружу ничего не отправляет, а файл-замок пишет им имя
        машины — без него две копии программы не различить."""
        netblock.install()
        import socket
        self.assertTrue(socket.gethostname())
