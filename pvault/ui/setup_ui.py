# -*- coding: utf-8 -*-
r"""Окно уборки следов прежних версий.

Окна установки здесь больше нет, потому что установки больше нет: программа
переносимая и работает там, где лежит. Почему так — подробно в pvault/setup.py.

Осталось одно окно, и открывается оно по команде «PassVault.exe --uninstall»,
которую прежние версии прописали в «Установленные программы». Человек нажимает
там «Удалить», ожидая, что программа уйдёт, — и обязан получить правду: сама
папка удаляется вручную, а окно снимает то, что программа когда-то добавила в
систему.
"""

import os
import tkinter as tk
from tkinter import ttk

from .. import __version__, setup as setuplib
from .widgets import DIM, GOOD, HEAD


class CleanupWindow(tk.Tk):
    """Что прежние версии оставили в системе и как это убрать."""

    def __init__(self):
        super().__init__()
        self.title("PassVault %s — удаление" % __version__)
        self.resizable(False, False)
        self.removed = None
        self._set_icon()

        self.traces = setuplib.legacy_traces()
        folder = setuplib.self_dir()

        frm = ttk.Frame(self, padding=18)
        frm.grid(sticky="nsew")
        frm.columnconfigure(0, weight=1)

        installed = setuplib.was_installed()

        ttk.Label(frm, text="PassVault", font=HEAD).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text=("Эта копия установлена установщиком."
                             if installed else
                             "Эта копия распакована из архива и в систему\n"
                             "не устанавливалась."),
                  foreground=DIM, justify="left"
                  ).grid(row=1, column=0, sticky="w", pady=(0, 14))

        # Главное, что человек должен унести из этого окна: как удалить.
        # Ответ зависит от того, как программа сюда попала, и соврать здесь
        # нельзя: человек удаляет менеджер паролей.
        box = ttk.LabelFrame(frm, text="Чтобы удалить программу", padding=10)
        box.grid(row=2, column=0, sticky="ew")
        box.columnconfigure(0, weight=1)
        ttk.Label(box, text=("Открой «Параметры → Приложения → Установленные\n"
                             "приложения», найди PassVault и нажми «Удалить»."
                             if installed else
                             "Закрой PassVault и удали эту папку:"),
                  justify="left").grid(row=0, column=0, sticky="w")
        ttk.Label(box, text=folder, foreground=DIM, wraplength=460,
                  justify="left").grid(row=1, column=0, sticky="w", pady=(4, 8))
        ttk.Button(box, text="Открыть папку в проводнике",
                   command=self._open_folder).grid(row=2, column=0, sticky="w")

        # Предупреждение обязано быть здесь: хранилище лежит в этой же папке,
        # и «удали папку» без этой строки означало бы «удали заодно все свои
        # пароли». Установщик хранилище не удаляет — он удаляет только то, что
        # сам положил, — но папку с данными человек потом снесёт руками.
        ttk.Label(frm, text="Хранилище vault.pmv и архив копий лежат в той же папке.\n"
                            "Удаление программы их не тронет, но если будешь\n"
                            "удалять папку целиком — сначала перенеси их.",
                  foreground="#b00000", justify="left", wraplength=460
                  ).grid(row=3, column=0, sticky="w", pady=(8, 0))

        row = 4
        if self.traces:
            box2 = ttk.LabelFrame(frm, text="Следы прежних версий в системе",
                                  padding=10)
            box2.grid(row=row, column=0, sticky="ew", pady=(14, 0))
            box2.columnconfigure(0, weight=1)
            ttk.Label(box2, text="Версии 2.x–3.2 прописывали программу в систему.\n"
                                 "Эта версия так не делает; старое можно убрать:",
                      justify="left").grid(row=0, column=0, sticky="w")
            ttk.Label(box2, text="\n".join("    " + t for t in self.traces),
                      foreground=DIM, justify="left", wraplength=440
                      ).grid(row=1, column=0, sticky="w", pady=(6, 8))
            self.btn_clean = ttk.Button(box2, text="Убрать следы",
                                        command=self._clean)
            self.btn_clean.grid(row=2, column=0, sticky="w")
            row += 1

        self.status = ttk.Label(frm, text="", foreground=GOOD, wraplength=460,
                                justify="left")
        self.status.grid(row=row, column=0, sticky="w", pady=(12, 0))

        ttk.Button(frm, text="Закрыть", command=self.destroy
                   ).grid(row=row + 1, column=0, sticky="e", pady=(14, 0))

        self.update_idletasks()
        self._center()

    def _set_icon(self):
        try:
            from .icon import ICON_PNG_B64
            self._icon = tk.PhotoImage(data=ICON_PNG_B64)
            self.iconphoto(True, self._icon)
        except Exception:
            pass

    def _center(self):
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 3
        self.geometry("+%d+%d" % (max(0, x), max(0, y)))

    def _open_folder(self):
        try:
            os.startfile(setuplib.self_dir())     # noqa: S606 — только Windows
        except (OSError, AttributeError):
            pass

    def _clean(self):
        self.removed = setuplib.remove_legacy_traces()
        self.btn_clean.state(["disabled"])
        self.status.config(
            text="Убрано: %d. Программа больше нигде в системе не значится."
                 % len(self.removed))


def run_cleanup(quiet=False):
    """Показывает окно удаления. quiet — снять следы без окна.

    Тихий режим вызывается из QuietUninstallString, который прежние версии
    прописали в реестр: там окно показывать не принято.
    """
    if quiet:
        setuplib.remove_legacy_traces()
        return True
    win = CleanupWindow()
    win.mainloop()
    return win.removed is not None
