# -*- coding: utf-8 -*-
"""Мелкие общие детали интерфейса."""

import tkinter as tk
from tkinter import ttk

MONO = ("Consolas", 11)
MONO_BIG = ("Consolas", 12)
HEAD = ("Segoe UI", 20, "bold")
SMALL = ("Segoe UI", 8)

DIM = "#777777"
DANGER = "#b00000"
GOOD = "#1a7f37"


def center_on(win, parent, dx=60, dy=60):
    try:
        win.geometry("+%d+%d" % (parent.winfo_rootx() + dx,
                                 parent.winfo_rooty() + dy))
    except tk.TclError:
        pass


def human_size(n):
    if n < 1024:
        return "%d Б" % n
    if n < 1024 * 1024:
        return "%.1f КБ" % (n / 1024.0)
    return "%.1f МБ" % (n / 1024.0 / 1024.0)


def elide(text, limit=200):
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[:limit] + "…"


class Modal(tk.Toplevel):
    """Модальное окно с общим поведением.

    Закрытие крестиком или Escape ВСЕГДА трактуется как отмена. Это важно не
    из вежливости: автоблокировка при бездействии может закрыть окно сама, и
    вызывающий код обязан отличить «пользователь выбрал» от «окно закрылось».
    Поэтому show() возвращает None при отмене, и никак иначе.
    """

    def __init__(self, parent, title, resizable=False):
        super().__init__(parent)
        self.parent = parent
        self.result = None
        self.title(title)
        self.resizable(resizable, resizable)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.bind("<Escape>", lambda _e: self.on_cancel())

    def show(self):
        """Показывает окно и ждёт закрытия. Возвращает self.result."""
        self.update_idletasks()
        center_on(self, self.parent)
        self.grab_set()
        self.wait_window(self)
        return self.result

    def on_cancel(self):
        self.result = None
        self.destroy()

    def finish(self, result):
        self.result = result
        self.destroy()


class PasswordPrompt(Modal):
    """Запрос пароля. Возвращает строку или None при отмене."""

    def __init__(self, parent, title, prompt, confirm=False):
        super().__init__(parent, title)
        self.confirm = confirm
        self.v1 = tk.StringVar()
        self.v2 = tk.StringVar()

        frm = ttk.Frame(self, padding=14)
        frm.grid(sticky="nsew")
        ttk.Label(frm, text=prompt, wraplength=420, justify="left"
                  ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(frm, text="Пароль:").grid(row=1, column=0, sticky="e", padx=(0, 6))
        e1 = ttk.Entry(frm, textvariable=self.v1, show="•", width=32, font=MONO)
        e1.grid(row=1, column=1, pady=3)

        if confirm:
            ttk.Label(frm, text="Ещё раз:").grid(row=2, column=0, sticky="e",
                                                 padx=(0, 6))
            ttk.Entry(frm, textvariable=self.v2, show="•", width=32, font=MONO
                      ).grid(row=2, column=1, pady=3)

        self.error = ttk.Label(frm, text="", foreground=DANGER, wraplength=420)
        self.error.grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=4, column=0, columnspan=2, pady=(12, 0), sticky="e")
        ttk.Button(bar, text="OK", command=self._ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Отмена", command=self.on_cancel).pack(side="left")

        self.bind("<Return>", lambda _e: self._ok())
        e1.focus_set()

    def _ok(self):
        p1 = self.v1.get()
        if not p1:
            self.error.config(text="Пароль пуст")
            return
        if self.confirm and p1 != self.v2.get():
            self.error.config(text="Пароли не совпадают")
            return
        self.finish(p1)


class ScrollList(ttk.Frame):
    """Список с полосой прокрутки — то, что иначе приходится собирать каждый раз."""

    def __init__(self, parent, height=12, width=48, font=None, selectmode="browse"):
        super().__init__(parent)
        self.listbox = tk.Listbox(self, height=height, width=width,
                                  exportselection=False, activestyle="dotbox",
                                  selectmode=selectmode,
                                  font=font or ("Segoe UI", 10))
        bar = ttk.Scrollbar(self, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=bar.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")

    def set_items(self, items):
        self.listbox.delete(0, "end")
        for item in items:
            self.listbox.insert("end", item)

    def selected_index(self):
        sel = self.listbox.curselection()
        return sel[0] if sel else None

    def selected_indices(self):
        return list(self.listbox.curselection())

    def select(self, index):
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(index)
        self.listbox.see(index)

    def bind_double(self, callback):
        self.listbox.bind("<Double-Button-1>", lambda _e: callback())
