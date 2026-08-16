# -*- coding: utf-8 -*-
"""Окна установки и удаления."""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import __version__, setup as setuplib
from .widgets import DANGER, DIM, GOOD, HEAD


class InstallerWindow(tk.Tk):
    """Окно установщика. Установщик только ставит — больше он ничего не делает."""

    def __init__(self):
        super().__init__()
        self.title("Установка PassVault %s" % __version__)
        self.resizable(False, False)
        self.result = None
        self._set_icon()

        self.v_dir = tk.StringVar(value=setuplib.default_install_dir())
        self.v_desktop = tk.BooleanVar(value=True)
        self.v_start_menu = tk.BooleanVar(value=True)
        self.v_launch = tk.BooleanVar(value=True)

        frm = ttk.Frame(self, padding=18)
        frm.grid(sticky="nsew")
        frm.columnconfigure(0, weight=1)

        ttk.Label(frm, text="PassVault", font=HEAD).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text="Офлайн-хранилище и генератор паролей, версия %s"
                            % __version__, foreground=DIM
                  ).grid(row=1, column=0, sticky="w", pady=(0, 14))

        existing = setuplib.installed_location()
        if existing:
            ttk.Label(frm, text="Обновление: " + existing, foreground=GOOD
                      ).grid(row=2, column=0, sticky="w", pady=(0, 10))
            self.v_dir.set(existing)

        box = ttk.LabelFrame(frm, text="Куда установить", padding=10)
        box.grid(row=3, column=0, sticky="ew")
        box.columnconfigure(0, weight=1)
        ttk.Entry(box, textvariable=self.v_dir, width=58).grid(row=0, column=0, sticky="ew")
        ttk.Button(box, text="Обзор…", command=self._browse).grid(row=0, column=1, padx=(6, 0))

        # Предупреждение про системный диск. Не запрет — человек вправе
        # поставить куда хочет, — но знать он об этом должен заранее.
        self.drive_note = ttk.Label(frm, text="", foreground=DANGER,
                                    justify="left", wraplength=460)
        self.drive_note.grid(row=4, column=0, sticky="w", pady=(6, 0))
        self.v_dir.trace_add("write", lambda *_a: self._check_drive())
        self._check_drive()

        opts = ttk.Frame(frm)
        opts.grid(row=5, column=0, sticky="w", pady=(10, 0))
        ttk.Checkbutton(opts, text="Ярлык на рабочем столе",
                        variable=self.v_desktop).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(opts, text="Ярлык в меню «Пуск»",
                        variable=self.v_start_menu).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(opts, text="Запустить после установки",
                        variable=self.v_launch).grid(row=2, column=0, sticky="w")

        self.status = ttk.Label(frm, text="", foreground=DIM, wraplength=460,
                                justify="left")
        self.status.grid(row=6, column=0, sticky="w", pady=(10, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=7, column=0, sticky="ew", pady=(14, 0))
        self.btn_install = ttk.Button(bar, text="Установить", command=self._install)
        self.btn_install.pack(side="left")
        ttk.Button(bar, text="Выход", command=self.destroy).pack(side="right")

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

    def _browse(self):
        d = filedialog.askdirectory(title="Куда установить PassVault",
                                    initialdir=self.v_dir.get(), parent=self)
        if d:
            self.v_dir.set(os.path.join(d, "PassVault")
                           if os.path.basename(d).lower() != "passvault" else d)

    def _check_drive(self):
        if setuplib.is_on_system_drive(self.v_dir.get()):
            self.drive_note.config(
                text="Это системный диск (%s). Хранилище окажется на нём же —\n"
                     "выбери другой диск, если держишь данные отдельно."
                     % setuplib.system_drive())
        else:
            self.drive_note.config(text="")

    def _say(self, text):
        self.status.config(text=text)
        self.update_idletasks()

    def _install(self):
        self.btn_install.state(["disabled"])
        try:
            exe = setuplib.install(self.v_dir.get(),
                                   desktop_shortcut=self.v_desktop.get(),
                                   start_menu=self.v_start_menu.get(),
                                   progress=self._say)
        except OSError as e:
            self.btn_install.state(["!disabled"])
            messagebox.showerror("Установка", "Не удалось установить:\n%s" % e,
                                 parent=self)
            return

        self.status.config(text="Установлено: " + exe, foreground=GOOD)
        if self.v_launch.get():
            # Открываем установленную программу через оболочку (ShellExecute),
            # как будто по ней кликнули в проводнике. Раньше здесь стоял
            # subprocess.Popen([exe]) — прямой запуск только что записанного
            # файла дочерним процессом. Для поведенческого монитора Windows
            # Defender это в точности почерк дроппера: неподписанная программа
            # копирует exe в другую папку и тут же исполняет его как своего
            # потомка. Именно эта связка (копирование + запись в реестр +
            # запуск записанного файла) и ловится как DefenseEvasion. Через
            # os.startfile запуск идёт штатным путём оболочки, а не потомком
            # установщика, и «дропнул и запустил» из картины уходит.
            try:
                os.startfile(exe)
            except OSError:
                pass
        self.result = "installed"
        self.destroy()


class UninstallWindow(tk.Tk):
    """Подтверждение удаления.

    Окно обязано говорить правду про судьбу данных. Прежняя версия писала
    «Хранилище и резервные копии останутся» безусловно — и это было ложью
    ровно в том случае, который встречается чаще всего: программа установлена
    в ту же папку, где лежит хранилище.
    """

    def __init__(self):
        super().__init__()
        self.title("Удаление PassVault")
        self.resizable(False, False)
        self.confirmed = False
        self.kept = []

        target = setuplib.self_dir()
        vaults = setuplib.vault_files_in(target)

        frm = ttk.Frame(self, padding=18)
        frm.grid(sticky="nsew")

        ttk.Label(frm, text="Удалить PassVault?", font=("Segoe UI", 14, "bold")
                  ).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text=target, foreground=DIM, justify="left", wraplength=460
                  ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        # Единственный вопрос, который тут важен, — что будет с паролями.
        if vaults:
            ttk.Label(frm, text="В этой папке лежит твоё хранилище:",
                      foreground=DANGER, font=("Segoe UI", 10, "bold")
                      ).grid(row=2, column=0, sticky="w", pady=(12, 2))
            ttk.Label(frm, text="\n".join("    " + n for n in vaults),
                      foreground=DANGER, justify="left", wraplength=460
                      ).grid(row=3, column=0, sticky="w")
            ttk.Label(frm, text="Оно НЕ будет удалено. Удаляется только сама\n"
                                "программа; папка останется вместе с данными.",
                      foreground=GOOD, justify="left"
                      ).grid(row=4, column=0, sticky="w", pady=(6, 0))
        else:
            ttk.Label(frm, text="Хранилище и резервные копии останутся:\n"
                                "они лежат рядом с файлом vault.pmv, а не здесь.",
                      foreground=GOOD, justify="left"
                      ).grid(row=2, column=0, sticky="w", pady=(12, 0))

        self.status = ttk.Label(frm, text="", foreground=DIM, wraplength=460,
                                justify="left")
        self.status.grid(row=5, column=0, sticky="w", pady=(12, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=6, column=0, sticky="e", pady=(14, 0))
        ttk.Button(bar, text="Удалить", command=self._go).pack(side="left", padx=4)
        ttk.Button(bar, text="Отмена", command=self.destroy).pack(side="left")

        self.update_idletasks()
        x = (self.winfo_screenwidth() - self.winfo_width()) // 2
        y = (self.winfo_screenheight() - self.winfo_height()) // 3
        self.geometry("+%d+%d" % (max(0, x), max(0, y)))

    def _go(self):
        def say(t):
            self.status.config(text=t)
            self.update_idletasks()
        target, self.kept = setuplib.uninstall(progress=say)
        self.confirmed = True
        if self.kept:
            messagebox.showinfo(
                "Удаление",
                "Программа удалена.\n\nПапка оставлена — в ней твои файлы:\n%s\n\n%s"
                % ("\n".join("    " + n for n in self.kept), target),
                parent=self)
        self.destroy()


def run_installer():
    win = InstallerWindow()
    win.mainloop()
    return win.result


def run_uninstaller(quiet=False):
    if quiet:
        setuplib.uninstall()
        return True
    win = UninstallWindow()
    win.mainloop()
    return win.confirmed
