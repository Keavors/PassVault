# -*- coding: utf-8 -*-
"""Главное окно PassVault."""

import os
import shutil
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import APP_NAME, __version__, config, crypto, model, paths
from .. import portable, storage, throttle
from ..session import Vault
from . import dialogs
from .widgets import (DANGER, DIM, HEAD, MONO, PasswordPrompt,
                      ScrollList, center_on, human_size)

AUTOSAVE_DELAY_MS = 900
AUTOLOCK_TICK_MS = 10_000


class App(tk.Tk):
    def __init__(self, vault_path=None):
        super().__init__()
        # Заголовок виден на панели задач и в Alt+Tab — там только название.
        self.title(APP_NAME)
        self.geometry("1040x650")
        self.minsize(860, 520)
        self._set_icon()

        self.vault = Vault(self._pick_startup_path(vault_path))
        self.current_id = None
        self.view_ids = []
        self._save_job = None
        self._clip_job = None
        self._countdown_job = None
        self._loading = False
        self._baseline_password = ""
        self.last_activity = time.time()
        self.status_var = tk.StringVar(value="")

        self.bind_all("<Any-KeyPress>", self._touch, add="+")
        self.bind_all("<Button>", self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.show_unlock()
        self.after(AUTOLOCK_TICK_MS, self._autolock_tick)

    # ------------------------------------------------------------------
    # Служебное
    # ------------------------------------------------------------------
    def _set_icon(self):
        try:
            from .icon import ICON_PNG_B64
            self._icon = tk.PhotoImage(data=ICON_PNG_B64)
            self.iconphoto(True, self._icon)
        except Exception:
            pass

    @staticmethod
    def _pick_startup_path(explicit):
        """Какое хранилище открывать.

        Порядок важен: явный аргумент, потом запомненное, потом поиск по
        вероятным местам. Прошлая версия смотрела только рядом с exe — если
        программа лежала в подпапке, она объявляла «хранилище не создано»,
        хотя файл был уровнем выше.
        """
        if explicit:
            return os.path.abspath(explicit)
        last = config.last_vault()
        if last:
            return last
        found = paths.find_existing_vault()
        if found:
            return found
        return paths.default_vault_path()

    def _touch(self, *_):
        self.last_activity = time.time()

    def _autolock_tick(self):
        if self.vault.is_open:
            minutes = int(self.vault.app_settings.get("autolock_minutes", 5))
            if time.time() - self.last_activity > minutes * 60:
                self.lock("Заблокировано после %d мин бездействия" % minutes,
                          silent=True)
        self.after(AUTOLOCK_TICK_MS, self._autolock_tick)

    def _busy(self, on=True):
        try:
            self.config(cursor="watch" if on else "")
            self.update_idletasks()
        except tk.TclError:
            pass

    def _clear_window(self):
        try:
            self.config(menu="")
        except tk.TclError:
            pass
        for w in self.winfo_children():
            w.destroy()

    def status_msg(self, text):
        self.status_var.set(text)

    # ------------------------------------------------------------------
    # Экран входа
    # ------------------------------------------------------------------
    def show_unlock(self, msg=None):
        self._clear_window()
        self.current_id = None

        box = ttk.Frame(self, padding=24)
        box.place(relx=0.5, rely=0.42, anchor="center")

        ttk.Label(box, text=APP_NAME, font=HEAD).grid(row=0, column=0,
                                                          columnspan=2, pady=(0, 4))
        ttk.Label(box, text="Файл: " + self.vault.path, foreground=DIM,
                  wraplength=540).grid(row=1, column=0, columnspan=2, pady=(0, 14))

        self._pw1 = tk.StringVar()
        self._pw2 = tk.StringVar()
        exists = self.vault.exists()

        if exists:
            wait = self.vault.guard.remaining()
            ttk.Label(box, text="Мастер-пароль:").grid(row=2, column=0, sticky="e",
                                                       padx=6, pady=4)
            self._entry_pw = ttk.Entry(box, textvariable=self._pw1, show="•",
                                       width=34, font=MONO)
            self._entry_pw.grid(row=2, column=1, pady=4)
            self._btn_open = ttk.Button(box, text="Открыть", command=self._unlock)
            self._btn_open.grid(row=3, column=1, sticky="ew", pady=8)
            self._entry_pw.bind("<Return>", lambda _e: self._unlock())
            self._entry_pw.focus_set()
            self._lock_note = ttk.Label(box, text="", foreground=DANGER)
            self._lock_note.grid(row=4, column=0, columnspan=2)
            if wait:
                self._countdown(wait)
        else:
            candidates = self.vault.recovery_candidates()
            if candidates:
                self.after(80, lambda: self._offer_recovery(candidates))
            ttk.Label(box, justify="left",
                      text="Хранилище ещё не создано.\n"
                           "Придумай мастер-пароль — лучше фразу из 4–5 слов:"
                      ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 6))
            ttk.Label(box, text="Мастер-пароль:").grid(row=3, column=0, sticky="e",
                                                       padx=6, pady=4)
            e1 = ttk.Entry(box, textvariable=self._pw1, show="•", width=34, font=MONO)
            e1.grid(row=3, column=1, pady=4)
            ttk.Label(box, text="Ещё раз:").grid(row=4, column=0, sticky="e",
                                                 padx=6, pady=4)
            e2 = ttk.Entry(box, textvariable=self._pw2, show="•", width=34, font=MONO)
            e2.grid(row=4, column=1, pady=4)
            ttk.Button(box, text="Создать хранилище", command=self._create
                       ).grid(row=5, column=1, sticky="ew", pady=8)
            e2.bind("<Return>", lambda _e: self._create())
            e1.focus_set()

        bar = ttk.Frame(box)
        bar.grid(row=9, column=0, columnspan=2, sticky="e", pady=(16, 0))
        recent = config.recent_vaults()
        if len(recent) > 1:
            ttk.Button(bar, text="Недавние…", command=self._pick_recent
                       ).pack(side="left", padx=4)
        ttk.Button(bar, text="Резервные копии…", command=self._recovery_browser
                   ).pack(side="left", padx=4)
        ttk.Button(bar, text="Открыть другой файл…", command=self._pick_file
                   ).pack(side="left", padx=4)

        if msg:
            ttk.Label(box, text=msg, foreground=DANGER, wraplength=540
                      ).grid(row=10, column=0, columnspan=2, pady=(10, 0))

    def _countdown(self, seconds):
        """Пауза после неверных паролей — видимая, а не молчаливая.

        Прежняя задача обязательно отменяется. Без этого каждая новая неверная
        попытка пересоздавала экран и запускала ВТОРУЮ цепочку after(); после
        нескольких попыток счётчик тикал по две-три секунды в секунду и
        досчитывал до нуля раньше, чем истекала настоящая пауза.
        """
        if self._countdown_job:
            self.after_cancel(self._countdown_job)
            self._countdown_job = None
        if not hasattr(self, "_lock_note"):
            return
        try:
            if seconds <= 0:
                self._lock_note.config(text="")
                self._btn_open.state(["!disabled"])
                self._entry_pw.state(["!disabled"])
                return
            self._btn_open.state(["disabled"])
            self._entry_pw.state(["disabled"])
            self._lock_note.config(text="Слишком много неверных попыток. "
                                        "Подожди %s" % throttle.human_delay(seconds))
            self._countdown_job = self.after(
                1000, lambda: self._countdown(seconds - 1))
        except tk.TclError:
            pass

    def _pick_file(self):
        p = filedialog.askopenfilename(
            title="Файл хранилища", parent=self,
            filetypes=[("Хранилище", "*.pmv"), ("Все файлы", "*.*")])
        if p:
            self.vault = Vault(p)
            self.show_unlock()

    def _pick_recent(self):
        recent = config.recent_vaults()
        dlg = tk.Toplevel(self)
        dlg.title("Недавние хранилища")
        dlg.transient(self)
        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill="both", expand=True)
        lst = ScrollList(frm, height=min(8, len(recent)), width=70)
        lst.pack(fill="both", expand=True)
        lst.set_items(recent)
        lst.select(0)

        def choose():
            i = lst.selected_index()
            if i is None:
                return
            dlg.destroy()
            self.vault = Vault(recent[i])
            self.show_unlock()

        lst.bind_double(choose)
        bar = ttk.Frame(frm)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="Открыть", command=choose).pack(side="left")
        ttk.Button(bar, text="Закрыть", command=dlg.destroy).pack(side="right")
        center_on(dlg, self)
        dlg.grab_set()

    def _recovery_browser(self):
        candidates = self.vault.recovery_candidates()
        if not candidates:
            messagebox.showinfo("Резервные копии", "Копий не найдено:\n%s"
                                % self.vault.paths.backups, parent=self)
            return
        self._offer_recovery(candidates)

    def _offer_recovery(self, candidates):
        result = dialogs.RecoveryDialog(self, self.vault.path, candidates).show()
        if not result:
            return
        if result[0] == "new":
            return
        src = result[1]
        try:
            os.makedirs(os.path.dirname(self.vault.path), exist_ok=True)
            shutil.copy2(src, self.vault.path)
        except OSError as e:
            messagebox.showerror("Восстановление",
                                 "Не удалось восстановить:\n%s" % e, parent=self)
            return
        self.show_unlock("Восстановлено. Введи пароль от этой копии.")

    # ------------------------------------------------------------------
    def _unlock(self):
        pw = self._pw1.get()
        if not pw:
            return
        wait = self.vault.guard.remaining()
        if wait:
            self._countdown(wait)
            return

        self._busy(True)
        try:
            notes = self.vault.open(pw)
        except crypto.VaultError as e:
            self._busy(False)
            delay = self.vault.guard.remaining()
            note = str(e)
            if delay:
                note += "\nСлишком много попыток — пауза %s." % throttle.human_delay(delay)
            else:
                left = self.vault.guard.attempts_left()
                if left and self.vault.guard.failures():
                    note += "\nПопыток до паузы: %d" % left
            self.show_unlock(note)
            return
        except (storage.StorageError, ValueError) as e:
            self._busy(False)
            self.show_unlock(str(e))
            return
        self._busy(False)

        if not self._acquire_lock():
            self.vault.close()
            self.show_unlock()
            return

        self.show_main()
        if notes:
            # Показываем последнее: перевод на Argon2id важнее сообщения о
            # перенесённых служебных файлах, а места в строке одна штука.
            self.status_msg(notes[-1])

    def _create(self):
        p1, p2 = self._pw1.get(), self._pw2.get()
        if not p1:
            return
        if p1 != p2:
            messagebox.showerror(APP_NAME, "Пароли не совпадают", parent=self)
            return
        if len(p1) < 12 and not messagebox.askyesno(
                APP_NAME,
                "Мастер-пароль короче 12 символов — его проще подобрать перебором.\n"
                "Всё равно использовать?", parent=self):
            return
        self._busy(True)
        try:
            self.vault.create(p1)
        except (storage.StorageError, OSError) as e:
            self._busy(False)
            self.vault.close()
            messagebox.showerror(APP_NAME, "Не удалось создать хранилище:\n%s" % e,
                                 parent=self)
            return
        self._busy(False)
        if not self._acquire_lock():
            self.vault.close()
            self.show_unlock()
            return
        self.show_main()

    def _acquire_lock(self):
        """Не даём двум копиям программы затирать правки друг друга."""
        try:
            self.vault.lock.acquire()
            return True
        except storage.AlreadyLocked as e:
            if messagebox.askyesno(
                    "Хранилище уже открыто",
                    "Хранилище уже открыто другой копией (процесс %s на «%s»).\n"
                    "Всё равно открыть?" % (e.pid, e.host),
                    icon="warning", parent=self):
                self.vault.lock.force()
                return True
            return False

    # ------------------------------------------------------------------
    # Сохранение
    # ------------------------------------------------------------------
    def schedule_save(self):
        if self._save_job:
            self.after_cancel(self._save_job)
        self._save_job = self.after(AUTOSAVE_DELAY_MS, self._flush_save)

    def _flush_save(self):
        self._save_job = None
        if not self.vault.is_open:
            return
        try:
            self.vault.save()
            self.status_msg("Сохранено " + time.strftime("%H:%M:%S"))
        except (storage.StorageError, OSError) as e:
            # Молча глотать ошибку записи нельзя: раньше правки исчезали при
            # закрытии программы и при автоблокировке, и никто не узнавал.
            self.status_msg("НЕ СОХРАНЕНО — " + str(e).split("\n")[0])
            messagebox.showerror("Не удалось сохранить", str(e), parent=self)

    def flush_now(self):
        """Немедленно сохраняет отложенные правки. Возвращает True при успехе."""
        if self._save_job:
            self.after_cancel(self._save_job)
            self._save_job = None
        if not self.vault.is_open:
            return True
        try:
            self.vault.save()
            return True
        except (storage.StorageError, OSError) as e:
            messagebox.showerror("Не удалось сохранить", str(e), parent=self)
            return False

    def settings_changed(self):
        self.vault.mark_dirty()
        self.schedule_save()

    def _snapshot_before(self, tag):
        try:
            self.vault.snapshot(tag)
            return True
        except (storage.StorageError, OSError) as e:
            messagebox.showerror(
                "Резервная копия",
                "Не удалось сделать снимок перед операцией, операция отменена:\n%s" % e,
                parent=self)
            return False

    # ------------------------------------------------------------------
    # Главный экран
    # ------------------------------------------------------------------
    def show_main(self):
        self._clear_window()
        self._build_menu()

        bar = ttk.Frame(self, relief="groove", padding=(8, 2))
        bar.pack(side="bottom", fill="x")
        ttk.Label(bar, textvariable=self.status_var, foreground="#444").pack(side="left")
        self.fmt_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.fmt_var, foreground=DIM).pack(side="right")

        outer = ttk.Frame(self)
        outer.pack(side="top", fill="both", expand=True)

        left = ttk.Frame(outer, padding=(10, 10, 6, 10))
        left.pack(side="left", fill="y")
        self.search_var = tk.StringVar()
        se = ttk.Entry(left, textvariable=self.search_var, width=34)
        se.pack(fill="x")
        se.bind("<KeyRelease>", lambda _e: self.refresh_list())

        self.list = ScrollList(left, height=24, width=34)
        self.list.pack(fill="both", expand=True, pady=(6, 6))
        self.list.listbox.bind("<<ListboxSelect>>", self._on_select)

        btns = ttk.Frame(left)
        btns.pack(fill="x")
        ttk.Button(btns, text="＋ Новая", command=self.new_entry
                   ).pack(side="left", expand=True, fill="x", padx=(0, 3))
        ttk.Button(btns, text="Удалить", command=self.delete_entry
                   ).pack(side="left", expand=True, fill="x", padx=(3, 0))

        right = ttk.Frame(outer, padding=(6, 10, 12, 10))
        right.pack(side="left", fill="both", expand=True)
        right.columnconfigure(1, weight=1)

        self.title_var = tk.StringVar()
        self.login_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.meta_var = tk.StringVar()
        self.show_pw = tk.BooleanVar(value=False)

        r = 0
        ttk.Label(right, text="Название:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
        self.e_title = ttk.Entry(right, textvariable=self.title_var)
        self.e_title.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        r += 1
        ttk.Label(right, text="Логин:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
        self.e_login = ttk.Entry(right, textvariable=self.login_var)
        self.e_login.grid(row=r, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Button(right, text="Копировать", command=self.copy_login
                   ).grid(row=r, column=3, padx=(4, 0))
        r += 1
        ttk.Label(right, text="Пароль:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
        self.e_pass = ttk.Entry(right, textvariable=self.pass_var, show="•", font=MONO)
        self.e_pass.grid(row=r, column=1, sticky="ew", pady=4)
        ttk.Checkbutton(right, text="показать", variable=self.show_pw,
                        command=self._toggle_pw).grid(row=r, column=2, padx=4)
        pwb = ttk.Frame(right)
        pwb.grid(row=r, column=3, padx=(2, 0))
        ttk.Button(pwb, text="Копировать", command=self.copy_password).pack(side="left", padx=2)
        ttk.Button(pwb, text="Сгенерировать…",
                   command=self.open_generator_for_entry).pack(side="left", padx=2)
        ttk.Button(pwb, text="История…", command=self.show_history).pack(side="left", padx=2)
        r += 1
        ttk.Label(right, text="Адрес:").grid(row=r, column=0, sticky="e", padx=6, pady=4)
        self.e_url = ttk.Entry(right, textvariable=self.url_var)
        self.e_url.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        r += 1
        ttk.Label(right, text="Заметки:").grid(row=r, column=0, sticky="ne", padx=6, pady=4)
        nf = ttk.Frame(right)
        nf.grid(row=r, column=1, columnspan=3, sticky="nsew", pady=4)
        right.rowconfigure(r, weight=1)
        self.t_notes = tk.Text(nf, wrap="word", height=10, undo=True)
        nsb = ttk.Scrollbar(nf, command=self.t_notes.yview)
        self.t_notes.config(yscrollcommand=nsb.set)
        self.t_notes.pack(side="left", fill="both", expand=True)
        nsb.pack(side="right", fill="y")
        r += 1
        ttk.Label(right, textvariable=self.meta_var, foreground=DIM
                  ).grid(row=r, column=1, columnspan=3, sticky="w")

        for w in (self.e_title, self.e_login, self.e_pass, self.e_url):
            w.bind("<KeyRelease>", self._on_field_change)
            w.bind("<FocusOut>", self._on_field_change)
        self.t_notes.bind("<KeyRelease>", self._on_field_change)
        self.t_notes.bind("<FocusOut>", self._on_field_change)

        self._set_fields_state(False)
        self.current_id = None
        self.refresh_list()
        self._update_status_counts()
        self.fmt_var.set(self.vault.params.describe_container())

    def _build_menu(self):
        m = tk.Menu(self)

        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Сохранить сейчас", command=self._flush_save,
                       accelerator="Ctrl+S")
        fm.add_separator()
        fm.add_command(label="Слить с другим файлом… (синхронизация)",
                       command=self.merge_with_file)
        fm.add_command(label="Сохранить копию как… (для переноса)",
                       command=self.export_copy)
        fm.add_separator()
        fm.add_command(label="Экспорт в CSV…", command=lambda: self.export_plain("csv"))
        fm.add_command(label="Экспорт в JSON…", command=lambda: self.export_plain("json"))
        fm.add_command(label="Импорт из CSV/JSON…", command=self.import_plain)
        fm.add_separator()
        fm.add_command(label="Заблокировать", command=self.lock, accelerator="Ctrl+L")
        fm.add_command(label="Выход", command=self._on_close)
        m.add_cascade(label="Файл", menu=fm)

        em = tk.Menu(m, tearoff=0)
        em.add_command(label="Новая запись", command=self.new_entry, accelerator="Ctrl+N")
        em.add_command(label="Удалить запись", command=self.delete_entry)
        em.add_separator()
        em.add_command(label="Корзина…", command=self.show_trash)
        m.add_cascade(label="Правка", menu=em)

        bm = tk.Menu(m, tearoff=0)
        bm.add_command(label="Резервные копии…", command=self.show_backups,
                       accelerator="Ctrl+B")
        bm.add_command(label="Создать снимок сейчас", command=self.snapshot_now)
        m.add_cascade(label="Копии", menu=bm)

        tm = tk.Menu(m, tearoff=0)
        tm.add_command(label="Генератор паролей…",
                       command=lambda: dialogs.GeneratorDialog(
                           self, self.vault.gen_settings).show())
        tm.add_separator()
        tm.add_command(label="Сменить мастер-пароль…", command=self.change_master)
        tm.add_separator()
        tm.add_command(label="Очистить старые удалённые записи…",
                       command=self.purge_tombstones)
        tm.add_command(label="Настройки…", command=self.show_settings)
        m.add_cascade(label="Инструменты", menu=tm)

        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="О программе", command=self._about)
        m.add_cascade(label="Справка", menu=hm)

        self.config(menu=m)
        self.bind("<Control-s>", lambda _e: self._flush_save())
        self.bind("<Control-l>", lambda _e: self.lock())
        self.bind("<Control-n>", lambda _e: self.new_entry())
        self.bind("<Control-b>", lambda _e: self.show_backups())

    def _about(self):
        snaps = self.vault.backups.list_snapshots()
        messagebox.showinfo(
            "О программе",
            "%s %s\n\n"
            "%s\n"
            "AES-256-GCM, %s\n"
            "%s\n\n"
            "Снимков: %d (%s)\n"
            "%s"
            % (APP_NAME, __version__, self.vault.path, self.vault.params.describe(),
               self.vault.params.describe_container(), len(snaps),
               human_size(self.vault.backups.total_size()), self.vault.paths.backups),
            parent=self)

    # ------------------------------------------------------------------
    # Список записей
    # ------------------------------------------------------------------
    def refresh_list(self, select_id=None):
        q = self.search_var.get().lower().strip()
        self.view_ids = []
        items = []
        for e in sorted(model.live_entries(self.vault.entries),
                        key=lambda x: (x.get("title") or "").lower()):
            if q and q not in model.search_haystack(e):
                continue
            self.view_ids.append(e["id"])
            items.append(model.display_title(e))
        self.list.set_items(items)

        if select_id is None:
            select_id = self.current_id
        if select_id in self.view_ids:
            self.list.select(self.view_ids.index(select_id))

    def _update_status_counts(self):
        trash = len(model.deleted_entries(self.vault.entries))
        extra = ("   ·   в корзине: %d" % trash) if trash else ""
        self.status_msg("Записей: %d%s"
                        % (len(model.live_entries(self.vault.entries)), extra))

    def _on_select(self, _event=None):
        i = self.list.selected_index()
        if i is None:
            return
        eid = self.view_ids[i]
        if eid != self.current_id:
            self._commit_password_history()
            self.load_entry(eid)

    def load_entry(self, eid):
        e = self.vault.entry(eid)
        if not e:
            return
        self.current_id = eid
        self._loading = True
        self._set_fields_state(True)
        self.title_var.set(e.get("title", ""))
        self.login_var.set(e.get("login", ""))
        self.pass_var.set(e.get("password", ""))
        self.url_var.set(e.get("url", ""))
        self.t_notes.delete("1.0", "end")
        self.t_notes.insert("1.0", e.get("notes", ""))
        self._baseline_password = e.get("password", "")
        self._refresh_meta(e)
        self.show_pw.set(False)
        self._toggle_pw()
        self._loading = False

    def _refresh_meta(self, e):
        hist = e.get("history") or []
        extra = ("   ·   прошлых паролей: %d" % len(hist)) if hist else ""
        self.meta_var.set("создано %s   ·   изменено %s%s"
                          % (model.fmt_ts(e.get("created")),
                             model.fmt_ts(e.get("modified")), extra))

    def _set_fields_state(self, enabled):
        st = "normal" if enabled else "disabled"
        for w in (self.e_title, self.e_login, self.e_pass, self.e_url):
            w.config(state=st)
        self.t_notes.config(state=st)

    def _clear_fields(self):
        self._loading = True
        self._set_fields_state(True)
        for var in (self.title_var, self.login_var, self.pass_var, self.url_var):
            var.set("")
        self.t_notes.delete("1.0", "end")
        self.meta_var.set("")
        self._set_fields_state(False)
        self._loading = False

    def _on_field_change(self, _event=None):
        if self._loading or not self.current_id or not self.vault.is_open:
            return
        e = self.vault.entry(self.current_id)
        if not e:
            return
        new = (self.title_var.get(), self.login_var.get(), self.pass_var.get(),
               self.url_var.get(), self.t_notes.get("1.0", "end-1c"))
        old = (e.get("title", ""), e.get("login", ""), e.get("password", ""),
               e.get("url", ""), e.get("notes", ""))
        if new == old:
            return
        (e["title"], e["login"], e["password"], e["url"], e["notes"]) = new
        e["modified"] = model.now_iso()
        self.vault.mark_dirty()
        self._refresh_meta(e)
        self._update_list_title()
        self.schedule_save()

    def _commit_password_history(self):
        """Кладёт прежний пароль в историю при уходе с записи.

        Именно при уходе, а не на каждое нажатие клавиши: иначе история
        забилась бы огрызками набираемого пароля.
        """
        if not self.current_id or not self.vault.is_open:
            return
        e = self.vault.entry(self.current_id)
        if not e:
            return
        current = e.get("password", "")
        if current != self._baseline_password and self._baseline_password:
            model.push_history(e, self._baseline_password)
            self.vault.mark_dirty()
            self.schedule_save()
        self._baseline_password = current

    def _update_list_title(self):
        """Обновляет название в списке, а если надо — и его место в нём.

        Раньше строка правилась только на месте: переименуй «Яндекс» в
        «Аська» — и запись остаётся внизу списка до следующего обновления,
        хотя список отсортирован по алфавиту.

        Полностью пересобираем список лишь когда порядок действительно
        нарушился: пересборка на каждое нажатие клавиши заметно моргает.
        """
        if self.current_id not in self.view_ids:
            return
        i = self.view_ids.index(self.current_id)
        new = model.display_title(self.vault.entry(self.current_id))
        if self.list.listbox.get(i) == new:
            return

        low = new.lower()
        fits_after = i == 0 or self.list.listbox.get(i - 1).lower() <= low
        fits_before = (i == len(self.view_ids) - 1
                       or low <= self.list.listbox.get(i + 1).lower())
        if fits_after and fits_before:
            self.list.listbox.delete(i)
            self.list.listbox.insert(i, new)
            self.list.select(i)
        else:
            self.refresh_list(select_id=self.current_id)

    def new_entry(self):
        if not self.vault.is_open:
            return
        self._commit_password_history()
        e = self.vault.new_entry()
        self.search_var.set("")
        self.refresh_list(select_id=e["id"])
        self.load_entry(e["id"])
        self.e_title.focus_set()
        self.e_title.select_range(0, "end")
        self._update_status_counts()
        self.schedule_save()

    def delete_entry(self):
        if not self.current_id:
            return
        e = self.vault.entry(self.current_id)
        if not e:
            return
        if not messagebox.askyesno(
                "Удалить запись",
                "Удалить «%s»?" % model.display_title(e), parent=self):
            return
        self.vault.delete_entry(self.current_id)
        self.current_id = None
        self._baseline_password = ""
        self._clear_fields()
        self.refresh_list()
        self._update_status_counts()
        self.schedule_save()

    def show_trash(self):
        def on_change(msg):
            self.vault.mark_dirty()
            self.refresh_list()
            self._update_status_counts()
            self.schedule_save()
            self.status_msg(msg)
        dialogs.TrashDialog(self, self.vault.entries, on_change).show()

    def show_history(self):
        if not self.current_id:
            return
        self._commit_password_history()
        e = self.vault.entry(self.current_id)
        if not e:
            return
        chosen = dialogs.HistoryDialog(self, e).show()
        if chosen is None:
            return
        self.pass_var.set(chosen)
        self.show_pw.set(True)
        self._toggle_pw()
        self._on_field_change()
        self.status_msg("Пароль возвращён из истории")

    # ------------------------------------------------------------------
    # Пароль и буфер обмена
    # ------------------------------------------------------------------
    def _toggle_pw(self):
        self.e_pass.config(show="" if self.show_pw.get() else "•")

    def copy_password(self):
        self.copy_secret(self.pass_var.get())

    def copy_login(self):
        self.copy_secret(self.login_var.get())

    def copy_secret(self, text):
        """Кладёт пароль в буфер и заводит будильник на его стирание.

        Раньше пароль оставался в буфере обмена навсегда. На Windows 10 и 11
        это особенно дорого: включена история буфера (Win+V), и оттуда пароль
        может уехать в облачную синхронизацию.

        Чего это НЕ даёт, и врать тут нельзя: саму историю Win+V программа
        почистить не может, туда пароль попадает в момент копирования. Стереть
        мы способны только текущее содержимое буфера.
        """
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

        seconds = self._clipboard_seconds()
        if seconds:
            self._arm_clipboard_clear(text, seconds)
            self.status_msg("Скопировано · буфер очистится через %d с" % seconds)
        else:
            self.status_msg("Скопировано")

    def _clipboard_seconds(self):
        if not self.vault.is_open:
            return 0
        try:
            return max(0, int(self.vault.app_settings.get("clipboard_seconds", 30)))
        except (TypeError, ValueError):
            return 30

    def _arm_clipboard_clear(self, secret, seconds):
        if self._clip_job:
            self.after_cancel(self._clip_job)
        self._clip_job = self.after(seconds * 1000,
                                    lambda: self._clear_clipboard(secret))

    def _clear_clipboard(self, secret):
        """Стирает буфер, но только если там всё ещё наш пароль.

        Проверка обязательна: за эти секунды человек мог скопировать что-то
        своё, и стереть чужое из-под него — свинство.
        """
        self._clip_job = None
        try:
            if self.clipboard_get() != secret:
                return
        except tk.TclError:
            return                      # буфер пуст или там не текст
        try:
            self.clipboard_clear()
            self.status_msg("Буфер обмена очищен")
        except tk.TclError:
            pass

    def open_generator_for_entry(self):
        if not self.vault.is_open:
            return
        on_use = None
        if self.current_id:
            def on_use(p):
                self._commit_password_history()
                self.pass_var.set(p)
                self.show_pw.set(True)
                self._toggle_pw()
                self._on_field_change()
                self.status_msg("Пароль вставлен в запись, прежний сохранён в истории")
        dialogs.GeneratorDialog(self, self.vault.gen_settings, on_use=on_use).show()

    # ------------------------------------------------------------------
    # Перенос и слияние
    # ------------------------------------------------------------------
    def export_copy(self):
        if not self.flush_now():
            return
        p = filedialog.asksaveasfilename(
            title="Сохранить копию хранилища", parent=self, defaultextension=".pmv",
            initialfile="vault.pmv",
            filetypes=[("Хранилище", "*.pmv"), ("Все файлы", "*.*")])
        if not p:
            return
        try:
            shutil.copy2(self.vault.path, p)
        except OSError as e:
            messagebox.showerror("Экспорт", "Не удалось сохранить:\n%s" % e, parent=self)
            return
        self.status_msg("Копия сохранена: " + p)

    def _load_foreign_vault(self, path, ask_title):
        """Читает чужой файл: сначала пробуем текущий ключ, потом спрашиваем пароль."""
        try:
            return self.vault.read_foreign(path)
        except (crypto.VaultError, storage.StorageError):
            pass
        pw = PasswordPrompt(self, ask_title,
                            "Этот файл зашифрован другим паролем.\n"
                            "Введи мастер-пароль от него:").show()
        if pw is None:
            return None
        self._busy(True)
        try:
            return self.vault.read_foreign(path, pw)
        except (crypto.VaultError, storage.StorageError) as e:
            messagebox.showerror("Открытие файла", str(e), parent=self)
            return None
        finally:
            self._busy(False)

    def merge_with_file(self):
        p = filedialog.askopenfilename(
            title="Файл для слияния (например, принесённый с телефона)", parent=self,
            filetypes=[("Хранилище", "*.pmv"), ("Все файлы", "*.*")])
        if not p:
            return
        data = self._load_foreign_vault(p, "Слияние")
        if data is None:
            return
        self._run_merge(self.vault.entries_of(data), os.path.basename(p), "premerge")

    def _run_merge(self, incoming, source_name, tag):
        plan = self.vault.plan_merge(incoming)
        if plan.is_empty:
            messagebox.showinfo("Слияние", "Различий не найдено — всё уже совпадает.",
                                parent=self)
            return

        mode = dialogs.MergePreviewDialog(self, plan, source_name).show()
        if mode is None:
            self.status_msg("Слияние отменено — ничего не изменено.")
            return

        decisions = plan.suggestions()
        if mode == "auto":
            ask = [i for i, c in enumerate(plan.conflicts) if c.same_timestamp]
        else:
            ask = list(range(len(plan.conflicts)))

        n = 0
        while n < len(ask):
            idx = ask[n]
            answer = dialogs.ConflictDialog(self, plan.conflicts[idx],
                                            n + 1, len(ask)).show()
            if answer is None:
                self.status_msg("Слияние отменено — ничего не изменено.")
                return
            decision, apply_all = answer
            decisions[idx] = decision
            if apply_all:
                for k in ask[n + 1:]:
                    decisions[k] = decision
                break
            n += 1

        if not self._snapshot_before(tag):
            return
        stats = self.vault.apply_merge(plan, decisions)
        if not self.flush_now():
            return
        self.refresh_list()
        self._update_status_counts()
        messagebox.showinfo(
            "Слияние завершено",
            "Добавлено: %d\nРасхождений: %d\n   локальных: %d\n   из файла: %d\n"
            "   обе версии: %d"
            % (stats["added"], len(plan.conflicts), stats["kept_local"],
               stats["took_incoming"], stats["kept_both"]), parent=self)

    # ------------------------------------------------------------------
    # Резервные копии
    # ------------------------------------------------------------------
    def show_backups(self):
        if not self.flush_now():
            return

        def snap_now():
            try:
                return self.vault.snapshot()
            except (storage.StorageError, OSError) as e:
                messagebox.showerror("Резервные копии", str(e), parent=self)
                return None

        result = dialogs.BackupDialog(self, self.vault.backups, snap_now).show()
        if result and result[0] == "restore":
            self._restore_from_snapshot(result[1])

    def snapshot_now(self):
        if not self.flush_now():
            return
        try:
            snap = self.vault.snapshot()
        except (storage.StorageError, OSError) as e:
            messagebox.showerror("Резервные копии", str(e), parent=self)
            return
        self.status_msg("Снимок создан: " + (snap.label() if snap else "—"))

    def _restore_from_snapshot(self, snap):
        """Восстановление слиянием, а не заменой файла.

        Так «вернуть запись, удалённую вчера» не сносит всё, что добавлено
        сегодня. За разбор расхождений отвечает тот же механизм, что и за
        синхронизацию с телефоном.
        """
        data = self._load_foreign_vault(snap.path, "Восстановление")
        if data is None:
            return
        self._run_merge(self.vault.entries_of(data),
                        "снимок от " + snap.label(), "prerestore")

    # ------------------------------------------------------------------
    # Экспорт и импорт открытым текстом
    # ------------------------------------------------------------------
    def export_plain(self, fmt):
        if not messagebox.askyesno(
                "Экспорт без шифрования",
                "Файл будет сохранён БЕЗ ШИФРОВАНИЯ — пароли открытым текстом.\n"
                "Продолжить?",
                icon="warning", parent=self):
            return
        ext = ".csv" if fmt == "csv" else ".json"
        p = filedialog.asksaveasfilename(
            title="Экспорт (без шифрования)", parent=self, defaultextension=ext,
            initialfile="passvault-export" + ext,
            filetypes=[("CSV", "*.csv") if fmt == "csv" else ("JSON", "*.json"),
                       ("Все файлы", "*.*")])
        if not p:
            return
        entries = self.vault.entries
        text = (portable.export_csv(entries) if fmt == "csv"
                else portable.export_json(entries))
        try:
            portable.write_export(p, text)
        except OSError as e:
            messagebox.showerror("Экспорт", "Не удалось сохранить:\n%s" % e, parent=self)
            return
        self.status_msg("Экспортировано без шифрования: " + p)

    def import_plain(self):
        p = filedialog.askopenfilename(
            title="Импорт из CSV или JSON", parent=self,
            filetypes=[("CSV и JSON", "*.csv *.json"), ("Все файлы", "*.*")])
        if not p:
            return
        try:
            entries = portable.read_import(p)
        except portable.ImportError_ as e:
            messagebox.showerror("Импорт", str(e), parent=self)
            return
        if not messagebox.askyesno(
                "Импорт",
                "Найдено записей: %d. Добавить?" % len(entries), parent=self):
            return
        if not self._snapshot_before("preimport"):
            return
        added = self.vault.add_entries(entries)
        if not self.flush_now():
            return
        self.refresh_list()
        self._update_status_counts()
        self.status_msg("Добавлено записей: %d" % added)

    # ------------------------------------------------------------------
    # Инструменты
    # ------------------------------------------------------------------
    def purge_tombstones(self):
        doomed = model.purgeable_tombstones(self.vault.entries)
        if not doomed:
            messagebox.showinfo(
                "Очистка",
                "Удалённых записей старше %d дней нет."
                % model.TOMBSTONE_TTL_DAYS, parent=self)
            return
        if not messagebox.askyesno(
                "Очистка",
                "Стереть %d записей старше %d дней? Отменить будет нельзя."
                % (len(doomed), model.TOMBSTONE_TTL_DAYS),
                icon="warning", parent=self):
            return
        if not self._snapshot_before("prepurge"):
            return
        n = self.vault.purge_tombstones()
        if not self.flush_now():
            return
        self.refresh_list()
        self._update_status_counts()
        self.status_msg("Вычищено записей: %d" % n)


    def change_master(self):
        result = dialogs.ChangeMasterDialog(self).show()
        if not result:
            return
        current, new = result
        if not self.flush_now():
            return
        self._busy(True)
        try:
            ok = self.vault.change_password(current, new)
        except (storage.StorageError, OSError) as e:
            self._busy(False)
            messagebox.showerror("Смена пароля", "Пароль НЕ изменён.\n%s" % e, parent=self)
            return
        self._busy(False)
        if not ok:
            messagebox.showerror("Смена пароля", "Текущий пароль неверен", parent=self)
            return
        self.status_msg("Мастер-пароль изменён")

    def show_settings(self):
        result = dialogs.SettingsDialog(self, self.vault.app_settings,
                                        self.vault.paths.default_backups).show()
        if not result:
            return
        backup_dir = result.pop("backup_dir")
        self.vault.app_settings.update(result)
        moved_to = self.vault.move_backups_to(backup_dir)
        self.settings_changed()
        self.status_msg("Резервные копии: " + moved_to)

    # ------------------------------------------------------------------
    # Блокировка и выход
    # ------------------------------------------------------------------
    def lock(self, msg=None, silent=False):
        if not self.vault.is_open:
            return
        self._commit_password_history()
        if not self.flush_now():
            if silent:
                # Автоблокировка не имеет права выбросить несохранённое.
                self.status_msg("Автоблокировка отложена: правки не сохранены")
                self.last_activity = time.time()
                return
            if not messagebox.askyesno(
                    "Заблокировать",
                    "Правки не сохранены. Если заблокировать сейчас, они пропадут.\n\n"
                    "Всё равно заблокировать?", icon="warning", parent=self):
                return
        self.vault.lock.release()
        self.vault.close()
        self.current_id = None
        self._baseline_password = ""
        self.show_unlock(msg or "Заблокировано")

    def destroy(self):
        """Снимает отложенные задачи Tk перед закрытием.

        Иначе автосохранение, очистка буфера или обратный отсчёт, назначенные
        через after(), срабатывают уже на разрушенном окне и сыплют ошибками
        Tcl.
        """
        for attr in ("_save_job", "_clip_job", "_countdown_job"):
            try:
                job = getattr(self, attr, None)
                if job:
                    self.after_cancel(job)
                setattr(self, attr, None)
            except Exception:
                pass
        try:
            self.vault.lock.release()
        except Exception:
            pass
        super().destroy()

    def _on_close(self):
        if self.vault.is_open:
            self._commit_password_history()
            if not self.flush_now():
                if not messagebox.askyesno(
                        "Выход", "Правки не сохранены и будут потеряны.\n\n"
                                 "Всё равно выйти?", icon="warning", parent=self):
                    return
        self.destroy()
