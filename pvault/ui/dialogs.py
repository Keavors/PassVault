# -*- coding: utf-8 -*-
"""Диалоговые окна PassVault."""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import generator as gen
from .. import merge as mergelib
from .. import model
from .widgets import (DANGER, DIM, GOOD, MONO, MONO_BIG, Modal, ScrollList,
                      elide, human_size)

__all__ = ["GeneratorDialog", "MergePreviewDialog", "ConflictDialog",
           "TrashDialog", "HistoryDialog", "BackupDialog", "RecoveryDialog",
           "ChangeMasterDialog", "SettingsDialog"]


# ---------------------------------------------------------------------------
# Генератор
# ---------------------------------------------------------------------------
class GeneratorDialog(Modal):
    def __init__(self, app, settings, on_use=None):
        super().__init__(app, "Генератор паролей")
        self.app = app
        self.settings = settings
        self.on_use = on_use

        s = settings
        self.v_lower = tk.BooleanVar(value=s.get("use_lower", True))
        self.v_upper = tk.BooleanVar(value=s.get("use_upper", True))
        self.v_digits = tk.BooleanVar(value=s.get("use_digits", True))
        self.v_symbols = tk.BooleanVar(value=s.get("use_symbols", True))
        self.v_symset = tk.StringVar(value=s.get("symbols", gen.DEFAULT_SYMBOLS))
        self.v_require = tk.BooleanVar(value=s.get("require_each", True))
        self.v_noamb = tk.BooleanVar(value=s.get("no_ambiguous", False))
        self.v_mode = tk.StringVar(value="exact" if s.get("exact_mode", True) else "range")
        self.v_exact = tk.IntVar(value=int(s.get("exact_len", 16)))
        self.v_min = tk.IntVar(value=int(s.get("min_len", 12)))
        self.v_max = tk.IntVar(value=int(s.get("max_len", 20)))
        self.v_req = tk.StringVar(value=s.get("required_chars", ""))
        self.v_excl = tk.StringVar(value=s.get("excluded_chars", ""))
        self.v_result = tk.StringVar()

        frm = ttk.Frame(self, padding=12)
        frm.grid(sticky="nsew")

        lf = ttk.LabelFrame(frm, text="Длина", padding=8)
        lf.grid(row=0, column=0, sticky="ew")
        ttk.Radiobutton(lf, text="Точная:", variable=self.v_mode, value="exact",
                        command=self._sync).grid(row=0, column=0, sticky="w")
        self.sp_exact = ttk.Spinbox(lf, from_=1, to=gen.MAX_LENGTH, width=5, textvariable=self.v_exact)
        self.sp_exact.grid(row=0, column=1, padx=(4, 24))
        ttk.Radiobutton(lf, text="Диапазон:", variable=self.v_mode, value="range",
                        command=self._sync).grid(row=0, column=2, sticky="w")
        self.sp_min = ttk.Spinbox(lf, from_=1, to=gen.MAX_LENGTH, width=5, textvariable=self.v_min)
        self.sp_min.grid(row=0, column=3, padx=4)
        ttk.Label(lf, text="—").grid(row=0, column=4)
        self.sp_max = ttk.Spinbox(lf, from_=1, to=gen.MAX_LENGTH, width=5, textvariable=self.v_max)
        self.sp_max.grid(row=0, column=5, padx=4)

        gf = ttk.LabelFrame(frm, text="Группы символов", padding=8)
        gf.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Checkbutton(gf, text="Строчные латинские (a–z)", variable=self.v_lower
                        ).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(gf, text="Заглавные латинские (A–Z)", variable=self.v_upper
                        ).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(gf, text="Цифры (0–9)", variable=self.v_digits
                        ).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(gf, text="Спецсимволы:", variable=self.v_symbols
                        ).grid(row=3, column=0, sticky="w")
        ttk.Entry(gf, textvariable=self.v_symset, width=30, font=MONO
                  ).grid(row=3, column=1, sticky="w", padx=(4, 0))
        ttk.Checkbutton(gf, text="Минимум по одному из каждой группы",
                        variable=self.v_require).grid(row=4, column=0, columnspan=2,
                                                      sticky="w", pady=(6, 0))
        ttk.Checkbutton(gf, text="Исключить похожие символы",
                        variable=self.v_noamb).grid(row=5, column=0, columnspan=2,
                                                    sticky="w")

        ef = ttk.LabelFrame(frm, text="Тонкая настройка", padding=8)
        ef.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ef.columnconfigure(1, weight=1)
        ttk.Label(ef, text="Обязательно включить:").grid(row=0, column=0, sticky="e",
                                                         padx=(0, 4))
        ttk.Entry(ef, textvariable=self.v_req, font=MONO).grid(row=0, column=1, sticky="ew")
        ttk.Label(ef, text="Исключить символы:").grid(row=1, column=0, sticky="e",
                                                      padx=(0, 4), pady=(4, 0))
        ttk.Entry(ef, textvariable=self.v_excl, font=MONO).grid(row=1, column=1,
                                                                sticky="ew", pady=(4, 0))

        rf = ttk.Frame(frm)
        rf.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        rf.columnconfigure(0, weight=1)
        ttk.Entry(rf, textvariable=self.v_result, font=MONO_BIG, width=44
                  ).grid(row=0, column=0, sticky="ew")
        self.lb_bits = ttk.Label(rf, text="", foreground=DIM)
        self.lb_bits.grid(row=1, column=0, sticky="w", pady=(3, 0))

        bf = ttk.Frame(frm)
        bf.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(bf, text="Сгенерировать", command=self.do_generate).pack(side="left")
        ttk.Button(bf, text="Копировать", command=self.do_copy).pack(side="left", padx=6)
        if on_use:
            ttk.Button(bf, text="Вставить в запись", command=self.do_use).pack(side="left")
        ttk.Button(bf, text="Закрыть", command=self.on_cancel).pack(side="right")

        self._sync()
        self.bind("<Return>", lambda _e: self.do_generate())

    def _sync(self):
        exact = self.v_mode.get() == "exact"
        self.sp_exact.config(state="normal" if exact else "disabled")
        state = "disabled" if exact else "normal"
        self.sp_min.config(state=state)
        self.sp_max.config(state=state)

    @staticmethod
    def _int(var, default):
        try:
            return int(var.get())
        except (tk.TclError, ValueError):
            return default

    def collect(self):
        return {
            "use_lower": self.v_lower.get(),
            "use_upper": self.v_upper.get(),
            "use_digits": self.v_digits.get(),
            "use_symbols": self.v_symbols.get(),
            "symbols": self.v_symset.get(),
            "require_each": self.v_require.get(),
            "exact_mode": self.v_mode.get() == "exact",
            "exact_len": self._int(self.v_exact, 16),
            "min_len": self._int(self.v_min, 12),
            "max_len": self._int(self.v_max, 20),
            "required_chars": self.v_req.get(),
            "excluded_chars": self.v_excl.get(),
            "no_ambiguous": self.v_noamb.get(),
        }

    def do_generate(self):
        opts = self.collect()
        try:
            pwd, pool = gen.generate_password(opts)
        except gen.GeneratorError as e:
            messagebox.showerror("Генератор", str(e), parent=self)
            return
        self.v_result.set(pwd)
        bits = gen.estimate_bits(opts, len(pwd), pool)
        self.lb_bits.config(
            text="≈%.0f бит — %s" % (bits, gen.rate_bits(bits)),
            foreground=GOOD if bits >= 64 else DANGER if bits < 45 else DIM)
        self.settings.clear()
        self.settings.update(opts)
        self.app.settings_changed()

    def do_copy(self):
        if self.v_result.get():
            self.app.copy_secret(self.v_result.get())

    def do_use(self):
        pwd = self.v_result.get()
        if pwd and self.on_use:
            self.on_use(pwd)
            self.destroy()


# ---------------------------------------------------------------------------
# Слияние
# ---------------------------------------------------------------------------
class MergePreviewDialog(Modal):
    """Возвращает "auto" | "manual" | None."""

    def __init__(self, parent, plan, source_name):
        super().__init__(parent, "Слияние")
        frm = ttk.Frame(self, padding=14)
        frm.grid(sticky="nsew")

        ttk.Label(frm, text=source_name, wraplength=520, foreground=DIM,
                  justify="left").grid(row=0, column=0, sticky="w", pady=(0, 10))

        ambiguous = plan.ambiguous_count
        text = ("Добавится записей: %d\nРасхождений: %d"
                % (len(plan.to_add), len(plan.conflicts)))
        if ambiguous:
            text += "\nИз них правились одновременно: %d" % ambiguous
        ttk.Label(frm, text=text, justify="left").grid(row=1, column=0, sticky="w")

        bar = ttk.Frame(frm)
        bar.grid(row=2, column=0, sticky="e", pady=(14, 0))
        if plan.conflicts:
            ttk.Button(bar, text="Взять самое свежее",
                       command=lambda: self.finish("auto")).pack(side="left", padx=4)
            ttk.Button(bar, text="По одному",
                       command=lambda: self.finish("manual")).pack(side="left", padx=4)
        else:
            ttk.Button(bar, text="Слить",
                       command=lambda: self.finish("auto")).pack(side="left", padx=4)
        ttk.Button(bar, text="Отмена", command=self.on_cancel).pack(side="left", padx=4)


class ConflictDialog(Modal):
    """Возвращает (решение, применить_ко_всем) либо None при отмене."""

    def __init__(self, parent, conflict, index, total):
        super().__init__(parent, "Расхождение %d из %d" % (index, total))
        self.conflict = conflict
        self.v_all = tk.BooleanVar(value=False)

        frm = ttk.Frame(self, padding=14)
        frm.grid(sticky="nsew")
        frm.columnconfigure(0, weight=1, uniform="c")
        frm.columnconfigure(1, weight=1, uniform="c")

        ttk.Label(frm, text=conflict.title, font=("Segoe UI", 11, "bold")
                  ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        same = conflict.same_timestamp
        self._card(frm, 0, "На этом компьютере", conflict.local,
                   is_newer=not conflict.incoming_is_newer and not same)
        self._card(frm, 1, "В файле", conflict.incoming,
                   is_newer=conflict.incoming_is_newer and not same)

        if same:
            ttk.Label(frm, text="Правились одновременно", foreground=DANGER
                      ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

        if total > 1:
            ttk.Checkbutton(frm, variable=self.v_all,
                            text="Ко всем оставшимся (%d)" % (total - index + 1)
                            ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Button(bar, text="Оставить локальную",
                   command=lambda: self._done(mergelib.LOCAL)).pack(side="left")
        ttk.Button(bar, text="Взять из файла",
                   command=lambda: self._done(mergelib.INCOMING)).pack(side="left", padx=6)
        if not conflict.involves_deletion:
            ttk.Button(bar, text="Оставить обе",
                       command=lambda: self._done(mergelib.BOTH)).pack(side="left")
        ttk.Button(bar, text="Отменить слияние",
                   command=self.on_cancel).pack(side="right")

    def _card(self, parent, col, caption, e, is_newer):
        box = ttk.LabelFrame(parent, text=caption + ("   • новее" if is_newer else ""),
                             padding=8)
        box.grid(row=1, column=col, sticky="nsew", padx=(0, 8) if col == 0 else (8, 0))
        box.columnconfigure(1, weight=1)

        if e.get("deleted"):
            ttk.Label(box, text="УДАЛЕНА", foreground=DANGER,
                      font=("Segoe UI", 10, "bold")).grid(row=0, column=0,
                                                          columnspan=2, sticky="w")
            ttk.Label(box, text=model.fmt_ts(e.get("modified")), foreground=DIM
                      ).grid(row=1, column=0, columnspan=2, sticky="w")
            return

        rows = [("Название", e.get("title", ""), None),
                ("Логин", e.get("login", ""), None),
                ("Пароль", e.get("password", ""), MONO),
                ("Адрес", e.get("url", ""), None),
                ("Заметки", elide(e.get("notes", ""), 260), None)]
        r = 0
        for label, value, font in rows:
            if not value:
                continue
            ttk.Label(box, text=label + ":", foreground=DIM).grid(row=r, column=0,
                                                                  sticky="ne", padx=(0, 6))
            ttk.Label(box, text=value, wraplength=260, justify="left",
                      font=font).grid(row=r, column=1, sticky="w")
            r += 1
        ttk.Label(box, text=model.fmt_ts(e.get("modified")), foreground=DIM
                  ).grid(row=r, column=0, columnspan=2, sticky="w", pady=(6, 0))

    def _done(self, decision):
        self.finish((decision, self.v_all.get()))


# ---------------------------------------------------------------------------
# Корзина
# ---------------------------------------------------------------------------
class TrashDialog(Modal):
    def __init__(self, app, entries, on_change):
        super().__init__(app, "Корзина", resizable=True)
        self.app = app
        self.entries_ref = entries
        self.on_change = on_change
        self.items = []

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        self.header = ttk.Label(frm, text="")
        self.header.pack(anchor="w", pady=(0, 6))

        self.list = ScrollList(frm, height=14, width=70)
        self.list.pack(fill="both", expand=True)
        self.list.listbox.config(selectmode="extended")
        self.list.bind_double(self.restore)

        bar = ttk.Frame(frm)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text="Восстановить", command=self.restore).pack(side="left")
        ttk.Button(bar, text="Восстановить всё", command=self.restore_all
                   ).pack(side="left", padx=6)
        ttk.Button(bar, text="Удалить окончательно", command=self.purge).pack(side="left")
        ttk.Button(bar, text="Закрыть", command=self.on_cancel).pack(side="right")

        self.refresh()
        self.geometry("680x420")

    def refresh(self):
        self.items = sorted(model.deleted_entries(self.entries_ref),
                            key=lambda e: model.ts_sort_key(e.get("modified")),
                            reverse=True)
        self.list.set_items([
            "%s   ·   %s" % (model.display_title(e), model.fmt_ts(e.get("modified")))
            for e in self.items])
        self.header.config(text="Записей: %d" % len(self.items))

    def _selected(self):
        return [self.items[i] for i in self.list.selected_indices()]

    def restore(self):
        chosen = self._selected()
        if not chosen:
            return
        for e in chosen:
            model.restore(e)
        self.refresh()
        self.on_change("Восстановлено: %d" % len(chosen))

    def restore_all(self):
        if not self.items:
            return
        if not messagebox.askyesno("Корзина", "Восстановить все %d записей?"
                                   % len(self.items), parent=self):
            return
        n = len(self.items)
        for e in list(self.items):
            model.restore(e)
        self.refresh()
        self.on_change("Восстановлено: %d" % n)

    def purge(self):
        chosen = self._selected()
        if not chosen:
            return
        if not messagebox.askyesno(
                "Удалить окончательно",
                "Стереть %d запис(ь/и) без возможности восстановления?" % len(chosen),
                icon="warning", parent=self):
            return
        doomed = {id(e) for e in chosen}
        self.entries_ref[:] = [e for e in self.entries_ref if id(e) not in doomed]
        self.refresh()
        self.on_change("Стёрто: %d" % len(chosen))


# ---------------------------------------------------------------------------
# История паролей
# ---------------------------------------------------------------------------
class HistoryDialog(Modal):
    """Возвращает выбранный пароль или None."""

    def __init__(self, app, entry):
        super().__init__(app, "История паролей", resizable=True)
        self.app = app
        self.entry = entry
        self.items = list(entry.get("history") or [])

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        if not self.items:
            ttk.Label(frm, text="Пусто").pack(anchor="w")
            ttk.Button(frm, text="Закрыть", command=self.on_cancel).pack(anchor="e",
                                                                          pady=(14, 0))
            return

        self.list = ScrollList(frm, height=10, width=60, font=MONO)
        self.list.pack(fill="both", expand=True)
        self.list.set_items(["%s   ·   %s"
                             % (h.get("password", ""),
                                model.fmt_ts(h.get("changed"), "—"))
                             for h in self.items])
        self.list.bind_double(self.restore_selected)

        bar = ttk.Frame(frm)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text="Копировать", command=self.copy_selected).pack(side="left")
        ttk.Button(bar, text="Сделать текущим",
                   command=self.restore_selected).pack(side="left", padx=6)
        ttk.Button(bar, text="Закрыть", command=self.on_cancel).pack(side="right")
        self.geometry("600x380")

    def _sel(self):
        i = self.list.selected_index()
        return self.items[i] if i is not None else None

    def copy_selected(self):
        h = self._sel()
        if h:
            self.app.copy_secret(h.get("password", ""))

    def restore_selected(self):
        h = self._sel()
        if h:
            self.finish(h.get("password", ""))


# ---------------------------------------------------------------------------
# Резервные копии
# ---------------------------------------------------------------------------
class BackupDialog(Modal):
    # Параметра on_restore здесь больше нет: он принимался и никогда не
    # использовался, а вызывающий код честно передавал в него None.
    def __init__(self, app, manager, on_snapshot_now):
        super().__init__(app, "Резервные копии", resizable=True)
        self.app = app
        self.manager = manager
        self.on_snapshot_now = on_snapshot_now
        self.items = []

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        self.header = ttk.Label(frm, text="")
        self.header.pack(anchor="w")
        ttk.Label(frm, text=manager.dir, foreground=DIM, wraplength=660,
                  justify="left").pack(anchor="w", pady=(0, 8))

        self.list = ScrollList(frm, height=14, width=70)
        self.list.pack(fill="both", expand=True)
        self.list.bind_double(self.restore)

        bar = ttk.Frame(frm)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text="Восстановить", command=self.restore).pack(side="left")
        ttk.Button(bar, text="Снимок сейчас",
                   command=self.snapshot_now).pack(side="left", padx=6)
        ttk.Button(bar, text="Открыть папку", command=self.open_folder).pack(side="left")
        ttk.Button(bar, text="Закрыть", command=self.on_cancel).pack(side="right")

        self.refresh()
        self.geometry("740x480")

    def refresh(self):
        self.items = self.manager.list_snapshots()
        self.list.set_items(["%s   ·   %s" % (s.label(), human_size(s.size))
                             for s in self.items])
        self.header.config(text="Снимков: %d   ·   %s"
                                % (len(self.items),
                                   human_size(self.manager.total_size())))

    def restore(self):
        i = self.list.selected_index()
        if i is None:
            return
        self.finish(("restore", self.items[i]))

    def snapshot_now(self):
        self.on_snapshot_now()
        self.refresh()

    def open_folder(self):
        try:
            os.startfile(self.manager.dir)          # noqa: S606 — только Windows
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Восстановление пропавшего хранилища
# ---------------------------------------------------------------------------
class RecoveryDialog(Modal):
    """Возвращает ("restore", путь) | ("new",) | None."""

    def __init__(self, parent, vault_path, candidates):
        super().__init__(parent, "Хранилище не найдено", resizable=True)
        self.candidates = candidates

        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=vault_path, foreground=DIM, wraplength=620,
                  justify="left").pack(anchor="w", pady=(0, 8))

        self.list = ScrollList(frm, height=10, width=76)
        self.list.pack(fill="both", expand=True)
        import time
        self.list.set_items([
            "%s   ·   %s   ·   %s"
            % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.mtime)),
               c.note, human_size(c.size))
            for c in candidates])
        self.list.select(0)
        self.list.bind_double(self._restore)

        bar = ttk.Frame(frm)
        bar.pack(fill="x", pady=(12, 0))
        ttk.Button(bar, text="Восстановить", command=self._restore).pack(side="left")
        ttk.Button(bar, text="Создать новое",
                   command=lambda: self.finish(("new",))).pack(side="left", padx=6)
        ttk.Button(bar, text="Выход", command=self.on_cancel).pack(side="right")
        self.geometry("720x400")

    def _restore(self):
        i = self.list.selected_index()
        if i is None:
            return
        self.finish(("restore", self.candidates[i].path))


# ---------------------------------------------------------------------------
# Мастер-пароль и формат
# ---------------------------------------------------------------------------
class ChangeMasterDialog(Modal):
    """Возвращает (текущий, новый) или None."""

    def __init__(self, parent):
        super().__init__(parent, "Смена мастер-пароля")
        self.v0, self.v1, self.v2 = tk.StringVar(), tk.StringVar(), tk.StringVar()

        frm = ttk.Frame(self, padding=14)
        frm.grid(sticky="nsew")
        for i, (label, var) in enumerate((("Текущий пароль:", self.v0),
                                          ("Новый пароль:", self.v1),
                                          ("Новый ещё раз:", self.v2))):
            ttk.Label(frm, text=label).grid(row=i, column=0, sticky="e", padx=6, pady=4)
            ent = ttk.Entry(frm, textvariable=var, show="•", width=30, font=MONO)
            ent.grid(row=i, column=1, pady=4)
            if i == 0:
                ent.focus_set()

        self.error = ttk.Label(frm, text="", foreground=DANGER, wraplength=380)
        self.error.grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=4, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(bar, text="Применить", command=self._ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Отмена", command=self.on_cancel).pack(side="left", padx=4)
        self.bind("<Return>", lambda _e: self._ok())

    def _ok(self):
        if not self.v1.get():
            self.error.config(text="Новый пароль пуст")
            return
        if self.v1.get() != self.v2.get():
            self.error.config(text="Пароли не совпадают")
            return
        if len(self.v1.get()) < 12 and not messagebox.askyesno(
                "Смена пароля", "Пароль короче 12 символов. Использовать?",
                parent=self):
            return
        self.finish((self.v0.get(), self.v1.get()))


# Здесь был FormatDialog — окно «Формат шифрования» с выбором между PBKDF2 и
# Argon2id. Удалено вместе с самим выбором: PBKDF2 слабее при любых настройках,
# и предлагать его пользователю было нечестно.
#
# Отдельно про надпись, которая жила в этом окне красным текстом:
#
#     «Android-версия PMVAULT2 не открывает.»
#
# Это была неправда. Телефон считает Argon2id через BouncyCastle и открывает
# оба формата — на это есть тесты с обеих сторон (PcCompatibilityTest на
# Android и test_android_interop.py здесь). Надпись осталась от версии 2.0,
# где так и было, и три версии подряд пугала пользователя на ровном месте.


class SettingsDialog(Modal):
    """Возвращает словарь настроек или None."""

    def __init__(self, parent, current, default_backup_dir):
        super().__init__(parent, "Настройки")
        self.default_backup_dir = default_backup_dir
        self.v_lock = tk.IntVar(value=int(current.get("autolock_minutes", 5)))
        self.v_clip = tk.IntVar(value=int(current.get("clipboard_seconds", 30)))
        self.v_backups = tk.StringVar(
            value=current.get("backup_dir") or default_backup_dir)

        frm = ttk.Frame(self, padding=14)
        frm.grid(sticky="nsew")
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Автоблокировка, минут:").grid(row=0, column=0, sticky="e",
                                                           padx=(0, 6), pady=4)
        ttk.Spinbox(frm, from_=1, to=180, width=6, textvariable=self.v_lock
                    ).grid(row=0, column=1, sticky="w", pady=4)

        ttk.Label(frm, text="Очищать буфер обмена через, секунд:"
                  ).grid(row=1, column=0, sticky="e", padx=(0, 6), pady=4)
        clip = ttk.Frame(frm)
        clip.grid(row=1, column=1, sticky="w", pady=4)
        ttk.Spinbox(clip, from_=0, to=600, width=6, textvariable=self.v_clip
                    ).pack(side="left")
        ttk.Label(clip, text="0 — не очищать", foreground=DIM
                  ).pack(side="left", padx=(8, 0))
        # Обещать больше, чем можем, нельзя: история буфера Windows (Win+V)
        # программе недоступна, туда пароль попадает в момент копирования.
        ttk.Label(frm, text="История буфера Windows (Win+V) остаётся — её\n"
                            "программа очистить не может.",
                  foreground=DIM, justify="left"
                  ).grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Папка резервных копий:").grid(row=3, column=0, sticky="e",
                                                           padx=(0, 6), pady=(12, 4))
        box = ttk.Frame(frm)
        box.grid(row=3, column=1, sticky="ew", pady=(12, 4))
        box.columnconfigure(0, weight=1)
        ttk.Entry(box, textvariable=self.v_backups, width=54).grid(row=0, column=0,
                                                                   sticky="ew")
        ttk.Button(box, text="Обзор…", command=self._browse).grid(row=0, column=1,
                                                                  padx=(6, 0))
        ttk.Button(box, text="По умолчанию", command=self._reset).grid(row=0, column=2,
                                                                       padx=(6, 0))

        self.error = ttk.Label(frm, text="", foreground=DANGER)
        self.error.grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        bar = ttk.Frame(frm)
        bar.grid(row=5, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(bar, text="Сохранить", command=self._ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Отмена", command=self.on_cancel).pack(side="left")
        self.bind("<Return>", lambda _e: self._ok())

    def _browse(self):
        d = filedialog.askdirectory(title="Папка резервных копий", parent=self,
                                    initialdir=self.v_backups.get() or None)
        if d:
            self.v_backups.set(os.path.abspath(d))

    def _reset(self):
        self.v_backups.set(self.default_backup_dir)

    def _ok(self):
        try:
            lock = int(self.v_lock.get())
            clip = int(self.v_clip.get())
        except (tk.TclError, ValueError):
            self.error.config(text="Введи целое число")
            return

        chosen = self.v_backups.get().strip()
        if chosen:
            try:
                os.makedirs(chosen, exist_ok=True)
            except OSError as e:
                self.error.config(text="Папка недоступна: %s" % e)
                return
        if os.path.normcase(os.path.abspath(chosen or self.default_backup_dir)) == \
                os.path.normcase(self.default_backup_dir):
            chosen = ""

        self.finish({"autolock_minutes": max(1, min(180, lock)),
                     "clipboard_seconds": max(0, min(600, clip)),
                     "backup_dir": chosen})
