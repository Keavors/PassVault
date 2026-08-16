# -*- coding: utf-8 -*-
r"""Переносимый режим и уборка следов прежних версий.

Программа больше НИЧЕГО не устанавливает. Она работает там, где лежит: рядом
с PassVault.exe живёт vault.pmv, туда же пишется config.json. Перенести на
другой компьютер — скопировать папку. Удалить — удалить папку.

ПОЧЕМУ УСТАНОВЩИКА БОЛЬШЕ НЕТ

Версии 2.x–3.x несли установщик внутри себя: тот же самый exe под именем
PassVault-Setup.exe копировал себя в выбранную папку, писал ключ в
CurrentVersion\Uninstall, создавал ярлыки и запускал только что записанный
файл. Каждое действие по отдельности законно. Вместе они складываются в ту
самую последовательность, по которой антивирус узнаёт дроппер — программу,
которая незаметно раскладывает по диску другую программу.

Windows Defender так и поступил: установка версии 3.1 обрывалась вердиктом
Behavior:Win32/DefenseEvasion.A!ml, а файл удалялся. Вердикт был ложным —
эвристика, а не сигнатура (суффикс !ml): те же байты под именем PassVault.exe
проверку проходили, а под именем PassVault-Setup-3.1.exe удалялись.

Версия 3.2 убрала два самых приметных следа: вызов powershell для ярлыков и
прямой запуск установленного файла дочерним процессом. Этого не хватило —
на чужой машине Defender ругался снова, потому что несущая связка осталась:
скопировал себя, прописался в реестр, запустил записанное.

Дальше был выбор: маскировать эти действия или не делать их. Маскировка —
это ровно то, что и называется defense evasion; ею проблему не решить, ей её
подтверждают. Поэтому действий больше нет. Версия 1.0 не делала ничего
подобного и не ловилась антивирусом ни разу — сюда и вернулись.

ЧТО ОСТАЛОСЬ В МОДУЛЕ

Только уборка за прежними версиями: запись в «Установленных программах» и
ярлыки, которые они успели создать. Файлы программы и данные не удаляются
никогда и ничем: удалять с диска этот модуль умеет РОВНО ОДНО — файлы с
расширением .lnk, и на это есть тест.

Такое ограничение здесь не из аккуратности. Прежнее удаление выполняло

    rmdir /s /q "папка программы"

в расчёте на то, что хранилище лежит отдельно. Но переносимый режим кладёт
vault.pmv ровно рядом с exe — то есть штатный сценарий сам сводил программу и
данные в одну папку, и кнопка «Удалить» стирала хранилище, откат и весь архив
снимков. Модуль, который не умеет удалять ничего, кроме ярлыков, повторить
это не способен в принципе.
"""

import os
import sys

APP_NAME = "PassVault"
EXE_NAME = "PassVault.exe"

# Ключ, который создавали версии 2.x–3.x. Новая версия его НЕ СОЗДАЁТ —
# только находит и убирает. Записи в реестр этот модуль больше не делает.
REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\PassVault"

SHORTCUT_SUFFIX = ".lnk"


def is_frozen():
    return getattr(sys, "frozen", False)


def self_path():
    return os.path.abspath(sys.executable if is_frozen() else __file__)


def self_dir():
    return os.path.dirname(self_path())


# ---------------------------------------------------------------------------
# Следы прежних версий
# ---------------------------------------------------------------------------
def registry_entry():
    """Запись в «Установленных программах», если прежняя версия её оставила.

    Возвращает путь установки, пустую строку (ключ есть, значения нет) или
    None, если ключа нет вовсе. Читает и только читает.
    """
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY) as k:
            try:
                return winreg.QueryValueEx(k, "InstallLocation")[0]
            except OSError:
                return ""
    except OSError:
        return None


def start_menu_link():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs",
                        APP_NAME + SHORTCUT_SUFFIX)


def desktop_link():
    home = os.path.expanduser("~")
    for name in ("Desktop", "Рабочий стол"):
        d = os.path.join(home, name)
        if os.path.isdir(d):
            return os.path.join(d, APP_NAME + SHORTCUT_SUFFIX)
    return os.path.join(home, "Desktop", APP_NAME + SHORTCUT_SUFFIX)


def legacy_shortcuts():
    """Ярлыки, созданные прежними версиями и существующие сейчас."""
    return [link for link in (start_menu_link(), desktop_link())
            if os.path.isfile(link)]


def legacy_traces():
    """Всё, что прежние версии оставили в системе, человеческим текстом.

    Пустой список означает, что убирать нечего: программа никогда не ставилась
    в систему на этой машине либо следы уже сняты.
    """
    traces = []
    where = registry_entry()
    if where is not None:
        note = "Запись в «Установленных программах»"
        if where:
            note += " → " + where
        traces.append(note)
    traces += legacy_shortcuts()
    return traces


def remove_legacy_traces():
    """Снимает запись в реестре и ярлыки. Возвращает список убранного.

    Ни один файл, кроме ярлыков .lnk, тронут быть не может: список путей
    берётся из legacy_shortcuts(), а расширение проверяется ещё раз прямо
    перед удалением. Программа и хранилище не удаляются — их удаляет человек
    вместе с папкой, когда сочтёт нужным.
    """
    removed = []

    if os.name == "nt":
        try:
            import winreg
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_KEY)
            removed.append("запись в «Установленных программах»")
        except OSError:
            pass                      # ключа нет — и хорошо

    for link in legacy_shortcuts():
        if not link.lower().endswith(SHORTCUT_SUFFIX):
            continue                  # страховка от правки legacy_shortcuts()
        try:
            os.remove(link)
            removed.append(link)
        except OSError:
            pass

    return removed
