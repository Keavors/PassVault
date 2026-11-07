# -*- coding: utf-8 -*-
r"""Установка и удаление программы.

Установщик и приложение — ОДИН И ТОТ ЖЕ exe. Прошлая версия носила рядом с
приложением ещё и uninstall.exe на 28 мегабайт: отдельная сборка PyInstaller
ради нескольких строк удаления. Здесь тот же файл умеет и то, и другое, а в
«Параметры → Приложения» прописывается команда «GemSwap.exe --uninstall».

Ставится под текущего пользователя, права администратора не нужны — и не
запрашиваются: менеджеру паролей нечего делать с системными папками.

ДАННЫЕ ПРИ УДАЛЕНИИ НЕ ТРОГАЮТСЯ, и это обеспечено механикой, а не обещанием.

Обещанием оно было раньше, и обещание было ложным. Удаление выполняло

    rmdir /s /q "папка программы"

в расчёте на то, что хранилище лежит где-то отдельно. Но переносимый режим
кладёт vault.pmv ровно рядом с exe, а установщик по умолчанию предлагает тот
диск, с которого запущен, — то есть штатный сценарий сам сводит программу и
данные в одну папку. Кнопка «Удалить» в «Параметрах» стирала хранилище,
предыдущую версию и весь архив снимков, а окно удаления в этот момент
показывало надпись «Хранилище и резервные копии останутся».

Теперь удаляются ПОИМЕННО файлы программы (PROGRAM_FILES), а папка сносится
командой rmdir БЕЗ /s — она физически не способна удалить непустой каталог.
Даже если проверка ниже ошибётся, чужой файл в папке остановит удаление.
"""

import os
import subprocess
import sys
import time

from . import APP_NAME, EXE_STEM, LEGACY_NAMES, __version__
from .paths import BACKUP_DIRNAME

EXE_NAME = EXE_STEM + ".exe"
LEGACY_EXE_NAMES = tuple(name + ".exe" for name in LEGACY_NAMES)

# Всё, что кладёт в папку установщик, и ничего сверх того. Удаление вправе
# трогать только эти имена: что не клали — то не наше. Прежние имена exe
# сюда входят: это та же программа, просто под старым названием.
PROGRAM_FILES = tuple(name + suffix
                      for name in (EXE_NAME,) + LEGACY_EXE_NAMES
                      for suffix in ("", ".old", ".new")) + ("config.json",)

# Признаки пользовательских данных рядом с программой — для предупреждения в
# окне удаления. На само удаление не влияют: там работает белый список выше.
VAULT_SUFFIXES = (".pmv", ".pmv.prev", ".pmv.lock", ".pmv.att", ".pmv.tmp",
                  ".pmv.bak")

# Имя раздела реестра пользователю не показывается (в списке программ видно
# DisplayName), поэтому оно прежнее: новая версия перезаписывает старую запись,
# а не оставляет рядом вторую.
REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\PassVault"


def is_frozen():
    return getattr(sys, "frozen", False)


def self_path():
    return os.path.abspath(sys.executable if is_frozen() else __file__)


def self_dir():
    return os.path.dirname(self_path())


def system_drive():
    return os.path.splitdrive(os.environ.get("SystemRoot", "C:"))[0].upper()


def is_on_system_drive(path):
    """Ведёт ли путь на системный диск. Для предупреждения в установщике."""
    drive = os.path.splitdrive(os.path.abspath(path))[0].upper()
    return bool(drive) and drive == system_drive()


def default_install_dir():
    """Куда ставить по умолчанию.

    Если установщик запущен не с системного диска — предлагаем тот же диск:
    человек, который держит программу на D:, не хочет её на C:. Системный диск
    остаётся запасным вариантом, а поле в любом случае можно поправить руками.

    Тот же порядок работает и на уже установленной копии: рядом с существующей
    установкой найдётся и хранилище, и привычка.
    """
    here = os.path.splitdrive(self_path())[0]
    if here and here.upper() != system_drive():
        return os.path.join(here + os.sep, EXE_STEM)

    # Системный диск — последний вариант. Ищем самый большой несистемный
    # фиксированный диск: менеджеру паролей там спокойнее, а пользователю,
    # который сознательно держит данные не на C:, не приходится править путь
    # руками при каждой переустановке.
    other = _largest_non_system_drive()
    if other:
        return os.path.join(other + os.sep, EXE_STEM)

    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Programs", EXE_STEM)


def _largest_non_system_drive():
    """Буква самого просторного несистемного диска или None."""
    if os.name != "nt":
        return None
    import shutil
    import string
    best, best_free = None, 0
    for letter in string.ascii_uppercase:
        drive = "%s:" % letter
        if drive == system_drive() or not os.path.isdir(drive + os.sep):
            continue
        try:
            free = shutil.disk_usage(drive + os.sep).free
        except OSError:
            continue
        if free > best_free:
            best, best_free = drive, free
    return best


def looks_like_setup_exe():
    """Файл назван установщиком — значит, от него и ждут окна установки.

    Правило одно и без исключений: GemSwap-Setup.exe ставит, GemSwap.exe
    открывает хранилище. Двойной клик по файлу делает ровно то, что обещает имя.

    Из исходников — всегда приложение. Без этой проверки self_path() отдавал
    путь к самому этому модулю, pvault\\setup.py, слово «setup» находилось в
    имени файла, и `python passvault.py` открывал окно установщика вместо
    хранилища. Из исходников программа не запускалась вообще.
    """
    if not is_frozen():
        return False
    return "setup" in os.path.basename(self_path()).lower()


def installed_location():
    """Куда программа уже установлена, по данным реестра. None — не установлена."""
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY) as k:
            return winreg.QueryValueEx(k, "InstallLocation")[0]
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Ярлыки
# ---------------------------------------------------------------------------
def _make_shortcut(link_path, target, working_dir, description):
    r"""Ярлык через COM-интерфейс IShellLink, ВНУТРИ своего процесса.

    Раньше здесь запускался powershell с inline-скриптом:

        subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", "$s=(New-Object -ComObject WScript.Shell)..."])

    и это ломало установку целиком. Для поведенческого монитора Windows
    Defender неподписанная программа с нулевой репутацией, которая копирует
    себя в другую папку, тут же вызывает powershell с готовым скриптом, пишет
    ключ в CurrentVersion\Uninstall и запускает только что созданный файл, —
    это в точности почерк вредоносного загрузчика. Установка обрывалась с
    вердиктом Behavior:Win32/DefenseEvasion.A!ml, а файл удалялся.

    Вердикт был ложным (эвристика, не сигнатура: суффикс !ml), но спорить с
    антивирусом бессмысленно — надо не давать повода. Обращение к COM идёт
    в своём же процессе, дочерних программ не запускается, и самого приметного
    следа не остаётся.

    Ярлыки при этом получаются ровно такие же: WScript.Shell внутри так же
    дёргает IShellLink, просто через лишний слой.

    Попыток три: антивирус в режиме проверки может подержать только что
    созданный .lnk и вернуть оболочке отказ (наблюдалось прямо во время этой
    правки — E_FAIL на IPersistFile::Save то возникал, то нет на одном и том
    же коде). Ярлык — удобство, а не смысл установки, поэтому окончательный
    провал не считается провалом установки.
    """
    if os.name != "nt":
        return False
    for attempt in range(3):
        if _write_shortcut(link_path, target, working_dir, description):
            return True
        time.sleep(0.3 * (attempt + 1))
    return False


# Порядковые номера методов в таблицах COM-интерфейсов. Первые три у любого
# интерфейса — QueryInterface, AddRef, Release, дальше идут свои.
_IUNKNOWN_QUERY_INTERFACE = 0
_IUNKNOWN_RELEASE = 2
_ISHELLLINK_SET_DESCRIPTION = 7
_ISHELLLINK_SET_WORKING_DIR = 9
_ISHELLLINK_SET_ICON = 17
_ISHELLLINK_SET_PATH = 20
_IPERSISTFILE_SAVE = 6

_CLSID_SHELL_LINK = "{00021401-0000-0000-C000-000000000046}"
_IID_ISHELL_LINK_W = "{000214F9-0000-0000-C000-000000000046}"
_IID_IPERSIST_FILE = "{0000010B-0000-0000-C000-000000000046}"
_CLSCTX_INPROC_SERVER = 1


def _com_guid(text):
    """GUID из строки вида {00021401-0000-0000-C000-000000000046}."""
    import ctypes
    from ctypes import byref
    from ctypes.wintypes import BYTE, DWORD, WORD

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", DWORD), ("Data2", WORD), ("Data3", WORD),
                    ("Data4", BYTE * 8)]

    guid = GUID()
    ctypes.oledll.ole32.CLSIDFromString(text, byref(guid))
    return guid


def _com_call(obj, index, argtypes, *args):
    """Вызов метода COM-интерфейса по номеру в таблице.

    Результат объявлен как HRESULT, поэтому ctypes сам бросит исключение при
    ошибке — проверять код возврата вручную не нужно.
    """
    import ctypes
    from ctypes import POINTER, c_void_p
    vtable = ctypes.cast(obj, POINTER(POINTER(c_void_p))).contents
    return ctypes.WINFUNCTYPE(ctypes.HRESULT, c_void_p, *argtypes)(
        vtable[index])(obj, *args)


def _com_release(obj):
    """Release возвращает счётчик ссылок, а не HRESULT: прототип отдельный."""
    import ctypes
    from ctypes import POINTER, c_void_p
    vtable = ctypes.cast(obj, POINTER(POINTER(c_void_p))).contents
    ctypes.WINFUNCTYPE(ctypes.c_ulong, c_void_p)(vtable[_IUNKNOWN_RELEASE])(obj)


def _write_shortcut(link_path, target, working_dir, description):
    """Одна попытка создать ярлык. True, если файл появился."""
    import ctypes
    from ctypes import byref, c_void_p, c_wchar_p

    # oledll сам проверяет HRESULT — это нужно для методов интерфейсов. Но
    # CoUninitialize не возвращает ничего, и oledll принял бы мусор в регистре
    # за код ошибки, поэтому он вызывается через windll.
    ole32 = ctypes.oledll.ole32
    ole32_raw = ctypes.windll.ole32

    link = persist = None
    try:
        os.makedirs(os.path.dirname(link_path), exist_ok=True)
        ole32.CoInitialize(None)
        try:
            link = c_void_p()
            ole32.CoCreateInstance(byref(_com_guid(_CLSID_SHELL_LINK)), None,
                                   _CLSCTX_INPROC_SERVER,
                                   byref(_com_guid(_IID_ISHELL_LINK_W)),
                                   byref(link))

            _com_call(link, _ISHELLLINK_SET_PATH, [c_wchar_p], target)
            _com_call(link, _ISHELLLINK_SET_WORKING_DIR, [c_wchar_p], working_dir)
            _com_call(link, _ISHELLLINK_SET_DESCRIPTION, [c_wchar_p], description)
            _com_call(link, _ISHELLLINK_SET_ICON, [c_wchar_p, ctypes.c_int],
                      target, 0)

            persist = c_void_p()
            _com_call(link, _IUNKNOWN_QUERY_INTERFACE, [c_void_p, c_void_p],
                      byref(_com_guid(_IID_IPERSIST_FILE)), byref(persist))
            _com_call(persist, _IPERSISTFILE_SAVE, [c_wchar_p, ctypes.c_int],
                      link_path, True)
        finally:
            for obj in (persist, link):
                if obj:
                    _com_release(obj)
            ole32_raw.CoUninitialize()
        return os.path.isfile(link_path)
    except Exception:
        if os.environ.get("PASSVAULT_DEBUG"):
            import traceback
            traceback.print_exc()
        return False


SHORTCUT_DESCRIPTION = "Головоломка «три в ряд»"


def start_menu_link(name=APP_NAME):
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs",
                        name + ".lnk")


def desktop_link(name=APP_NAME):
    home = os.path.expanduser("~")
    for folder in ("Desktop", "Рабочий стол"):
        d = os.path.join(home, folder)
        if os.path.isdir(d):
            return os.path.join(d, name + ".lnk")
    return os.path.join(home, "Desktop", name + ".lnk")


def _remove_files(paths):
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass


def remove_legacy(target_dir, start_menu=True, desktop=True):
    """Убирает следы прежнего названия: старый exe в папке установки и ярлыки.

    Без этого обновление поверх старой версии оставляло рядом с новым значком
    прежний «PassVault» — и маскировка теряла смысл. Exe под старым именем —
    это та же программа, его место занимает новый файл; данные не трогаются.
    """
    for name in LEGACY_EXE_NAMES:
        old = os.path.join(target_dir, name)
        try:
            os.remove(old)
        except FileNotFoundError:
            pass
        except OSError:
            # Старая копия запущена: удалить нельзя, переименовать можно.
            # Файл .old уберёт следующая установка или удаление.
            try:
                os.replace(old, old + ".old")
            except OSError:
                pass
    if start_menu:
        _remove_files(start_menu_link(n) for n in LEGACY_NAMES)
    if desktop:
        _remove_files(desktop_link(n) for n in LEGACY_NAMES)


# ---------------------------------------------------------------------------
# Установка
# ---------------------------------------------------------------------------
def install(target_dir=None, desktop_shortcut=True, start_menu=True,
            register=True, progress=None):
    """Ставит программу. Возвращает путь к установленному exe.

    start_menu и register выключаются в тестах: автотест не должен сорить в
    меню «Пуск» и в реестре пользователя.
    """
    def say(text):
        if progress:
            progress(text)

    target_dir = os.path.abspath(target_dir or default_install_dir())
    target_exe = os.path.join(target_dir, EXE_NAME)
    source = self_path()

    if os.path.normcase(source) == os.path.normcase(target_exe):
        raise OSError("Программа уже запущена из папки установки")

    say("Создаю папку " + target_dir)
    os.makedirs(target_dir, exist_ok=True)

    say("Копирую программу")
    import shutil
    tmp = target_exe + ".new"
    shutil.copy2(source, tmp)
    try:
        os.replace(tmp, target_exe)
    except OSError:
        # Файл занят: старая копия запущена. Переносим её в сторону и повторяем —
        # Windows позволяет переименовать работающий exe, но не перезаписать.
        old = target_exe + ".old"
        try:
            os.remove(old)
        except OSError:
            pass
        os.replace(target_exe, old)
        os.replace(tmp, target_exe)

    if start_menu or desktop_shortcut:
        say("Создаю ярлыки")
        if start_menu:
            _make_shortcut(start_menu_link(), target_exe, target_dir,
                           SHORTCUT_DESCRIPTION)
        if desktop_shortcut:
            _make_shortcut(desktop_link(), target_exe, target_dir,
                           SHORTCUT_DESCRIPTION)

    remove_legacy(target_dir, start_menu=start_menu, desktop=desktop_shortcut)

    if register:
        say("Регистрирую в списке программ")
        _register(target_dir, target_exe)

    # Отодвинутая при обновлении копия больше не нужна и оставалась в папке
    # навсегда: снести её можно только когда прежний процесс уже завершился,
    # то есть при следующем запуске установщика — вот он и есть.
    _remove_files(os.path.join(target_dir, name + ".old")
                  for name in (EXE_NAME,) + LEGACY_EXE_NAMES)

    say("Готово")
    return target_exe


def _register(target_dir, target_exe):
    if os.name != "nt":
        return
    try:
        import winreg
        size_kb = 0
        for root, _dirs, files in os.walk(target_dir):
            for name in files:
                try:
                    size_kb += os.path.getsize(os.path.join(root, name)) // 1024
                except OSError:
                    pass
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_KEY) as k:
            winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, __version__)
            winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, APP_NAME)
            winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, target_dir)
            winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, target_exe)
            winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ,
                              '"%s" --uninstall' % target_exe)
            winreg.SetValueEx(k, "QuietUninstallString", 0, winreg.REG_SZ,
                              '"%s" --uninstall --quiet' % target_exe)
            winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "EstimatedSize", 0, winreg.REG_DWORD, size_kb)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Удаление
# ---------------------------------------------------------------------------
def foreign_files_in(directory):
    """Всё, что лежит в папке программы и программе не принадлежит.

    Список — для предупреждения пользователю. На удаление он не влияет: там
    работает белый список PROGRAM_FILES, а не этот чёрный.
    """
    known = {name.lower() for name in PROGRAM_FILES}
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    return sorted(n for n in names if n.lower() not in known)


def vault_files_in(directory):
    """Файлы хранилища, найденные в папке программы.

    Именно этот случай и стоил бы пользователю паролей: переносимый режим
    кладёт vault.pmv рядом с exe, а установщик по умолчанию предлагает диск,
    с которого запущен.
    """
    found = []
    for name in foreign_files_in(directory):
        low = name.lower()
        full = os.path.join(directory, name)
        if low == BACKUP_DIRNAME and os.path.isdir(full):
            found.append(name)
        elif any(low.endswith(suffix) for suffix in VAULT_SUFFIXES):
            found.append(name)
    return found


def uninstall(progress=None, shortcuts=True, register=True, defer=True):
    """Снимает регистрацию и ярлыки, затем удаляет файлы программы.

    Возвращает (папка, что_осталось). Второй элемент непуст, если рядом с
    программой лежали чужие файлы — тогда папка НЕ удаляется.

    shortcuts, register и defer выключаются в тестах: автотест не имеет права
    сносить настоящий ярлык в меню «Пуск» и настоящую запись в реестре, а
    отложенное удаление отдельным процессом невозможно проверить.

    Свой собственный exe удалить на месте нельзя, поэтому при defer=True
    уборка поручается процессу, который дожидается нашего выхода.
    """
    def say(text):
        if progress:
            progress(text)

    target_dir = self_dir()
    kept = foreign_files_in(target_dir)

    if shortcuts:
        say("Убираю ярлыки")
        for name in (APP_NAME,) + LEGACY_NAMES:
            _remove_files((start_menu_link(name), desktop_link(name)))

    if register:
        say("Снимаю регистрацию")
        if os.name == "nt":
            try:
                import winreg
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_KEY)
            except OSError:
                pass

    say("Удаляю файлы программы")
    if defer:
        _schedule_program_removal(target_dir)
    else:
        remove_program_files(target_dir)
    return target_dir, kept


def remove_program_files(target_dir):
    """Удаляет файлы программы, не трогая ничего чужого. Для тестов и не-Windows.

    Возвращает True, если папка после этого исчезла. Папка сносится только
    пустой: rmdir без /s физически не может удалить непустой каталог, и это
    последний рубеж на случай ошибки в проверках выше.
    """
    for name in PROGRAM_FILES:
        try:
            os.remove(os.path.join(target_dir, name))
        except OSError:
            pass
    try:
        os.rmdir(target_dir)
        return True
    except OSError:
        return False


def removal_command(target_dir):
    """Команда отложенного удаления для Windows.

    Вынесена отдельно, чтобы её проверял тест. Строку `rmdir /s /q` очень
    легко вернуть сюда по невнимательности — «так же короче», — а цена этой
    правке ровно одна: хранилище пользователя.

    Удаляются ТОЛЬКО файлы из PROGRAM_FILES, поимённо. Завершающий rmdir идёт
    БЕЗ ключа /s: он снесёт папку, если та опустела, и откажется, если внутри
    осталось хоть что-то чужое.
    """
    steps = ["ping 127.0.0.1 -n 4 > nul"]
    steps += ['del /f /q "%s"' % os.path.join(target_dir, name)
              for name in PROGRAM_FILES]
    steps.append('rmdir "%s"' % target_dir)          # без /s — только пустую
    return " & ".join(steps)


def _schedule_program_removal(target_dir):
    """Отложенное удаление: ждём, пока наш процесс завершится."""
    if os.name != "nt":
        remove_program_files(target_dir)
        return
    try:
        subprocess.Popen(["cmd", "/c", removal_command(target_dir)],
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                         | getattr(subprocess, "DETACHED_PROCESS", 0))
    except Exception:
        pass
