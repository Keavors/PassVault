# -*- coding: utf-8 -*-
r"""Сборка PassVault.

    python build.py

Что получается в dist\:

    PassVault\                папка с программой: PassVault.exe и _internal\
    PassVault-3.3-windows.zip та же папка архивом — её и носи на другие ПК

Установщика нет. Программа переносимая: распаковал папку куда угодно, запустил
PassVault.exe, рядом с ним лежит vault.pmv. Удаление — удалить папку.

СОБИРАЕМ --onedir, А НЕ --onefile, И ЭТО НЕ ВКУСОВЩИНА

При --onefile получается один exe, который при КАЖДОМ запуске распаковывает
около 15 МБ библиотек во временную папку (%TEMP%\_MEIxxxxx) и исполняет их
оттуда. «Программа без подписи запускает код из временной папки» — типовой
повод для эвристики антивируса, а сам загрузчик --onefile перепредставлен в
обучающих выборках, потому что им пользуется масса скриптовых зловредов.

При --onedir библиотеки просто лежат в _internal\ и никуда не копируются.
Ничего не распаковывается, ничего не исполняется из %TEMP%.

Цена решения — программа стала папкой, а не одним файлом. За это мы получаем
установку без ругани Windows Defender, и обмен того стоит: версия 3.1 ловилась
как Behavior:Win32/DefenseEvasion.A!ml и удалялась с диска.

Перед сборкой прогоняются автотесты. Если они не проходят, сборка
останавливается: собирать менеджер паролей с падающими тестами нельзя.

Ключи:
    --skip-tests   не гонять тесты (для быстрой проверки сборки)
    --clean        снести build/ и dist/ перед сборкой
    --console      оставить консоль (видно ошибки, полезно при отладке)
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from pvault import __version__            # noqa: E402

DIST = os.path.join(HERE, "dist")
BUILD = os.path.join(HERE, "build")
ICON = os.path.join(HERE, "assets", "passvault.ico")

REQUIRED = [("cryptography", "cryptography"),
            ("argon2", "argon2-cffi"),
            ("PyInstaller", "pyinstaller")]


def say(text):
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"), flush=True)


def ensure_deps():
    missing = []
    for module, package in REQUIRED:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if not missing:
        return
    say("Доустанавливаю: " + ", ".join(missing))
    subprocess.check_call([sys.executable, "-m", "pip", "install",
                           "--disable-pip-version-check"] + missing)


def run_tests():
    say("Прогоняю автотесты…")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, "passvault.py", "--test"],
                       cwd=HERE, env=env)
    if r.returncode != 0:
        say("\nТесты не прошли — сборка остановлена.\n"
            "Собирать менеджер паролей с падающими тестами нельзя.")
        sys.exit(1)


def make_icon():
    say("Рисую иконку…")
    subprocess.check_call([sys.executable, os.path.join("tools", "make_icon.py")],
                          cwd=HERE)


VERSION_TEMPLATE = """\
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=%(tuple)s, prodvers=%(tuple)s,
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('041904B0', [
        StringStruct('CompanyName', 'PassVault'),
        StringStruct('FileDescription', 'PassVault - офлайн-хранилище и генератор паролей'),
        StringStruct('FileVersion', '%(version)s'),
        StringStruct('InternalName', 'PassVault'),
        StringStruct('OriginalFilename', 'PassVault.exe'),
        StringStruct('ProductName', 'PassVault'),
        StringStruct('ProductVersion', '%(version)s')])]),
    VarFileInfo([VarStruct('Translation', [1049, 1200])])])
"""


def write_version_file():
    r"""Сведения о версии внутри exe (вкладка «Подробно» в свойствах файла).

    Не косметика. Неподписанный исполняемый файл БЕЗ сведений о версии —
    один из признаков, по которым эвристики антивирусов повышают оценку
    подозрительности: у обычных программ эти поля заполнены, у наспех
    собранных зловредов — нет. Само по себе это не спасает, но убирает ещё
    один повод.
    """
    parts = [int(x) for x in __version__.split(".")] + [0, 0, 0, 0]
    path = os.path.join(BUILD, "version_info.txt")
    os.makedirs(BUILD, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(VERSION_TEMPLATE % {"tuple": tuple(parts[:4]),
                                    "version": ".".join(str(p) for p in parts[:4])})
    return path


def clean():
    for d in (BUILD, DIST):
        shutil.rmtree(d, ignore_errors=True)
    spec = os.path.join(HERE, "PassVault.spec")
    if os.path.isfile(spec):
        os.remove(spec)


def build_exe(console=False):
    say("Собираю exe (это займёт минуту)…")
    args = [
        sys.executable, "-m", "PyInstaller",
        # --onedir, а не --onefile: см. пояснение в начале файла. Ничего не
        # распаковывается в %TEMP% и не исполняется оттуда.
        "--noconfirm", "--clean", "--onedir",
        "--name", "PassVault",
        "--icon", ICON,
        "--version-file", write_version_file(),
        "--distpath", DIST,
        "--workpath", BUILD,
        "--specpath", BUILD,
        # argon2-cffi тянет нативную библиотеку — без явного сбора PyInstaller
        # её не находит, и PMVAULT2 в собранном exe молча не открывается.
        "--collect-all", "argon2",
        "--hidden-import", "argon2.low_level",
        "--hidden-import", "_cffi_backend",
        # Тесты в бинарник не кладём, но и не ломаем импорт unittest.
        "--exclude-module", "pytest",
        "--exclude-module", "numpy",
        "--exclude-module", "PIL",
        # UPX намеренно отключён: сжатый неподписанный exe регулярно ловит
        # ложные срабатывания антивирусов, а менеджеру паролей это ни к чему.
        "--noupx",
    ]
    args += ["--console"] if console else ["--windowed"]
    args += [os.path.join(HERE, "passvault.py")]
    subprocess.check_call(args, cwd=HERE)


def folder_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def finish():
    app_dir = os.path.join(DIST, "PassVault")
    exe = os.path.join(app_dir, "PassVault.exe")
    if not os.path.isfile(exe):
        say("Не нашёл собранный exe — что-то пошло не так.")
        sys.exit(1)

    # Носить на другие ПК удобнее одним файлом, поэтому папка ещё и
    # упаковывается. Zip — не установщик: он ничего не делает с системой,
    # его распаковывает сам проводник Windows.
    say("Пакую архив…")
    base = os.path.join(DIST, "PassVault-%s-windows" % __version__)
    archive = shutil.make_archive(base, "zip", root_dir=DIST, base_dir="PassVault")

    say("\nГотово.\n")
    say("    %s   %.1f МБ   ← папка с программой"
        % (app_dir, folder_size(app_dir) / 1024 / 1024))
    say("    %s   %.1f МБ   ← архив, его и носи на другие ПК"
        % (archive, os.path.getsize(archive) / 1024 / 1024))
    say("\nУстановки нет: распаковать папку куда угодно и запустить "
        "PassVault.exe.\nХранилище vault.pmv ляжет рядом с ним.")


def main():
    argv = sys.argv[1:]
    if "--clean" in argv:
        clean()
    ensure_deps()
    if "--skip-tests" not in argv:
        run_tests()
    make_icon()
    build_exe(console="--console" in argv)
    finish()


if __name__ == "__main__":
    main()
