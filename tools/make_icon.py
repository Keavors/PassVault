# -*- coding: utf-8 -*-
"""Генератор иконки: assets/passvault.ico и pvault/ui/icon.py.

Иконка рисуется кодом, а не лежит картинкой, по двум причинам: не нужен
графический редактор в зависимостях сборки, и репозиторий остаётся текстовым.

Запуск:  python tools/make_icon.py
"""

import base64
import math
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

SIZE = 256

BG_TOP = (32, 78, 140)
BG_BOTTOM = (18, 46, 86)
METAL = (214, 222, 232)
METAL_DARK = (150, 165, 185)
GOLD = (240, 190, 74)
HOLE = (26, 58, 104)


def blend(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def rounded_rect(px, x0, y0, x1, y1, radius, color, alpha=255):
    for y in range(int(y0), int(y1) + 1):
        for x in range(int(x0), int(x1) + 1):
            dx = max(x0 + radius - x, 0, x - (x1 - radius))
            dy = max(y0 + radius - y, 0, y - (y1 - radius))
            if dx * dx + dy * dy <= radius * radius:
                px[y][x] = color + (alpha,)


def ring(px, cx, cy, r_outer, r_inner, color, y_max=None):
    for y in range(int(cy - r_outer), int(cy + r_outer) + 1):
        if y < 0 or y >= SIZE:
            continue
        if y_max is not None and y > y_max:
            continue
        for x in range(int(cx - r_outer), int(cx + r_outer) + 1):
            if x < 0 or x >= SIZE:
                continue
            d = math.hypot(x - cx, y - cy)
            if r_inner <= d <= r_outer:
                px[y][x] = color + (255,)


def build_pixels():
    px = [[(0, 0, 0, 0)] * SIZE for _ in range(SIZE)]

    # Фон — скруглённый квадрат с вертикальным градиентом.
    for y in range(SIZE):
        color = blend(BG_TOP, BG_BOTTOM, y / (SIZE - 1))
        for x in range(SIZE):
            dx = max(48 - x, 0, x - (SIZE - 1 - 48))
            dy = max(48 - y, 0, y - (SIZE - 1 - 48))
            # скругление радиусом 48 у квадрата 0..255
            if dx == 0 and dy == 0:
                px[y][x] = color + (255,)
            elif dx * dx + dy * dy <= 48 * 48:
                px[y][x] = color + (255,)

    # Дужка замка.
    ring(px, SIZE // 2, 104, 54, 38, METAL_DARK, y_max=104)
    ring(px, SIZE // 2, 104, 50, 42, METAL, y_max=104)
    for x in range(SIZE // 2 - 50, SIZE // 2 - 41):
        for y in range(104, 132):
            px[y][x] = METAL + (255,)
    for x in range(SIZE // 2 + 42, SIZE // 2 + 51):
        for y in range(104, 132):
            px[y][x] = METAL + (255,)

    # Корпус.
    rounded_rect(px, 56, 122, 200, 218, 22, GOLD)
    rounded_rect(px, 62, 128, 194, 212, 18, blend(GOLD, (255, 226, 140), 0.35))

    # Скважина.
    cx, cy = SIZE // 2, 160
    for y in range(cy - 20, cy + 40):
        for x in range(cx - 20, cx + 20):
            if math.hypot(x - cx, y - cy) <= 16:
                px[y][x] = HOLE + (255,)
    for y in range(cy, cy + 34):
        half = int(9 - 4 * (y - cy) / 34)
        for x in range(cx - half, cx + half + 1):
            px[y][x] = HOLE + (255,)

    return px


def write_png(px, size):
    """Кодирует пиксели в PNG, при необходимости уменьшая усреднением."""
    step = SIZE / size
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            r = g = b = a = 0.0
            n = 0
            for sy in range(int(y * step), int((y + 1) * step)):
                for sx in range(int(x * step), int((x + 1) * step)):
                    p = px[min(sy, SIZE - 1)][min(sx, SIZE - 1)]
                    r += p[0] * p[3]; g += p[1] * p[3]; b += p[2] * p[3]
                    a += p[3]; n += 1
            if a > 0:
                row += bytes([int(r / a), int(g / a), int(b / a), int(a / n)])
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))

    raw = b"".join(rows)

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def write_ico(path, images):
    """ICO с PNG внутри — Windows понимает это начиная с Vista."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                               len(data), offset)
        blobs += data
        offset += len(data)
    with open(path, "wb") as f:
        f.write(header + entries + blobs)


def main():
    px = build_pixels()

    assets = os.path.join(HERE, "assets")
    os.makedirs(assets, exist_ok=True)

    images = [(s, write_png(px, s)) for s in (16, 24, 32, 48, 64, 128, 256)]
    ico_path = os.path.join(assets, "passvault.ico")
    write_ico(ico_path, images)

    png64 = dict(images)[64]
    icon_py = os.path.join(HERE, "pvault", "ui", "icon.py")
    with open(icon_py, "w", encoding="utf-8") as f:
        f.write("# -*- coding: utf-8 -*-\n")
        f.write('"""Иконка окна. Сгенерирована tools/make_icon.py — не править руками."""\n\n')
        f.write("ICON_PNG_B64 = (\n")
        b64 = base64.b64encode(png64).decode("ascii")
        for i in range(0, len(b64), 76):
            f.write('    "%s"\n' % b64[i:i + 76])
        f.write(")\n")

    print("готово:", ico_path, "и", icon_py)


if __name__ == "__main__":
    main()
