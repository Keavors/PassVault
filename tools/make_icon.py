# -*- coding: utf-8 -*-
r"""Генератор иконки: поле «три в ряд» вместо замка.

Снаружи программа выглядит как обычная головоломка (название — APP_NAME в
pvault/__init__.py): по значку на рабочем столе или на телефоне не видно, что
внутри пароли. Иконка рисуется кодом, а не лежит картинкой, по двум причинам:
не нужен графический редактор в зависимостях сборки, и репозиторий остаётся
текстовым.

Рисунок — поле 3×3 с собранным рядом из трёх рубинов. Геометрия задана один
раз, в единицах холста адаптивной иконки Android (108×108, безопасная зона —
круг диаметром 66 в центре), и из неё получаются обе версии. Значок на
телефоне и на компьютере обязан быть один: это одна программа.

    python tools/make_icon.py
        assets/passvault.ico       иконка exe (16…256 px)
        pvault/ui/icon.py          иконка окна (PNG 64 px в base64)

    python tools/make_icon.py --android [ПАПКА_ANDROID_ПРОЕКТА]
        то же, плюс ресурсы Android-версии:
        res/drawable/ic_launcher_{background,foreground,monochrome}.xml
        res/mipmap-*dpi/ic_launcher{,_round}.png
"""

import base64
import math
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

ANDROID_PROJECT = os.environ.get("PASSVAULT_ANDROID_PROJECT",
                                 r"D:\vscode_projects\PassVaultAndroid")

# ---------------------------------------------------------------------------
# Рисунок. Все координаты — в единицах холста 108×108.
# ---------------------------------------------------------------------------
BG_TOP = (123, 75, 214)
BG_BOTTOM = (63, 31, 134)
# Какой отрезок холста по вертикали занимает градиент фона. На ПК в квадрат
# иконки попадает ровно он (см. DESKTOP_VIEW), на Android — с запасом по краям.
BG_SPAN = (24, 84)

TILE = (30, 14, 69)
WHITE = (255, 255, 255)

GEMS = {
    #            форма       основной         тень             блик
    "ruby":     ("circle",  (240, 68, 75),   (166, 30, 42),   (255, 154, 160)),
    "sapphire": ("rhombus", (61, 139, 255),  (26, 79, 176),   (168, 204, 255)),
    "emerald":  ("octagon", (51, 194, 106),  (21, 122, 60),   (155, 240, 187)),
    "topaz":    ("hexagon", (255, 197, 49),  (193, 127, 0),   (255, 233, 160)),
}

BOARD = (("sapphire", "emerald", "topaz"),
         ("ruby", "ruby", "ruby"),             # собранный ряд
         ("topaz", "sapphire", "emerald"))

CELLS = (37, 54, 71)       # центры клеток по обеим осям
TILE_HALF = 7.6
GEM_R = 6.6

# Многоугольники в долях радиуса камня, центр в нуле.
POLYGONS = {
    "rhombus": [(0, -1), (0.86, 0), (0, 1), (-0.86, 0)],
    "octagon": [(-0.5, -0.84), (0.5, -0.84), (0.84, -0.5), (0.84, 0.5),
                (0.5, 0.84), (-0.5, 0.84), (-0.84, 0.5), (-0.84, -0.5)],
    "hexagon": [(0, -1), (0.87, -0.5), (0.87, 0.5), (0, 1),
                (-0.87, 0.5), (-0.87, -0.5)],
}

# Какая часть холста видна в растровой иконке: на ПК — квадрат вокруг поля,
# в круглой иконке Android — с запасом, чтобы углы поля не срезал круг.
DESKTOP_VIEW = (24, 84)
ROUND_VIEW = (16, 92)


def gem_shape(kind, cx, cy, r):
    """Контур камня: ("circle", cx, cy, r) или ("poly", [(x, y), ...])."""
    if kind == "circle":
        return ("circle", cx, cy, r * 0.9)
    return ("poly", [(cx + x * r, cy + y * r) for x, y in POLYGONS[kind]])


def foreground_layers():
    """(фигура, цвет, непрозрачность) в порядке рисования поверх фона."""
    layers = []
    for cy in CELLS:
        for cx in CELLS:
            layers.append((("rrect", cx - TILE_HALF, cy - TILE_HALF,
                            cx + TILE_HALF, cy + TILE_HALF, 2.4), TILE, 0.35))

    # Подсветка собранного ряда.
    mid = CELLS[1]
    layers.append((("rrect", CELLS[0] - 8.8, mid - 8.2, CELLS[2] + 8.8, mid + 8.2,
                    5.0), WHITE, 0.16))

    for row, names in enumerate(BOARD):
        for col, name in enumerate(names):
            kind, main, dark, light = GEMS[name]
            cx, cy = CELLS[col], CELLS[row]
            layers.append((gem_shape(kind, cx, cy, GEM_R), dark, 1.0))
            layers.append((gem_shape(kind, cx - 0.3, cy - 0.3, GEM_R * 0.84), main, 1.0))
            layers.append((gem_shape(kind, cx - 0.9, cy - 1.0, GEM_R * 0.46), light, 1.0))
            layers.append((("circle", cx - 2.1, cy - 2.5, 0.95), WHITE, 0.9))
    return layers


def monochrome_layers():
    """Силуэты камней — для тематических значков Android 13+."""
    return [(gem_shape(GEMS[name][0], CELLS[col], CELLS[row], GEM_R), WHITE, 1.0)
            for row, names in enumerate(BOARD) for col, name in enumerate(names)]


# ---------------------------------------------------------------------------
# Растр
# ---------------------------------------------------------------------------
def blend(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


class Raster:
    """RGBA-холст n×n. Каждый пиксель либо внутри фигуры, либо снаружи;
    сглаживание получается позже, при уменьшении (рисуем с запасом)."""

    def __init__(self, n, view):
        self.n = n
        self.u0 = view[0]
        self.scale = n / (view[1] - view[0])
        self.ch = [bytearray(n * n) for _ in range(4)]

    def to_px(self, u):
        return (u - self.u0) * self.scale

    def put(self, x, y, color, alpha):
        i = y * self.n + x
        r, g, b, a = self.ch
        if alpha >= 1.0:
            r[i], g[i], b[i] = int(color[0]), int(color[1]), int(color[2])
            a[i] = 255
            return
        da = a[i] / 255.0
        oa = alpha + da * (1.0 - alpha)
        k = da * (1.0 - alpha)
        r[i] = int(round((color[0] * alpha + r[i] * k) / oa))
        g[i] = int(round((color[1] * alpha + g[i] * k) / oa))
        b[i] = int(round((color[2] * alpha + b[i] * k) / oa))
        a[i] = int(round(oa * 255))

    def _span(self, lo, hi):
        return range(max(0, int(math.floor(lo))), min(self.n, int(math.ceil(hi)) + 1))

    def fill(self, shape, color, alpha=1.0):
        kind = shape[0]
        if kind == "circle":
            cx, cy, r = (self.to_px(shape[1]), self.to_px(shape[2]),
                         shape[3] * self.scale)
            r2 = r * r
            for y in self._span(cy - r, cy + r):
                dy = y + 0.5 - cy
                for x in self._span(cx - r, cx + r):
                    dx = x + 0.5 - cx
                    if dx * dx + dy * dy <= r2:
                        self.put(x, y, color, alpha)
        elif kind == "poly":
            pts = [(self.to_px(x), self.to_px(y)) for x, y in shape[1]]
            edges = [(pts[i], pts[(i + 1) % len(pts)]) for i in range(len(pts))]
            xs, ys = [p[0] for p in pts], [p[1] for p in pts]
            for y in self._span(min(ys), max(ys)):
                py = y + 0.5
                for x in self._span(min(xs), max(xs)):
                    px = x + 0.5
                    # Многоугольники выпуклые: точка внутри, если она по одну
                    # сторону от всех рёбер.
                    pos = neg = False
                    for (x0, y0), (x1, y1) in edges:
                        c = (x1 - x0) * (py - y0) - (y1 - y0) * (px - x0)
                        if c > 0:
                            pos = True
                        elif c < 0:
                            neg = True
                    if not (pos and neg):
                        self.put(x, y, color, alpha)
        elif kind == "rrect":
            x0, y0, x1, y1 = (self.to_px(v) for v in shape[1:5])
            self._rrect(x0, y0, x1, y1, shape[5] * self.scale,
                        lambda _y: color, alpha)
        else:
            raise ValueError(kind)

    def _rrect(self, x0, y0, x1, y1, rad, color_at, alpha):
        for y in self._span(y0, y1):
            py = y + 0.5
            if not y0 <= py <= y1:
                continue
            color = color_at(py)
            dy = max(y0 + rad - py, 0, py - (y1 - rad))
            for x in self._span(x0, x1):
                px = x + 0.5
                if not x0 <= px <= x1:
                    continue
                dx = max(x0 + rad - px, 0, px - (x1 - rad))
                if dx * dx + dy * dy <= rad * rad:
                    self.put(x, y, color, alpha)

    def background(self, shape):
        """Фон с вертикальным градиентом: скруглённый квадрат или круг."""
        top, bottom = self.to_px(BG_SPAN[0]), self.to_px(BG_SPAN[1])

        def color_at(py):
            t = min(1.0, max(0.0, (py - top) / (bottom - top)))
            return blend(BG_TOP, BG_BOTTOM, t)

        n = self.n
        if shape == "circle":
            self._rrect(0, 0, n, n, n / 2, color_at, 1.0)
        else:
            self._rrect(0, 0, n, n, n * 48 / 256, color_at, 1.0)

    def png(self, size):
        """PNG size×size, уменьшение усреднением с учётом прозрачности."""
        step = self.n / size
        r, g, b, a = self.ch
        n = self.n
        rows = []
        for y in range(size):
            row = bytearray([0])
            ys = range(int(y * step), max(int(y * step) + 1, int((y + 1) * step)))
            for x in range(size):
                xs = range(int(x * step), max(int(x * step) + 1, int((x + 1) * step)))
                sr = sg = sb = sa = 0
                cnt = 0
                for sy in ys:
                    base = sy * n
                    for sx in xs:
                        i = base + sx
                        w = a[i]
                        sr += r[i] * w
                        sg += g[i] * w
                        sb += b[i] * w
                        sa += w
                        cnt += 1
                if sa:
                    row += bytes((sr // sa, sg // sa, sb // sa, sa // cnt))
                else:
                    row += b"\0\0\0\0"
            rows.append(bytes(row))
        return encode_png(size, b"".join(rows))


def encode_png(size, raw):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def render(n, view, bg_shape):
    canvas = Raster(n, view)
    canvas.background(bg_shape)
    for shape, color, alpha in foreground_layers():
        canvas.fill(shape, color, alpha)
    return canvas


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


# ---------------------------------------------------------------------------
# Вектор для Android
# ---------------------------------------------------------------------------
def _num(v):
    return ("%.2f" % v).rstrip("0").rstrip(".")


def path_data(shape):
    kind = shape[0]
    if kind == "circle":
        cx, cy, r = shape[1:4]
        return ("M%s,%s a%s,%s 0 1,0 %s,0 a%s,%s 0 1,0 %s,0 z"
                % (_num(cx - r), _num(cy), _num(r), _num(r), _num(2 * r),
                   _num(r), _num(r), _num(-2 * r)))
    if kind == "poly":
        pts = shape[1]
        return ("M" + " L".join("%s,%s" % (_num(x), _num(y)) for x, y in pts)
                + " z")
    if kind == "rrect":
        x0, y0, x1, y1, r = shape[1:6]
        arc = "A%s,%s 0 0 1 " % (_num(r), _num(r))
        return ("M%s,%s H%s %s%s,%s V%s %s%s,%s H%s %s%s,%s V%s %s%s,%s z"
                % (_num(x0 + r), _num(y0), _num(x1 - r), arc, _num(x1), _num(y0 + r),
                   _num(y1 - r), arc, _num(x1 - r), _num(y1), _num(x0 + r),
                   arc, _num(x0), _num(y1 - r), _num(y0 + r), arc, _num(x0 + r),
                   _num(y0)))
    raise ValueError(kind)


def _hex(color):
    return "#%02X%02X%02X" % tuple(int(c) for c in color)


VECTOR_HEAD = """<?xml version="1.0" encoding="utf-8"?>
<!-- %s
     Сгенерировано tools/make_icon.py из ПК-версии PassVault — не править руками:
     значок на телефоне и на компьютере обязан быть один. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"%s
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
"""


def vector_xml(comment, layers):
    out = [VECTOR_HEAD % (comment, "")]
    for shape, color, alpha in layers:
        out.append('\n    <path\n        android:pathData="%s"\n'
                   '        android:fillColor="%s"' % (path_data(shape), _hex(color)))
        if alpha < 1.0:
            out.append('\n        android:fillAlpha="%s"' % _num(alpha))
        out.append(" />\n")
    out.append("</vector>\n")
    return "".join(out)


def background_xml():
    return (VECTOR_HEAD % ("Фон иконки: фиолетовый градиент.",
                           '\n    xmlns:aapt="http://schemas.android.com/aapt"')
            + """
    <path android:pathData="M0,0h108v108h-108z">
        <aapt:attr name="android:fillColor">
            <gradient
                android:type="linear"
                android:startX="54"
                android:startY="%s"
                android:endX="54"
                android:endY="%s"
                android:startColor="#FF%s"
                android:endColor="#FF%s" />
        </aapt:attr>
    </path>
</vector>
""" % (BG_SPAN[0], BG_SPAN[1], _hex(BG_TOP)[1:], _hex(BG_BOTTOM)[1:]))


# Размеры растровой иконки по плотностям экрана (48 dp).
MIPMAPS = (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144),
           ("xxxhdpi", 192))


def write_android(project):
    res = os.path.join(project, "app", "src", "main", "res")
    if not os.path.isdir(res):
        raise SystemExit("Не нашёл Android-проект: %s" % res)

    drawable = os.path.join(res, "drawable")
    files = {
        "ic_launcher_background.xml": background_xml(),
        "ic_launcher_foreground.xml": vector_xml(
            "Поле «три в ряд» 3×3. Безопасная зона адаптивной иконки — круг\n"
            "     диаметром 66 в центре холста; камни вписаны в неё.",
            foreground_layers()),
        "ic_launcher_monochrome.xml": vector_xml(
            "Силуэты камней для тематических значков (Android 13+):\n"
            "     система берёт только форму, цвет подставляет сама.",
            monochrome_layers()),
    }
    for name, text in files.items():
        with open(os.path.join(drawable, name), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write(text)

    square = render(2 * MIPMAPS[-1][1], DESKTOP_VIEW, "rounded")
    round_ = render(2 * MIPMAPS[-1][1], ROUND_VIEW, "circle")
    for density, size in MIPMAPS:
        folder = os.path.join(res, "mipmap-" + density)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "ic_launcher.png"), "wb") as f:
            f.write(square.png(size))
        with open(os.path.join(folder, "ic_launcher_round.png"), "wb") as f:
            f.write(round_.png(size))
    return res


def main(argv):
    canvas = render(512, DESKTOP_VIEW, "rounded")

    assets = os.path.join(HERE, "assets")
    os.makedirs(assets, exist_ok=True)

    images = [(s, canvas.png(s)) for s in (16, 24, 32, 48, 64, 128, 256)]
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

    if "--android" in argv:
        rest = argv[argv.index("--android") + 1:]
        project = rest[0] if rest and not rest[0].startswith("-") else ANDROID_PROJECT
        print("готово:", write_android(project))


if __name__ == "__main__":
    main(sys.argv[1:])
