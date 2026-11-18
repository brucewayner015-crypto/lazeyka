"""Draws the Лазейка icons: two fence pickets with a path slipping through the gap."""
import math, os, sys
from PIL import Image, ImageDraw

OUT = sys.argv[1]
SPRUCE = (23, 49, 44, 255)
BIRCH = (228, 236, 233, 255)

def bezier(p0, p1, p2, p3, n=80):
    pts = []
    for i in range(n + 1):
        t = i / n
        x = (1-t)**3*p0[0] + 3*(1-t)**2*t*p1[0] + 3*(1-t)*t**2*p2[0] + t**3*p3[0]
        y = (1-t)**3*p0[1] + 3*(1-t)**2*t*p1[1] + 3*(1-t)*t**2*p2[1] + t**3*p3[1]
        pts.append((x, y))
    return pts

def draw(path_color, bg=SPRUCE, size=256, bar=BIRCH):
    s = 4 * size  # supersample
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    k = s / 32.0
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(7 * k), fill=bg)
    d.rounded_rectangle([6.5 * k, 5 * k, 12 * k, 27 * k], radius=int(1.6 * k), fill=bar)
    d.rounded_rectangle([20 * k, 5 * k, 25.5 * k, 27 * k], radius=int(1.6 * k), fill=bar)
    pts = bezier((3 * k, 23 * k), (10.5 * k, 23 * k), (13 * k, 10.5 * k), (29 * k, 9.5 * k), n=1200)
    r = 2.1 * k
    for (x, y) in pts:  # stamp discs for a smooth round-capped stroke
        d.ellipse([x - r, y - r, x + r, y + r], fill=path_color)
    return im.resize((size, size), Image.LANCZOS)

def save_ico(name, path_color, bg=SPRUCE, bar=BIRCH):
    base = draw(path_color, bg, 256, bar)
    sizes = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)]
    base.save(f"{OUT}/{name}", format="ICO", sizes=sizes)

save_ico("lazeyka.ico", (217, 139, 28, 255))
save_ico("tray-on.ico", (240, 160, 40, 255))
save_ico("tray-off.ico", (150, 162, 159, 255), bg=(70, 84, 81, 255), bar=(200, 208, 205, 255))
save_ico("tray-busy.ico", (98, 200, 216, 255))
save_ico("tray-err.ico", (236, 84, 72, 255))
if os.environ.get("PREVIEW"):  # optional 256 px preview, kept out of the embedded assets
    draw((217, 139, 28, 255), size=256).save(os.environ["PREVIEW"])
print("ok")
