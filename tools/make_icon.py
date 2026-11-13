"""Draws the Cyber Caffeine tray icon: a simplified take on logo v1.3.
Usage: python tools/make_icon.py assets/tray.ico <preview.png>"""
import sys
from PIL import Image, ImageDraw

CYAN = (64, 230, 230, 255)
CYAN_DIM = (40, 170, 190, 255)
BODY = (44, 58, 68, 255)
RIM = (24, 32, 40, 255)
RED = (235, 60, 50, 255)
S = 256


def draw(size=S, tiny=False):
    """tiny=True drops detail that turns to noise at 16-20px."""
    k = size / S
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    p = lambda pts: [(x * k, y * k) for x, y in pts]
    w = max(1, round(12 * k))

    # cup body: tapered, cyan outline so it reads on dark and light taskbars
    d.polygon(p([(70, 62), (226, 62), (206, 240), (90, 240)]), fill=BODY, outline=CYAN, width=w)
    # rim + glowing coffee surface
    d.ellipse(p([(62, 36, ), (234, 92)]), fill=RIM, outline=CYAN, width=w)
    d.ellipse(p([(82, 48), (214, 80)]), fill=CYAN)
    # binary bits dripping off the left lip, fading as they fall
    drips = [(36, 96), (36, 140), (36, 184)] if tiny else \
            [(40, 92), (40, 128), (40, 164), (40, 200), (16, 112), (16, 150)]
    for i, (x, y) in enumerate(drips):
        d.rectangle(p([(x, y), (x + 16, y + 22)]), fill=CYAN if y < 130 else CYAN_DIM)
    # red alert panel on the cup
    if tiny:
        d.rectangle(p([(112, 116), (196, 184)]), fill=RED)
    else:
        d.rectangle(p([(118, 120), (190, 176)]), fill=RED)
        d.rectangle(p([(150, 130), (158, 156)]), fill=(255, 255, 255, 255))
        d.rectangle(p([(150, 162), (158, 168)]), fill=(255, 255, 255, 255))
    return img


def main(ico_path, preview_path):
    big = draw(S)
    sizes = [16, 20, 24, 32, 40, 48, 64, 256]
    frames = [draw(n * 4, tiny=n <= 20).resize((n, n), Image.LANCZOS) for n in sizes]
    frames[-1] = big
    # Pillow builds an .ico from the image it's called on and drops any size
    # bigger than it, so save from the 256px frame and attach the tuned small ones.
    big.save(ico_path, format="ICO", sizes=[(n, n) for n in sizes],
             append_images=frames[:-1])

    # preview: each size at 1:1 and scaled x6, on a dark and a light taskbar
    show = [16, 24, 32]
    cell = 32 * 6 + 20
    out = Image.new("RGBA", (cell * len(show) + 220, cell * 2), (0, 0, 0, 255))
    for row, bg in enumerate([(32, 32, 32, 255), (243, 243, 243, 255)]):
        ImageDraw.Draw(out).rectangle([0, row * cell, out.width, (row + 1) * cell], fill=bg)
        for col, n in enumerate(show):
            f = frames[sizes.index(n)]
            out.alpha_composite(f.resize((n * 6, n * 6), Image.NEAREST), (col * cell + 10, row * cell + 10))
            out.alpha_composite(f, (len(show) * cell + 20 + col * 40, row * cell + 40))
        out.alpha_composite(big.resize((96, 96), Image.LANCZOS), (len(show) * cell + 110, row * cell + 100))
    out.save(preview_path)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
