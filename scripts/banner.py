"""1280x400 black-and-white banner: pixel blackletter name, mono tagline, dithered Dürer plates at the edges."""
from PIL import Image, ImageDraw, ImageFont, ImageOps

W, H = 1280, 400
FONT = "docs/art/UnifrakturMaguntia-Book.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def plate(path, box, side, mirror=False):
    im = Image.open(path).convert("L").crop(box).resize((360, H), Image.LANCZOS)
    if mirror:
        im = ImageOps.mirror(im)
    im = ImageOps.autocontrast(im, cutoff=1)
    px = im.load()
    for x in range(im.width):  # fade toward the centre so the plate dissolves into the black
        f = (1 - x / im.width) if side == "l" else x / im.width
        f = min(1.0, max(0.0, f * 1.5 - 0.1)) ** 1.6
        for y in range(H):
            g = min(1.0, y / 30, (H - 1 - y) / 30)
            px[x, y] = int((255 - px[x, y]) * f * g * 0.85)  # engravings are black on paper: invert
    return im.convert("1", dither=Image.FLOYDSTEINBERG).convert("L")


img = Image.new("L", (W, H), 0)
img.paste(plate("docs/art/durer_st_michael.jpg", (120, 300, 1160, 1456), "l"), (0, 0))
img.paste(plate("docs/art/durer_st_jerome.jpg", (380, 280, 1240, 1236), "r"), (W - 360, 0))
small = Image.new("L", (300, 60), 0)  # render tiny, upscale nearest: pixel blackletter
ImageDraw.Draw(small).text((150, 30), "mcp–audit", font=ImageFont.truetype(FONT, 44), fill=255, anchor="mm")
small = small.point(lambda v: 255 if v > 110 else 0).resize((900, 180), Image.NEAREST)
img.paste(235, (190, 70), small)
d = ImageDraw.Draw(img)
mono = ImageFont.truetype(MONO, 22)
for i, line in enumerate(["read the tool before your agent does", "tool poisoning · rug-pulls · SARIF"]):
    d.text((W // 2, 268 + 34 * i), line, font=mono, fill=170, anchor="mm")
img.save("docs/screenshots/banner.png", optimize=True)
