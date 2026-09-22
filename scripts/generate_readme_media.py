"""Render the custom raster assets used by the README.

The SVG tables and diagrams in ``assets/`` are deliberately hand-authored. This
script produces the two raster assets that benefit from animation or social-card
dimensions, and verifies every text bounding box before it writes a file.
"""

from pathlib import Path
import random

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
W, H = 1200, 630
PAPER = "#f5f1e8"
INK = "#171612"
MUTED = "#716d65"
LINE = "#c8c1b3"
ORANGE = "#f25c19"
SAGE = "#9ab59d"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


def textured_paper() -> Image.Image:
    """A restrained paper grain—texture, not decorative illustration."""
    image = Image.new("RGB", (W, H), PAPER)
    px = image.load()
    noise = random.Random(256)
    for y in range(H):
        for x in range(W):
            grain = noise.randrange(-5, 6)
            px[x, y] = (245 + grain, 241 + grain, 232 + grain)
    return image


def checked_text(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str,
                 typeface: ImageFont.FreeTypeFont, fill: str,
                 bounds: tuple[int, int, int, int]) -> None:
    """Draw text only after proving it fits its designated safe area."""
    box = draw.textbbox(xy, text, font=typeface)
    left, top, right, bottom = bounds
    assert left <= box[0] and top <= box[1] and box[2] <= right and box[3] <= bottom, (
        f"Text out of bounds: {text!r} has {box}, expected inside {bounds}"
    )
    draw.text(xy, text, fill=fill, font=typeface)


def gate(draw: ImageDraw.ImageDraw, x: int, y: int, width: int, height: int) -> None:
    """The quiet boundary motif used across the preview and animated diagram."""
    draw.rounded_rectangle((x, y, x + width, y + height), radius=width // 2, fill=INK)
    inset = 18
    draw.rounded_rectangle(
        (x + inset, y + inset, x + width - inset, y + height + width // 3),
        radius=max(8, (width - inset * 2) // 2),
        fill=PAPER,
    )
    draw.rectangle((x + width // 2 - 8, y + 55, x + width // 2 + 8, y + height - 10), fill=ORANGE)


def social_preview() -> None:
    image = textured_paper()
    draw = ImageDraw.Draw(image)
    draw.line((66, 78, 543, 78), fill=LINE, width=2)
    draw.rectangle((66, 99, 78, 132), fill=ORANGE)
    checked_text(draw, (98, 100), "PRIVACY GATEWAY", font(BOLD, 27), INK, (66, 90, 600, 140))
    checked_text(draw, (66, 176), "SENSITIVE DATA", font(BOLD, 60), INK, (60, 160, 640, 240))
    checked_text(draw, (66, 249), "STAYS IN.", font(BOLD, 60), INK, (60, 230, 610, 315))
    draw.line((66, 342, 455, 342), fill=ORANGE, width=7)
    checked_text(draw, (66, 374), "LOCAL-FIRST PII BOUNDARY", font(MONO, 17), INK, (60, 360, 550, 410))
    checked_text(draw, (66, 408), "POLICY-CONTROLLED · FAIL CLOSED", font(MONO, 15), MUTED, (60, 395, 580, 445))

    gate(draw, 775, 118, 185, 395)
    for index, y in enumerate((190, 248, 306, 364, 422)):
        draw.line((1055, y, 960, y), fill=(INK if index % 2 else ORANGE), width=4)
        draw.ellipse((1060, y - 9, 1078, y + 9), fill=INK if index % 2 else ORANGE)
        draw.line((775, y, 696, y), fill=ORANGE, width=3)
        draw.rounded_rectangle((670, y - 8, 690, y + 8), radius=3, fill=SAGE)
    checked_text(draw, (775, 548), "LOCAL TRUST BOUNDARY", font(MONO, 14), MUTED, (750, 535, 1110, 580))
    image.save(ASSETS / "privacy-gateway-social-preview.png", optimize=True)


def boundary_frame(stage: int) -> Image.Image:
    image = textured_paper()
    draw = ImageDraw.Draw(image)
    draw.line((64, 85, 1136, 85), fill=LINE, width=2)
    checked_text(draw, (64, 108), "RAW INPUT", font(MONO, 16), MUTED, (60, 98, 300, 145))
    checked_text(draw, (486, 108), "PRIVACY GATEWAY", font(MONO, 16), INK, (480, 98, 800, 145))
    checked_text(draw, (935, 108), "PROTECTED OUTPUT", font(MONO, 16), MUTED, (920, 98, 1140, 145))
    draw.line((132, 310, 468, 310), fill=INK, width=3)
    draw.line((732, 310, 1068, 310), fill=INK, width=3)
    gate(draw, 525, 178, 150, 285)
    for index, y in enumerate((256, 310, 364)):
        raw_x = 154 + index * 95
        protected_x = 825 + index * 88
        draw.ellipse((raw_x - 11, y - 11, raw_x + 11, y + 11), fill=INK)
        if stage >= 1:
            draw.line((raw_x + 14, y, 519, y), fill=ORANGE, width=4)
        if stage >= 2:
            draw.line((681, y, protected_x - 15, y), fill=ORANGE, width=4)
        if stage >= 3:
            draw.rounded_rectangle((protected_x - 12, y - 12, protected_x + 12, y + 12), radius=4, fill=SAGE)
    captions = ("inspect", "apply policy", "transform", "release protected output")
    checked_text(draw, (64, 526), captions[stage], font(BOLD, 26), INK, (60, 510, 820, 570))
    checked_text(draw, (64, 570), "Original values do not cross the boundary.", font(SANS, 17), MUTED, (60, 555, 780, 610))
    return image


def boundary_loop() -> None:
    frames = [boundary_frame(stage) for stage in range(4)]
    frames[0].save(
        ASSETS / "privacy-boundary-loop.gif",
        save_all=True,
        append_images=frames[1:],
        duration=[900, 900, 900, 1100],
        loop=0,
        optimize=False,
        disposal=2,
    )


if __name__ == "__main__":
    social_preview()
    boundary_loop()
