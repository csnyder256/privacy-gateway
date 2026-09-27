"""Render the custom raster assets used by the README.

The SVG tables and diagrams in ``assets/`` are deliberately hand-authored. This
script produces the two raster assets that benefit from animation or social-card
dimensions, and verifies every text bounding box before it writes a file.

It needs Pillow and the DejaVu fonts; set README_MEDIA_FONTS to their directory
when they are not in the Debian location.
"""

import math
import os
import random
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
W, H = 1200, 630
PAPER = "#f5f1e8"
INK = "#171612"
MUTED = "#716d65"
LINE = "#c8c1b3"
ORANGE = "#f25c19"
SAGE = "#9ab59d"
FONTS = Path(os.environ.get("README_MEDIA_FONTS", "/usr/share/fonts/truetype/dejavu"))
SANS = str(FONTS / "DejaVuSans.ttf")
BOLD = str(FONTS / "DejaVuSans-Bold.ttf")
MONO = str(FONTS / "DejaVuSansMono.ttf")
MONO_BOLD = str(FONTS / "DejaVuSansMono-Bold.ttf")


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


def checked_text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text: str,
    typeface: ImageFont.FreeTypeFont,
    fill: str,
    bounds: tuple[int, int, int, int],
) -> None:
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
    checked_text(
        draw, (66, 374), "LOCAL-FIRST PII BOUNDARY", font(MONO, 17), INK, (60, 360, 550, 410)
    )
    checked_text(
        draw,
        (66, 408),
        "POLICY-CONTROLLED · FAIL CLOSED",
        font(MONO, 15),
        MUTED,
        (60, 395, 580, 445),
    )

    gate(draw, 775, 118, 185, 395)
    for index, y in enumerate((190, 248, 306, 364, 422)):
        draw.line((1055, y, 960, y), fill=(INK if index % 2 else ORANGE), width=4)
        draw.ellipse((1060, y - 9, 1078, y + 9), fill=INK if index % 2 else ORANGE)
        draw.line((775, y, 696, y), fill=ORANGE, width=3)
        draw.rounded_rectangle((670, y - 8, 690, y + 8), radius=3, fill=SAGE)
    checked_text(
        draw, (775, 548), "LOCAL TRUST BOUNDARY", font(MONO, 14), MUTED, (750, 535, 1110, 580)
    )
    image.save(ASSETS / "privacy-gateway-social-preview.png", optimize=True)


# Animated boundary loop.
#
# Chips ride three lanes through the gate. A detected raw value squeezes into an ink dot,
# crosses the orange policy bar and unrolls on the far side as the protected output. Each
# frame is a pure function of its index modulo LOOP_FRAMES, and every position is integer
# arithmetic, so the last frame steps into the first exactly like any other pair of frames.

SS = 2  # draw at 2x and downsample once per frame, for anti-aliased motion
LOOP_FPS = 20
LOOP_FRAMES = 160  # 8 s
STEP = 5  # px each chip advances per frame (100 px/s)
SPACING = STEP * LOOP_FRAMES // 2  # two chips per lane per loop
LANES = (238, 318, 398)
LANE_OFFSETS = (0, 133, 267)  # staggered, so the gate takes a chip every ~1.3 s
GATE_X, GATE_Y, GATE_W, GATE_H = 525, 150, 150, 320
BAR_X = GATE_X + GATE_W // 2
CHIP_H, DOT = 40, 22
# Where a chip's leading edge is when each phase of its trip happens.
DETECT = (300, 345)  # the detector tag appears
COLLAPSE = (420, 512)  # the raw chip squeezes into a dot before the gate
EXPAND = (697, 755)  # the protected chip unrolls once the dot clears the gate
FADE_IN, FADE_OUT = (30, 100), (1100, 1170)  # chips enter and leave around the margins
CHIP_TEXT = (MONO, 16)
TAG_TEXT = (MONO_BOLD, 14)
LABEL_TEXT = (MONO_BOLD, 15)


@dataclass(frozen=True)
class Chip:
    entity: str
    raw: str
    action: str
    protected: str


# The engine's output for each value under the named action. The regex detector finds every
# value at 0.99 confidence; the keyed hash and the token are truncated to fit.
CHIPS = (
    (
        Chip("EMAIL_ADDRESS", "ana@example.com", "label", "<EMAIL_ADDRESS>"),
        Chip("IP_ADDRESS", "10.0.4.17", "hash", "sha256:c2ce1bd4…"),
    ),
    (
        Chip("PHONE_NUMBER", "415-555-0142", "synthetic", "+1-202-555-9319"),
        Chip("US_SSN", "123-45-6789", "redact", "[REDACTED:US_SSN]"),
    ),
    (
        Chip("CREDIT_CARD", "4111 1111 1111 1111", "tokenize", "[[PG1|CREDIT_CARD|…]]"),
        Chip("DATE_TIME", "2026-03-14", "generalize", "2026"),
    ),
)


def ss(value: float) -> int:
    """Layout units to supersampled pixels."""
    return round(value * SS)


@cache
def font_ss(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size * SS)


def ease(x: float, span: tuple[float, float]) -> float:
    """0 before the span, 1 after it, smoothstep in between."""
    t = min(1.0, max(0.0, (x - span[0]) / (span[1] - span[0])))
    return t * t * (3 - 2 * t)


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def text_width(text: str, spec: tuple[str, int], tracking: float = 0) -> float:
    typeface = font_ss(*spec)
    if not tracking:
        return typeface.getlength(text)
    return sum(typeface.getlength(char) for char in text) + ss(tracking) * (len(text) - 1)


def draw_text(draw, x, y_mid, text, spec, fill, tracking: float = 0) -> None:
    """Left-aligned text centred on y_mid, letter-spaced like the SVG keys when tracking > 0."""
    typeface = font_ss(*spec)
    if not tracking:
        draw.text((x, y_mid), text, font=typeface, fill=fill, anchor="lm")
        return
    for char in text:
        draw.text((x, y_mid), char, font=typeface, fill=fill, anchor="lm")
        x += typeface.getlength(char) + ss(tracking)


def text_extent(text: str, spec: tuple[str, int]) -> tuple[float, float]:
    """Top and bottom of the text around its middle line, in layout units."""
    box = font_ss(*spec).getbbox(text, anchor="lm")
    return box[1] / SS, box[3] / SS


def checked_label(draw, x, y_mid, text, spec, fill, bounds, tracking: float = 0) -> None:
    """draw_text, only after proving the text fits its safe area (bounds in layout units)."""
    top, bottom = text_extent(text, spec)
    box = (
        x / SS,
        y_mid / SS + top,
        (x + text_width(text, spec, tracking)) / SS,
        y_mid / SS + bottom,
    )
    left, upper, right, lower = bounds
    assert left <= box[0] and upper <= box[1] and box[2] <= right and box[3] <= lower, (
        f"Text out of bounds: {text!r} has {box}, expected inside {bounds}"
    )
    draw_text(draw, x, y_mid, text, spec, fill, tracking)


@cache
def text_sprite(text: str, spec: tuple[str, int], fill: str, tracking: float = 0) -> Image.Image:
    sprite = Image.new(
        "RGBA", (math.ceil(text_width(text, spec, tracking)) + SS, ss(spec[1] * 1.8))
    )
    draw_text(ImageDraw.Draw(sprite), 0, sprite.height / 2, text, spec, fill, tracking)
    return sprite


def faded(sprite: Image.Image, alpha: float) -> Image.Image:
    if alpha >= 1:
        return sprite
    out = sprite.copy()
    out.putalpha(sprite.getchannel("A").point(lambda a: round(a * alpha)))
    return out


def chip_width(chip: Chip) -> float:
    return max(text_width(chip.raw, CHIP_TEXT), text_width(chip.protected, CHIP_TEXT)) / SS + 28


def paste(layer: Image.Image, sprite: Image.Image, x: int, y: int, clip=(None, None)) -> None:
    """Composite sprite with its top-left at (x, y), keeping only the columns inside clip."""
    left = max(0, -x, clip[0] - x if clip[0] is not None else 0)
    right = min(sprite.width, layer.width - x, clip[1] - x if clip[1] is not None else sprite.width)
    top, bottom = max(0, -y), min(sprite.height, layer.height - y)
    if right > left and bottom > top:
        layer.alpha_composite(sprite.crop((left, top, right, bottom)), (x + left, y + top))


def pill(layer, left, y_mid, width, height, radius, fill, clip) -> None:
    """A rounded rectangle given in layout units."""
    box = Image.new("RGBA", (ss(width) + 1, ss(height) + 1))
    ImageDraw.Draw(box).rounded_rectangle(
        (0, 0, ss(width), ss(height)), radius=ss(radius), fill=fill
    )
    paste(layer, box, ss(left), ss(y_mid - height / 2), clip)


def check_loop_layout() -> None:
    """Prove the choreography before rendering it: chips in a lane never touch, raw chips are
    dots before the gate and unroll only after it, and every tag stays between the lanes."""
    widest = max(chip_width(chip) for lane in CHIPS for chip in lane)
    assert widest + 40 <= SPACING, f"chips {widest:.0f} px wide would crowd a {SPACING} px lane"
    assert COLLAPSE[1] <= GATE_X, "raw chips must be dots before they reach the gate"
    assert EXPAND[0] - DOT >= GATE_X + GATE_W, "protected chips must clear the gate first"
    assert STEP * LOOP_FRAMES % (2 * SPACING) == 0, "the loop must end where it began"
    for upper_lane, y in zip((None, *LANES), LANES):
        for chip in (chip for lane in CHIPS for chip in lane):
            for text in (chip.entity, chip.action):
                top, bottom = text_extent(text, TAG_TEXT)
                mid = y - CHIP_H / 2 - 16
                ceiling = 130 if upper_lane is None else upper_lane + CHIP_H / 2 + 6
                assert mid + top >= ceiling and mid + bottom + 6 <= y - CHIP_H / 2, (
                    f"tag {text!r} on lane {y} leaves its gap between the lanes"
                )


@cache
def loop_paper() -> Image.Image:
    return textured_paper().convert("RGBA")


@cache
def gate_layer() -> Image.Image:
    """The gate() arch, supersampled, with a transparent inside that the dots pass through."""
    x, y, width, height, inset = GATE_X, GATE_Y, GATE_W, GATE_H, 18
    mask = Image.new("L", (ss(W), ss(H)))
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle(
        (ss(x), ss(y), ss(x + width), ss(y + height)), radius=ss(width / 2), fill=255
    )
    draw.rounded_rectangle(
        (ss(x + inset), ss(y + inset), ss(x + width - inset), ss(y + height + width // 3)),
        radius=ss(max(8, (width - inset * 2) // 2)),
        fill=0,
    )
    layer = Image.new("RGBA", mask.size)
    layer.paste(INK, mask=mask)
    return layer


@cache
def loop_backdrop() -> Image.Image:
    layer = Image.new("RGBA", (ss(W), ss(H)))
    draw = ImageDraw.Draw(layer)
    draw.line((ss(64), ss(85), ss(W - 64), ss(85)), fill=LINE, width=ss(2))
    label, name, key = ss(112), "PRIVACY GATEWAY", "PROTECTED OUTPUT"
    checked_label(draw, ss(64), label, "RAW INPUT", LABEL_TEXT, MUTED, (60, 98, 400, 126), 2)
    x = ss(BAR_X) - text_width(name, LABEL_TEXT, 2) / 2
    checked_label(draw, x, label, name, LABEL_TEXT, INK, (440, 98, 760, 126), 2)
    x = ss(W - 64) - text_width(key, LABEL_TEXT, 2)
    checked_label(draw, x, label, key, LABEL_TEXT, MUTED, (800, 98, 1140, 126), 2)
    for y in LANES:
        draw.line((ss(64), ss(y), ss(GATE_X - 14), ss(y)), fill=LINE, width=ss(2))
        draw.line((ss(GATE_X + GATE_W + 14), ss(y), ss(W - 64), ss(y)), fill=LINE, width=ss(2))
    name, spec = "LOCAL TRUST BOUNDARY", (MONO, 13)
    x = ss(BAR_X) - text_width(name, spec, 1.5) / 2
    checked_label(draw, x, ss(GATE_Y + GATE_H + 22), name, spec, MUTED, (470, 480, 730, 505), 1.5)
    caption = "Original values do not cross the boundary."
    checked_label(draw, ss(64), ss(549), caption, (BOLD, 24), INK, (60, 530, 760, 570))
    stages = "INSPECT → APPLY POLICY → TRANSFORM → RELEASE"
    checked_label(draw, ss(64), ss(584), stages, (MONO, 14), MUTED, (60, 572, 760, 600), 1.5)
    return layer


@cache
def loop_fade() -> Image.Image:
    """Alpha ramp that lets chips appear and leave around the 64 px margins."""
    row = Image.new("L", (ss(W), 1))
    for x in range(ss(W)):
        row.putpixel((x, 0), round(255 * ease(x / SS, FADE_IN) * (1 - ease(x / SS, FADE_OUT))))
    return row.resize((ss(W), ss(H)))


def lane_chips(frame: int):
    """(lane y, chip, leading-edge x) for every chip in view on this frame of the loop."""
    travel = STEP * (frame % LOOP_FRAMES)
    for lane, (y, offset) in enumerate(zip(LANES, LANE_OFFSETS)):
        head = offset + travel
        for k in range(math.ceil((head - W - 300) / SPACING), head // SPACING + 1):
            yield y, CHIPS[lane][k % 2], head - k * SPACING


def boundary_scene(frame: int) -> Image.Image:
    moving = Image.new("RGBA", (ss(W), ss(H)))
    raw_side, protected_side = (None, ss(BAR_X)), (ss(BAR_X), None)
    crossings = []
    for y, chip, lead in lane_chips(frame):
        full = chip_width(chip)
        # Raw side: the leading edge keeps its pace while the tail catches up into a dot.
        squeeze = ease(lead, COLLAPSE)
        width = lerp(full, DOT, squeeze)
        height, radius = lerp(CHIP_H, DOT, squeeze), lerp(6, DOT / 2, squeeze)
        pill(moving, lead - width, y, width, height, radius, INK, raw_side)
        shown = 1 - ease(lead, (COLLAPSE[0], COLLAPSE[0] + 40))
        if shown > 0:
            sprite = faded(text_sprite(chip.raw, CHIP_TEXT, PAPER), shown)
            x = ss(lead - width / 2) - sprite.width // 2
            paste(moving, sprite, x, ss(y) - sprite.height // 2, raw_side)
        shown = ease(lead, DETECT) * (1 - ease(lead, (COLLAPSE[0], COLLAPSE[0] + 50)))
        if shown > 0:
            sprite = faded(text_sprite(chip.entity, TAG_TEXT, ORANGE, 1), shown)
            rise = 6 * (1 - ease(lead, DETECT))
            tag_y = ss(y - CHIP_H / 2 - 16 + rise) - sprite.height // 2
            paste(moving, sprite, ss(lead - full), tag_y, raw_side)
        # Protected side: the trailing edge keeps its pace while the chip unrolls ahead of it.
        grow = ease(lead, EXPAND)
        tail, width = lead - DOT, lerp(DOT, full, grow)
        height, radius = lerp(DOT, CHIP_H, grow), lerp(4, 6, grow)
        pill(moving, tail, y, width, height, radius, SAGE, protected_side)
        shown = ease(lead, (EXPAND[1] - 30, EXPAND[1] + 15))
        if shown > 0:
            sprite = faded(text_sprite(chip.protected, CHIP_TEXT, INK), shown)
            x = ss(tail + width / 2) - sprite.width // 2
            paste(moving, sprite, x, ss(y) - sprite.height // 2, protected_side)
            sprite = faded(text_sprite(chip.action, TAG_TEXT, MUTED, 1), shown)
            tag_y = ss(y - CHIP_H / 2 - 16) - sprite.height // 2
            paste(moving, sprite, ss(tail), tag_y, protected_side)
        # The bar swells around each dot as it passes through.
        swell = ease(28 - abs(lead - DOT / 2 - BAR_X), (0, 28))
        if swell > 0:
            crossings.append((y, swell))
    moving.putalpha(ImageChops.multiply(moving.getchannel("A"), loop_fade()))
    image = loop_backdrop().copy()
    image.alpha_composite(moving)
    image.alpha_composite(gate_layer())
    draw = ImageDraw.Draw(image)
    bar = (ss(BAR_X - 8), ss(GATE_Y + 55), ss(BAR_X + 8), ss(GATE_Y + GATE_H - 10))
    draw.rectangle(bar, fill=ORANGE)
    for y, swell in crossings:
        half_w, half_h = 8 + 5 * swell, 14 + 4 * swell
        box = (ss(BAR_X - half_w), ss(y - half_h), ss(BAR_X + half_w), ss(y + half_h))
        draw.rounded_rectangle(box, radius=ss(3), fill=ORANGE)
    small = image.convert("RGBa").resize((W, H), Image.Resampling.LANCZOS).convert("RGBA")
    frame_image = loop_paper().copy()
    frame_image.alpha_composite(small)
    return frame_image.convert("RGB")


def loop_palette() -> list[tuple[int, int, int]]:
    """Paper grain, the README colours, and even steps between colours that meet on screen."""
    paper, ink, muted, line, orange, sage = (
        tuple(int(color[i : i + 2], 16) for i in (1, 3, 5))
        for color in (PAPER, INK, MUTED, LINE, ORANGE, SAGE)
    )
    colors = [(245 + grain, 241 + grain, 232 + grain) for grain in range(-5, 6)]
    pairs = (
        (paper, ink, 16), (paper, muted, 6), (paper, line, 3), (paper, orange, 8),
        (paper, sage, 6), (ink, sage, 10), (ink, orange, 4), (sage, orange, 4),
        (line, ink, 4), (line, sage, 3), (line, orange, 3), (muted, ink, 2),
    )  # fmt: skip
    for a, b, steps in pairs:
        for i in range(steps + 1):
            color = tuple(round(a[k] + (b[k] - a[k]) * i / steps) for k in range(3))
            if color not in colors:
                colors.append(color)
    # Pillow gives unchanged pixels the next free index, which must still fit the colour table.
    assert len(colors) < 256 and len(colors) & (len(colors) - 1), len(colors)
    return colors


def boundary_loop() -> None:
    check_loop_layout()
    palette = bytes(channel for color in loop_palette() for channel in color)
    reference = Image.new("P", (1, 1))
    reference.putpalette(palette)
    frames = [
        boundary_scene(index).quantize(palette=reference, dither=Image.Dither.NONE)
        for index in range(LOOP_FRAMES)
    ]
    frames[0].save(
        ASSETS / "privacy-boundary-loop.gif",
        save_all=True,
        append_images=frames[1:],
        duration=1000 // LOOP_FPS,
        loop=0,
        disposal=1,  # later frames carry only the pixels that change
        optimize=True,
        palette=palette,
    )


if __name__ == "__main__":
    social_preview()
    boundary_loop()
