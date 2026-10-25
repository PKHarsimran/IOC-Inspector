"""Rebuild README artwork: python tools/render_readme_animation.py.

Requires Pillow (development artwork only; not a runtime dependency).
Each GIF plays once, then rests on its final frame. PNGs are the static copies.
"""

from pathlib import Path
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets"
BACKGROUND = "#0c1525"
TEXT = "#eef4ff"
MUTED = "#a4b5cc"
ACCENT = "#5ee6c4"


@lru_cache(maxsize=16)
def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        Path("C:/Windows/Fonts") / ("segoeuib.ttf" if bold else "segoeui.ttf"),
        Path("/usr/share/fonts/truetype/dejavu") / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.truetype("DejaVuSans.ttf", size)


@lru_cache(maxsize=8)
def mono(size: int) -> ImageFont.FreeTypeFont:
    for candidate in (Path("C:/Windows/Fonts/consola.ttf"),
                      Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")):
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return font(size)


def panel(height: int) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    canvas = Image.new("RGB", (1040, height), BACKGROUND)
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((1, 1, 1038, height - 2), radius=22,
                           outline="#263a53", width=2)
    return canvas, draw


def render(progress: float) -> Image.Image:
    canvas, draw = panel(280)
    draw.text((40, 25), "IOC INSPECTOR", font=font(33, True), fill=TEXT)
    draw.text((40, 75), "Static document triage. Indicators you can act on.", font=font(18), fill=MUTED)
    draw.text((1000, 45), "PDF / OFFICE / RTF", font=font(14), fill=ACCENT, anchor="ra")

    labels = [("EXTRACT", "URLs, IPs & macros"), ("ENRICH", "Optional threat feeds"),
              ("SCORE", "Heuristic risk signals"), ("REPORT", "Five export formats")]
    for index, (label, caption) in enumerate(labels):
        left = 40 + index * 250
        done = progress >= index + 1
        active = index <= progress < index + 1
        color = ACCENT if done or active else "#344c68"
        draw.rounded_rectangle((left, 126, left + 210, 233), radius=14,
                               fill="#14243a", outline=color, width=2)
        draw.text((left + 15, 140), f"0{index + 1}", font=font(14), fill=color)
        draw.text((left + 15, 162), label, font=font(20, True), fill=TEXT)
        draw.text((left + 15, 198), caption, font=font(13), fill=MUTED)
        if index < 3:
            draw.line((left + 215, 179, left + 242, 179), fill=color, width=2)
            draw.polygon([(left + 241, 179), (left + 235, 175), (left + 235, 183)], fill=color)
        if active:
            width = max(2, int(180 * (progress - index)))
            draw.rounded_rectangle((left + 15, 222, left + 15 + width, 225), radius=1, fill=ACCENT)
    draw.text((40, 251), "ILLUSTRATED WORKFLOW", font=font(11), fill=MUTED)
    return canvas


def render_terminal(progress: float) -> Image.Image:
    canvas, draw = panel(350)
    for index, color in enumerate(("#ff817b", "#efc570", ACCENT)):
        left = 30 + index * 23
        draw.ellipse((left, 23, left + 10, 33), fill=color)
    draw.text((520, 22), "A DOCUMENT SCAN", font=font(14, True), fill=MUTED, anchor="ma")
    draw.line((20, 51, 1020, 51), fill="#263a53", width=1)

    command = "ioc-inspector --file examples/test.pdf --report"
    typed = command[:int(min(1, progress / 0.58) * len(command))]
    draw.text((36, 83), "$", font=mono(22), fill=ACCENT)
    draw.text((67, 83), typed, font=mono(22), fill=TEXT)
    if progress < 0.58:
        cursor = 67 + draw.textlength(typed, font=mono(22))
        draw.rectangle((cursor + 3, 86, cursor + 13, 108), fill=ACCENT)

    if progress >= 0.65:
        draw.text((36, 139), "examples/test.pdf: score=0  verdict=benign", font=mono(21), fill=ACCENT)
    if progress >= 0.78:
        draw.line((36, 192, 1000, 192), fill="#263a53", width=1)
        draw.text((36, 211), "REPORT FILES", font=font(12, True), fill=MUTED)
        for index, name in enumerate(("test_report.md", "test_report.json")):
            left = 36 + index * 350
            draw.rounded_rectangle((left, 239, left + 324, 285), radius=10,
                                   fill="#14243a", outline="#344c68")
            draw.text((left + 15, 250), "reports/" + name, font=mono(16), fill=TEXT)
    draw.text((36, 317), "ILLUSTRATED BENIGN SAMPLE  /  ROUTINE LOG LINES OMITTED", font=font(11), fill=MUTED)
    return canvas


def render_exports(progress: float) -> Image.Image:
    canvas, draw = panel(330)
    draw.text((40, 25), "ONE SCAN. FIVE FORMATS.", font=font(29, True), fill=TEXT)
    draw.text((40, 70), "Choose the output that fits your next step.", font=font(17), fill=MUTED)
    draw.rounded_rectangle((416, 108, 624, 144), radius=10, fill="#14243a", outline=ACCENT)
    draw.text((520, 116), "Document findings", font=font(14, True), fill=TEXT, anchor="ma")
    labels = [(".md", "MARKDOWN", "Tickets & notes"), (".json", "JSON", "Structured data"),
              (".csv", "CSV", "Spreadsheet rows"), (".jsonl", "JSONL", "One object per file"),
              (".html", "HTML", "Browser preview")]
    for index, (extension, label, caption) in enumerate(labels):
        left = 40 + index * 196
        center = left + 88
        active = index <= progress < index + 1
        done = progress >= index + 1
        color = ACCENT if active or done else "#344c68"
        draw.line([(520, 145), (520, 161), (center, 161), (center, 187)], fill=color, width=2)
        if active:
            # A small packet travels toward the selected output card.
            fraction = progress - index
            x = 520 + (center - 520) * min(1, fraction * 1.5)
            y = 161 if fraction < 2 / 3 else 161 + 26 * (fraction - 2 / 3) * 3
            draw.ellipse((x - 4, y - 4, x + 4, y + 4), fill=TEXT)
        draw.rounded_rectangle((left, 188, left + 176, 289), radius=13,
                               fill="#14243a", outline=color, width=2)
        draw.text((left + 14, 200), extension, font=mono(16), fill=color)
        draw.text((left + 14, 227), label, font=font(18, True), fill=TEXT)
        draw.text((left + 14, 259), caption, font=font(12), fill=MUTED)
    draw.text((40, 306), "SELECT WITH REPORT_FORMATS  /  ILLUSTRATED EXPORT WORKFLOW", font=font(11), fill=MUTED)
    return canvas


def save_animation(name: str, frames: list[Image.Image], frame_ms: int) -> None:
    frames[-1].save(OUTPUT / f"{name}.png")
    # Omit the GIF loop extension so each animation ends on its final frame.
    frames[0].save(OUTPUT / f"{name}.gif", save_all=True, append_images=frames[1:],
                   duration=[frame_ms] * (len(frames) - 1) + [800], optimize=True)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    save_animation("workflow", [render(index / 10) for index in range(41)], 80)
    save_animation("terminal-demo", [render_terminal(index / 50) for index in range(51)], 70)
    save_animation("report-formats", [render_exports(index / 10) for index in range(51)], 70)


if __name__ == "__main__":
    main()
