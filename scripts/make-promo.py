# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
"""Renders Airlock's promo video from real screenshots of the demo app.

    scripts/ui-snapshots.sh <shots> onboarding install queue review apps
    python3 -I scripts/make-promo.py <shots> <output.mp4>

Every frame is composed here (background, app windows, type, highlights) and piped to ffmpeg, which also
synthesises a quiet ambient soundtrack. Nothing is downloaded; claims on screen must stay true of the app.
"""
import math
import os
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H, FPS = 1920, 1080, 30
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON = os.path.join(REPO, "App/Assets.xcassets/AppIcon.appiconset/icon_512x512@2x.png")
FONT = "/System/Library/Fonts/SFNS.ttf"
REPO_URL = "github.com/Monem-Benjeddou/Airlock"

INK = (244, 247, 247)
MUTED = (150, 172, 175)
TEAL = (43, 179, 184)
AMBER = (242, 184, 74)


# MARK: Easing and timing

def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def ease_out(x):
    x = clamp(x)
    return 1 - (1 - x) ** 3


def ease_in_out(x):
    x = clamp(x)
    return 4 * x ** 3 if x < 0.5 else 1 - (-2 * x + 2) ** 3 / 2


def ramp(t, start, length):
    """0 before `start`, 1 after `start + length`, eased between."""
    return ease_out((t - start) / length) if length > 0 else float(t >= start)


def fade(t, duration, fade_in=0.5, fade_out=0.5):
    """Scene opacity: in at the start, out at the end."""
    return min(ramp(t, 0, fade_in), 1 - ease_in_out((t - (duration - fade_out)) / fade_out))


# MARK: Type

_fonts = {}


def font(size, weight="Regular"):
    key = (size, weight)
    if key not in _fonts:
        f = ImageFont.truetype(FONT, size)
        f.set_variation_by_name(weight)
        _fonts[key] = f
    return _fonts[key]


_text_cache = {}


def text_image(text, size, weight="Regular", color=INK, tracking=0):
    """A tight RGBA image of one line of text, cached."""
    key = (text, size, weight, color, tracking)
    if key in _text_cache:
        return _text_cache[key]
    f = font(size, weight)
    if tracking:
        widths = [f.getlength(c) + tracking for c in text]
        width = int(sum(widths)) + 4
    else:
        width = int(f.getlength(text)) + 4
    ascent, descent = f.getmetrics()
    img = Image.new("RGBA", (width, ascent + descent + 4), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    if tracking:
        x = 0.0
        for c, w in zip(text, widths):
            draw.text((x, 0), c, font=f, fill=color + (255,))
            x += w
    else:
        draw.text((0, 0), text, font=f, fill=color + (255,))
    _text_cache[key] = img
    return img


def wrap(text, size, weight, width):
    f = font(size, weight)
    lines, line = [], ""
    for word in text.split():
        candidate = (line + " " + word).strip()
        if f.getlength(candidate) <= width or not line:
            line = candidate
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def with_alpha(img, alpha):
    if alpha >= 0.999:
        return img
    out = img.copy()
    out.putalpha(out.getchannel("A").point(lambda a: int(a * clamp(alpha))))
    return out


def put_text(frame, text, xy, size, weight="Regular", color=INK, alpha=1.0, rise=0.0, anchor="left", tracking=0):
    """Draws text that fades in while rising `rise` pixels."""
    if alpha <= 0.01:
        return
    img = text_image(text, size, weight, color, tracking)
    x, y = xy
    if anchor == "center":
        x -= img.width // 2
    frame.alpha_composite(with_alpha(img, alpha), (int(x), int(y + (1 - alpha) * rise)))


def put_paragraph(frame, text, xy, size, weight, color, width, alpha, rise=16, leading=1.32):
    for i, line in enumerate(wrap(text, size, weight, width)):
        put_text(frame, line, (xy[0], xy[1] + i * size * leading), size, weight, color, alpha, rise)


# MARK: Background

def make_background():
    base = Image.new("RGBA", (W, H))
    px = base.load()
    for y in range(H):
        for x in range(0, W):
            # A deep teal at the top left falling into near-black, like the icon's chamber.
            d = math.hypot((x - W * 0.25) / W, (y - H * 0.1) / H)
            k = clamp(d / 1.1)
            px[x, y] = (int(9 + 10 * (1 - k)), int(24 + 30 * (1 - k)), int(28 + 32 * (1 - k)), 255)
    return base


def make_glow(radius, color, strength):
    """A radial glow that falls to nothing well inside its square, so it never shows an edge."""
    size = radius * 2
    mask = Image.new("L", (size, size), 0)
    px = mask.load()
    for y in range(size):
        for x in range(size):
            d = math.hypot(x - radius, y - radius) / radius
            if d < 1:
                px[x, y] = int(strength * (1 - d) ** 2.2)
    glow = Image.new("RGBA", (size, size), color + (0,))
    glow.putalpha(mask)
    return glow


def make_scrim():
    """Darkens the left of the frame behind captions, so a window sliding under them never hurts legibility."""
    scrim = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    alpha = Image.new("L", (W, 1), 0)
    for x in range(W):
        alpha.putpixel((x, 0), int(235 * (1 - ease_in_out((x - 600) / 260))))
    scrim = Image.new("RGBA", (W, H), (8, 22, 26, 255))
    scrim.putalpha(alpha.resize((W, H)))
    return scrim


class Backdrop:
    def __init__(self):
        self.base = make_background()
        self.teal = make_glow(520, TEAL, 70)
        self.amber = make_glow(420, AMBER, 34)

    def frame(self, t):
        frame = self.base.copy()
        tx = int(W * 0.18 + math.sin(t * 0.21) * 160 - 520)
        ty = int(H * 0.15 + math.cos(t * 0.17) * 90 - 520)
        frame.alpha_composite(self.teal, (tx, ty))
        ax = int(W * 0.82 + math.cos(t * 0.13) * 140 - 420)
        ay = int(H * 0.86 + math.sin(t * 0.19) * 80 - 420)
        frame.alpha_composite(self.amber, (ax, ay))
        return frame


# MARK: App windows

class Shot:
    """A captured window with a soft shadow, drawn at any scale with a focus point."""

    def __init__(self, path):
        self.image = Image.open(path).convert("RGBA")
        pad = 120
        shadow = Image.new("RGBA", (self.image.width + pad * 2, self.image.height + pad * 2), (0, 0, 0, 0))
        alpha = Image.new("L", shadow.size, 0)
        alpha.paste(self.image.getchannel("A").point(lambda a: int(a * 0.62)), (pad, pad + 36))
        shadow.putalpha(alpha.filter(ImageFilter.GaussianBlur(48)))
        shadow.alpha_composite(self.image, (pad, pad))
        self.composite = shadow
        self.pad = pad

    def draw(self, frame, center, width, alpha=1.0):
        """Draws the window `width` pixels wide with its centre at `center`; returns the mapping from shot to frame."""
        scale = width / self.image.width
        size = (int(self.composite.width * scale), int(self.composite.height * scale))
        img = self.composite.resize(size, Image.Resampling.BICUBIC)
        x = int(center[0] - size[0] / 2)
        y = int(center[1] - size[1] / 2)
        frame.alpha_composite(with_alpha(img, alpha), (x, y))
        return lambda px, py: (x + (px + self.pad) * scale, y + (py + self.pad) * scale)

    def draw_focused(self, frame, focus, frame_point, width, alpha=1.0):
        """Like draw, but places the shot point `focus` at `frame_point`."""
        scale = width / self.image.width
        cx = frame_point[0] - (focus[0] - self.image.width / 2) * scale
        cy = frame_point[1] - (focus[1] - self.image.height / 2) * scale
        return self.draw(frame, (cx, cy), width, alpha)


def highlight(frame, mapping, box, alpha, color=AMBER, radius=18):
    """A glowing rounded ring around `box` (shot coordinates)."""
    if alpha <= 0.01:
        return
    x0, y0 = mapping(box[0], box[1])
    x1, y1 = mapping(box[2], box[3])
    grow = 10
    layer = Image.new("RGBA", frame.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    rect = (x0 - grow, y0 - grow, x1 + grow, y1 + grow)
    draw.rounded_rectangle(rect, radius=radius, outline=color + (int(200 * alpha),), width=10)
    glow = layer.filter(ImageFilter.GaussianBlur(14))
    frame.alpha_composite(glow)
    ring = Image.new("RGBA", frame.size, (0, 0, 0, 0))
    ImageDraw.Draw(ring).rounded_rectangle(rect, radius=radius, outline=color + (int(255 * alpha),), width=4)
    frame.alpha_composite(ring)


# MARK: Scenes

class Scenes:
    def __init__(self, shots):
        self.icon = Image.open(ICON).convert("RGBA")
        self.scrim = make_scrim()
        self.shots = {name: Shot(os.path.join(shots, f"{name}.png")) for name in ["install", "queue", "review", "apps"]}
        self.plan = [
            (4.5, self.logo),
            (4.6, self.problem),
            (6.4, self.drop),
            (6.6, self.verdicts),
            (9.2, self.reasons),
            (6.6, self.apps),
            (5.8, self.features),
            (6.4, self.end),
        ]

    @property
    def duration(self):
        return sum(d for d, _ in self.plan)

    def render(self, frame, t):
        start = 0.0
        for duration, scene in self.plan:
            if start <= t < start + duration:
                scene(frame, t - start, duration)
                return
            start += duration

    # Each scene draws onto the backdrop with its own fades.

    def logo(self, frame, t, d):
        a = fade(t, d, 0.8, 0.6)
        grow = 0.86 + 0.14 * ease_out(t / 1.6)
        size = int(300 * grow)
        icon = self.icon.resize((size, size), Image.Resampling.LANCZOS)
        frame.alpha_composite(with_alpha(icon, a), (W // 2 - size // 2, int(H * 0.40) - size // 2))
        put_text(frame, "Airlock", (W // 2, H * 0.40 + 170), 104, "Bold", INK, a * ramp(t, 0.9, 0.7), 20, "center")
        put_text(frame, "Know what you install.", (W // 2, H * 0.40 + 300), 44, "Regular", MUTED,
                 a * ramp(t, 1.6, 0.7), 16, "center")

    def problem(self, frame, t, d):
        a = fade(t, d, 0.4, 0.6)
        put_text(frame, "An APK from the internet", (W // 2, 360), 76, "Bold", INK, a * ramp(t, 0.1, 0.6), 24, "center")
        put_text(frame, "could be anything.", (W // 2, 460), 76, "Bold", INK, a * ramp(t, 0.7, 0.6), 24, "center")
        put_text(frame, "Airlock checks it before your phone ever sees it.", (W // 2, 640), 46, "Medium", TEAL,
                 a * ramp(t, 2.0, 0.7), 18, "center")

    def caption(self, frame, t, d, kicker, title, body):
        a = fade(t, d, 0.5, 0.5)
        frame.alpha_composite(with_alpha(self.scrim, a))
        x = 120
        put_text(frame, kicker, (x, 330), 26, "Semibold", TEAL, a * ramp(t, 0.15, 0.6), 12, tracking=5)
        y = 380
        for i, line in enumerate(wrap(title, 64, "Bold", 560)):
            put_text(frame, line, (x, y + i * 78), 64, "Bold", INK, a * ramp(t, 0.3, 0.6), 18)
        lines = len(wrap(title, 64, "Bold", 560))
        put_paragraph(frame, body, (x, y + lines * 78 + 30), 32, "Regular", MUTED, 540, a * ramp(t, 0.6, 0.6))

    def window(self, frame, t, d, name, width=1180, center=(1270, 560)):
        a = fade(t, d, 0.6, 0.5)
        rise = (1 - ease_out(t / 1.0)) * 60
        return self.shots[name].draw(frame, (center[0], center[1] + rise), width * (0.96 + 0.04 * ease_out(t / 1.2)), a), a

    def drop(self, frame, t, d):
        self.window(frame, t, d, "install")
        self.caption(frame, t, d, "DROP", "Drop any Android app.",
                     "APK, APKS, XAPK, APKM or a folder of split APKs, straight from Finder.")

    def verdicts(self, frame, t, d):
        mapping, a = self.window(frame, t, d, "queue")
        highlight(frame, mapping, (1540, 272, 1720, 610), a * ramp(t, 1.4, 0.6))
        self.caption(frame, t, d, "CHECK", "A verdict for every file.",
                     "Low-risk apps install on their own. Anything else waits for your decision.")

    def reasons(self, frame, t, d):
        a = fade(t, d, 0.6, 0.6)
        shot = self.shots["review"]
        # Full window, then a slow push into the verdict, then down to the buttons.
        zoom = ease_in_out((t - 1.6) / 1.6)
        down = ease_in_out((t - 5.0) / 1.6)
        width = 1180 + 520 * zoom
        banner = (1040, 380)
        buttons = (1300, 1340)
        focus = (banner[0] + (buttons[0] - banner[0]) * down, banner[1] + (buttons[1] - banner[1]) * down)
        start_focus = (shot.image.width / 2, shot.image.height / 2)
        f = (start_focus[0] + (focus[0] - start_focus[0]) * zoom, start_focus[1] + (focus[1] - start_focus[1]) * zoom)
        mapping = shot.draw_focused(frame, f, (1270, 560 + (1 - ease_out(t)) * 60), width, a)
        highlight(frame, mapping, (488, 292, 1592, 468), a * ramp(t, 2.6, 0.5) * (1 - ramp(t, 4.9, 0.4)), (232, 92, 82))
        highlight(frame, mapping, (1408, 1346, 1596, 1394), a * ramp(t, 6.4, 0.5), TEAL, 12)
        self.caption(frame, t, d, "DECIDE", "Reasons, not jargon.",
                     "High risk is explained in plain words, and Don't Install is always the default.")

    def apps(self, frame, t, d):
        self.window(frame, t, d, "apps")
        self.caption(frame, t, d, "MANAGE", "Every app on your phone.",
                     "Turn off bloat with UAD-ng lists. Core Android stays locked, and every change can be undone.")

    def features(self, frame, t, d):
        a = fade(t, d, 0.5, 0.6)
        put_text(frame, "Built to be trusted", (W // 2, 150), 64, "Bold", INK, a * ramp(t, 0.1, 0.6), 18, "center")
        cards = [
            ("Sandboxed parsing", "Files are opened in an isolated helper with no network access."),
            ("Signature checks", "See who signed an app, and whether it matches the one you have."),
            ("Plain permissions", "What an app can do, in words anyone can read."),
            ("Wi-Fi pairing", "Pair with a QR code and leave the cable behind."),
            ("Full undo", "Installs and changes are recorded and can be reversed."),
            ("Private by design", "No account. No analytics. Your phone stays yours."),
        ]
        cw, ch, gap = 500, 210, 40
        left = (W - (cw * 3 + gap * 2)) // 2
        for i, (title, body) in enumerate(cards):
            appear = a * ramp(t, 0.4 + i * 0.18, 0.6)
            if appear <= 0.01:
                continue
            x = left + (i % 3) * (cw + gap)
            y = 300 + (i // 3) * (ch + gap) + int((1 - appear) * 30)
            card = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
            draw = ImageDraw.Draw(card)
            draw.rounded_rectangle((0, 0, cw - 1, ch - 1), radius=22, fill=(255, 255, 255, 16), outline=(255, 255, 255, 34), width=2)
            draw.rounded_rectangle((32, 36, 40, 76), radius=4, fill=TEAL + (255,))
            frame.alpha_composite(with_alpha(card, appear), (x, y))
            put_text(frame, title, (x + 60, y + 32), 34, "Semibold", INK, appear)
            put_paragraph(frame, body, (x + 32, y + 100), 26, "Regular", MUTED, cw - 64, appear, 0)

    def end(self, frame, t, d):
        a = fade(t, d, 0.6, 1.0)
        size = 200
        icon = self.icon.resize((size, size), Image.Resampling.LANCZOS)
        frame.alpha_composite(with_alpha(icon, a * ramp(t, 0, 0.6)), (W // 2 - size // 2, 230))
        put_text(frame, "Airlock", (W // 2, 460), 96, "Bold", INK, a * ramp(t, 0.3, 0.6), 18, "center")
        put_text(frame, "Free and open source, for macOS.", (W // 2, 590), 42, "Regular", MUTED, a * ramp(t, 0.7, 0.6), 14, "center")
        put_text(frame, REPO_URL, (W // 2, 690), 40, "Semibold", TEAL, a * ramp(t, 1.1, 0.6), 14, "center")
        put_text(frame, "GPL-3.0  ·  macOS 14 or later", (W // 2, 790), 28, "Regular", MUTED, a * ramp(t, 1.5, 0.6), 10, "center")


# MARK: Sound

def soundtrack(path, duration):
    """A quiet ambient pad: four slow chords, softened and widened, fading in and out."""
    chords = [[220.0, 261.63, 329.63, 493.88], [174.61, 220.0, 261.63, 329.63],
              [130.81, 196.0, 261.63, 329.63], [196.0, 246.94, 293.66, 392.0]]
    segment = duration / len(chords)
    parts = []
    for i, chord in enumerate(chords):
        start = i * segment
        # Each chord swells in and out over its segment, overlapping the next a little.
        env = f"(0.5-0.5*cos(2*PI*min(max((t-{start - 1.5:.2f})/{segment + 3:.2f},0),1)))"
        tones = "+".join(f"sin(2*PI*{f}*t)*{0.9 / (k + 1):.2f}+sin(2*PI*{f * 1.003}*t)*{0.5 / (k + 1):.2f}"
                         for k, f in enumerate(chord))
        parts.append(f"({tones})*{env}")
    expr = "0.045*(" + "+".join(parts) + ")"
    subprocess.run([
        "ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi",
        "-i", f"aevalsrc='{expr}|{expr}':s=48000:d={duration:.2f}",
        # Normalised to a background-music level that sits under a voice or the room.
        "-af", f"lowpass=f=1800,aecho=0.8:0.7:120|240:0.35|0.25,loudnorm=I=-23:TP=-3,"
               f"afade=t=in:d=2,afade=t=out:st={duration - 2.5:.2f}:d=2.5",
        "-c:a", "aac", "-b:a", "192k", path,
    ], check=True)


def main(shots, out):
    scenes = Scenes(shots)
    backdrop = Backdrop()
    duration = scenes.duration
    frames = int(duration * FPS)
    with tempfile.TemporaryDirectory() as work:
        video = os.path.join(work, "video.mp4")
        audio = os.path.join(work, "audio.m4a")
        encoder = subprocess.Popen([
            "ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
            "-r", str(FPS), "-i", "-", "-c:v", "libx264", "-preset", "slow", "-crf", "17",
            "-pix_fmt", "yuv420p", "-movflags", "+faststart", video,
        ], stdin=subprocess.PIPE)
        for n in range(frames):
            t = n / FPS
            frame = backdrop.frame(t)
            scenes.render(frame, t)
            encoder.stdin.write(frame.convert("RGB").tobytes())
            if n % (FPS * 5) == 0:
                print(f"{t:5.1f}s / {duration:.1f}s", flush=True)
        encoder.stdin.close()
        if encoder.wait() != 0:
            sys.exit("ffmpeg failed to encode the video")
        soundtrack(audio, duration)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", video, "-i", audio, "-c:v", "copy",
                        "-c:a", "copy", "-shortest", out], check=True)
    print(f"wrote {out} ({duration:.1f}s)")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[3] == "--stills":
        # Renders one frame from the middle of each scene, for a quick review without encoding.
        scenes, backdrop = Scenes(sys.argv[1]), Backdrop()
        start = 0.0
        for i, (duration, _) in enumerate(scenes.plan):
            for part in (0.45, 0.85):
                t = start + duration * part
                frame = backdrop.frame(t)
                scenes.render(frame, t)
                frame.convert("RGB").save(os.path.join(sys.argv[2], f"still-{i}-{int(part * 100)}.jpg"), quality=88)
            start += duration
    else:
        main(sys.argv[1], sys.argv[2])
