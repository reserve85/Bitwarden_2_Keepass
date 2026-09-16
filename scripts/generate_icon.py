"""Generate the application icon (app/resources/Icon.ico + Icon.png).

Pure-Pillow, zero design-tool dependency: a white padlock on the Bitwarden
blue rounded tile. Re-run this script to regenerate the committed binaries:

    python scripts/generate_icon.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

SIZE = 256
BLUE = (23, 93, 216, 255)  # Bitwarden brand blue
WHITE = (255, 255, 255, 255)
CLEAR = (0, 0, 0, 0)

ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)

_RESOURCES = Path(__file__).resolve().parent.parent / "app" / "resources"


def _draw_padlock() -> Image.Image:
    """256x256 RGBA padlock on a rounded blue tile."""
    img = Image.new("RGBA", (SIZE, SIZE), CLEAR)
    d = ImageDraw.Draw(img)

    # Blue rounded tile background.
    d.rounded_rectangle((4, 4, SIZE - 4, SIZE - 4), radius=60, fill=BLUE)

    # Shackle: a ring whose lower half is covered by the body below.
    d.ellipse((78, 26, 178, 126), outline=WHITE, width=24)

    # Body: overlaps the ring bottom so only the top loop stays visible.
    d.rounded_rectangle((88, 112, 168, 182), radius=20, fill=WHITE)

    # Keyhole (the blue tile showing through the body).
    d.ellipse((120, 138, 140, 156), fill=BLUE)
    d.polygon([(122, 154), (138, 154), (130, 174)], fill=BLUE)

    return img


def main() -> None:
    _RESOURCES.mkdir(parents=True, exist_ok=True)
    master = _draw_padlock()

    png_path = _RESOURCES / "Icon.png"
    master.save(png_path, "PNG")
    print(f"wrote {png_path} ({master.size[0]}x{master.size[1]})")

    ico_path = _RESOURCES / "Icon.ico"
    master.save(ico_path, "ICO", sizes=[(s, s) for s in ICON_SIZES])
    print(f"wrote {ico_path} (sizes {ICON_SIZES})")


if __name__ == "__main__":
    main()