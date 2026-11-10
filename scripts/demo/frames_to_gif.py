#!/usr/bin/env python3
"""Join the demo frames (NN-name.png) into an animated GIF: frames_to_gif.py FRAMES OUT.gif"""

import glob
import os
import sys

from PIL import Image

# Seconds each frame stays on screen
HOLD = {"login": 2.0, "dashboard": 2.5, "alert-detail": 4.0, "hosts": 3.5}
WIDTH = 960


def main():
    frames_dir, out = sys.argv[1], sys.argv[2]
    paths = sorted(glob.glob(os.path.join(frames_dir, "[0-9][0-9]-*.png")))
    if not paths:
        raise SystemExit(f"no frames in {frames_dir}")
    images, durations = [], []
    for path in paths:
        img = Image.open(path).convert("RGB")
        img = img.resize((WIDTH, round(img.height * WIDTH / img.width)), Image.LANCZOS)
        images.append(img.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
        name = os.path.basename(path)[3:-4]
        durations.append(int(HOLD.get(name, 3.0) * 1000))
    images[0].save(out, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True)
    print(f"{out}: {len(images)} frames, {os.path.getsize(out) // 1024} KiB")


if __name__ == "__main__":
    main()
