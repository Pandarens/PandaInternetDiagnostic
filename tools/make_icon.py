"""Draws the app icon (panda face on a blue badge) and writes panda_diag/web/icon.ico. Pure Python, no deps."""
import math
import os
import struct
import zlib

BG1, BG2 = (59, 108, 246), (123, 92, 246)
BLACK, WHITE = (24, 26, 32), (255, 255, 255)


def in_rrect(x, y, s, r):
    cx = min(max(x, r), s - r)
    cy = min(max(y, r), s - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_ellipse(x, y, cx, cy, rx, ry, ang=0.0):
    dx, dy = x - cx, y - cy
    if ang:
        c, s = math.cos(ang), math.sin(ang)
        dx, dy = dx * c + dy * s, -dx * s + dy * c
    return (dx / rx) ** 2 + (dy / ry) ** 2 <= 1


def color_at(x, y):
    """Shapes in a 256x256 design space, painted back to front."""
    if not in_rrect(x, y, 256, 58):
        return None
    t = (x + y) / 512
    col = tuple(int(a + (b - a) * t) for a, b in zip(BG1, BG2))
    if in_ellipse(x, y, 74, 78, 32, 32) or in_ellipse(x, y, 182, 78, 32, 32):
        col = BLACK
    if in_ellipse(x, y, 128, 142, 84, 76):
        col = WHITE
    if in_ellipse(x, y, 96, 136, 19, 26, 0.55) or in_ellipse(x, y, 160, 136, 19, 26, -0.55):
        col = BLACK
    if in_ellipse(x, y, 99, 131, 6.5, 6.5) or in_ellipse(x, y, 157, 131, 6.5, 6.5):
        col = WHITE
    if in_ellipse(x, y, 128, 170, 13, 9):
        col = BLACK
    if in_ellipse(x, y, 128, 186, 16, 7) and not in_ellipse(x, y, 128, 181, 16, 7):
        col = BLACK
    return col


def render(size, ss=4):
    rows = []
    k = 256 / size
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    c = color_at((px + (sx + .5) / ss) * k, (py + (sy + .5) / ss) * k)
                    if c:
                        acc[0] += c[0]
                        acc[1] += c[1]
                        acc[2] += c[2]
                        acc[3] += 1
            n = acc[3]
            if n:
                row += bytes((acc[0] // n, acc[1] // n, acc[2] // n, 255 * n // (ss * ss)))
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    return rows


def png(rows, size):
    raw = b"".join(b"\0" + r for r in rows)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = [png(render(s), s) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(sizes))
    off = 6 + 16 * len(sizes)
    entries = b""
    for s, data in zip(sizes, imgs):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), off)
        off += len(data)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "panda_diag", "web", "icon.ico")
    with open(out, "wb") as f:
        f.write(head + entries + b"".join(imgs))
    with open(os.path.join(root, "tools", "icon.png"), "wb") as f:
        f.write(imgs[-1])
    print(out)


if __name__ == "__main__":
    main()
