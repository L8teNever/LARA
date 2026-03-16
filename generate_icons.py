"""Generate PWA icons for LARA. Run once: python generate_icons.py"""
import struct
import zlib
import os

def create_png(size, bg_color=(103, 80, 164), fg_color=(255, 255, 255)):
    """Create a simple PNG icon with an 'L' letter centered."""
    pixels = []
    center = size // 2
    letter_size = size // 3

    for y in range(size):
        row = []
        for x in range(size):
            # Rounded rectangle background (with radius)
            radius = size // 5
            in_rect = True
            # Check corners
            if x < radius and y < radius:
                in_rect = ((x - radius)**2 + (y - radius)**2) <= radius**2
            elif x >= size - radius and y < radius:
                in_rect = ((x - (size - radius - 1))**2 + (y - radius)**2) <= radius**2
            elif x < radius and y >= size - radius:
                in_rect = ((x - radius)**2 + (y - (size - radius - 1))**2) <= radius**2
            elif x >= size - radius and y >= size - radius:
                in_rect = ((x - (size - radius - 1))**2 + (y - (size - radius - 1))**2) <= radius**2

            if not in_rect:
                row.extend([0, 0, 0, 0])  # Transparent
                continue

            # Draw "L" shape
            lx = x - center + letter_size // 2
            ly = y - center + letter_size // 2
            bar_w = max(size // 12, 4)

            in_letter = False
            # Vertical bar of L
            if 0 <= lx < bar_w and 0 <= ly < letter_size:
                in_letter = True
            # Horizontal bar of L
            if 0 <= lx < letter_size and letter_size - bar_w <= ly < letter_size:
                in_letter = True

            if in_letter:
                row.extend([*fg_color, 255])
            else:
                row.extend([*bg_color, 255])
        pixels.append(bytes([0] + row))  # Filter byte 0 (None) per row

    raw = b''.join(pixels)

    def chunk(ctype, data):
        c = ctype + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    header = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
    idat = chunk(b'IDAT', zlib.compress(raw))
    iend = chunk(b'IEND', b'')

    return header + ihdr + idat + iend

if __name__ == '__main__':
    for s in [192, 512]:
        data = create_png(s)
        path = f'icon-{s}.png'
        with open(path, 'wb') as f:
            f.write(data)
        print(f'Created {path} ({len(data)} bytes)')
