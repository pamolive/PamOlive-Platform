"""Recognize the fixture's post-keypress pixels in the actual native display."""

import asyncio
import base64
from io import BytesIO


class PaintProof:
    EXPECTED = (187, 216, 88)

    def __init__(self):
        self.matches = False
        self.streams = {}

    def color(self, color):
        return all(abs(actual - expected) <= 8 for actual, expected in zip(color, self.EXPECTED))

    def image(self, data):
        from PIL import Image

        with Image.open(BytesIO(data)) as image:
            if image.format not in ("PNG", "JPEG") or image.width * image.height > 4 * 1024 * 1024:
                raise AssertionError("Unexpected test-peer image shape")
            pixels = image.convert("RGB").getcolors(maxcolors=4096) or []
            self.matches = self.matches or any(self.color(color) for _, color in pixels)

    def observe(self, instruction):
        opcode, args = instruction.opcode, instruction.arguments
        if opcode == "cfill" and len(args) == 6:
            self.matches = self.matches or self.color(tuple(map(int, args[2:5])))
        elif opcode == "img" and len(args) == 6:
            self.streams[args[0]] = bytearray()
        elif opcode == "blob" and args[0] in self.streams:
            target = self.streams[args[0]]
            target.extend(base64.b64decode(args[1], validate=True))
            if len(target) > 4 * 1024 * 1024:
                raise AssertionError("Unexpected test-peer image size")
        elif opcode == "end" and args[0] in self.streams:
            self.image(bytes(self.streams.pop(args[0])))
        elif opcode in ("png", "jpeg"):
            self.image(base64.b64decode(args[-1], validate=True))

    async def wait(self, task):
        async with asyncio.timeout(8):
            while not self.matches:
                if task.done():
                    task.result()
                    raise AssertionError("Display stopped before the target's pixels arrived")
                await asyncio.sleep(0.02)
