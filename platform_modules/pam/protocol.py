"""Bounded Guacamole framing and display-only client input policy.

This is a protocol primitive, NOT an authorization check or a public tunnel.
Connection arguments must only ever be produced by the server-side broker.
"""

import codecs
import re
from dataclasses import dataclass


class ProtocolFailure(Exception):
    """A stable error code, never the untrusted frame or connection arguments."""


@dataclass(frozen=True)
class Instruction:
    opcode: str
    arguments: tuple[str, ...] = ()

    def encode(self):
        elements = (self.opcode, *self.arguments)
        return (",".join(f"{len(value)}.{value}" for value in elements) + ";").encode()


class Parser:
    """Incremental UTF-8/code-point parser, bounded before allocating a payload."""

    def __init__(self, *, max_element=524_288, max_instruction=1_048_576, max_elements=256):
        self.max_element = max_element
        self.max_instruction = max_instruction
        self.max_elements = max_elements
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._buffer = ""
        self._length = None
        self._elements = []
        self._count = 0
        self._failed = False

    def _fail(self, code):
        self._failed = True
        self._buffer, self._elements = "", []
        raise ProtocolFailure(code)

    def feed(self, data):
        if self._failed:
            raise ProtocolFailure("parser_closed")
        if not isinstance(data, bytes) or len(data) > 65_536:
            self._fail("frame_too_large")
        try:
            self._buffer += self._decoder.decode(data)
        except UnicodeError:
            self._fail("invalid_utf8")
        instructions = []
        while self._buffer:
            if self._length is None:
                dot = self._buffer.find(".")
                prefix = self._buffer if dot == -1 else self._buffer[:dot]
                if (
                    not prefix
                    or len(prefix) > 7
                    or not prefix.isascii()
                    or not prefix.isdecimal()
                    or len(prefix) > 1
                    and prefix.startswith("0")
                ):
                    self._fail("invalid_length")
                if dot == -1:
                    break
                self._length = int(prefix)
                if self._length > self.max_element:
                    self._fail("element_too_large")
                self._count += dot + 2 + self._length
                if self._count > self.max_instruction:
                    self._fail("instruction_too_large")
                self._buffer = self._buffer[dot + 1 :]
            if len(self._buffer) <= self._length:
                break
            value = self._buffer[: self._length]
            delimiter = self._buffer[self._length]
            self._buffer = self._buffer[self._length + 1 :]
            self._length = None
            if delimiter not in (",", ";"):
                self._fail("invalid_delimiter")
            self._elements.append(value)
            if len(self._elements) > self.max_elements:
                self._fail("too_many_elements")
            if delimiter == ";":
                opcode, *arguments = self._elements
                if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", opcode):
                    self._fail("invalid_opcode")
                instructions.append(Instruction(opcode, tuple(arguments)))
                self._elements, self._count = [], 0
                if len(instructions) > 4096:
                    self._fail("too_many_instructions")
        return instructions

    def finish(self):
        if self._failed:
            raise ProtocolFailure("parser_closed")
        try:
            self._decoder.decode(b"", final=True)
        except UnicodeError:
            self._fail("invalid_utf8")
        if self._buffer or self._elements or self._length is not None:
            self._fail("incomplete_instruction")


def _integer(value, minimum, maximum):
    if (
        not value
        or len(value) > 16
        or not value.isascii()
        or not value.isdecimal()
        or not minimum <= int(value) <= maximum
    ):
        raise ProtocolFailure("invalid_input_value")


def validate_input(instruction):
    """No connect/select, credentials, clipboard, file upload or arbitrary streams.

    ACK only acknowledges a server-created output stream. It cannot create a
    stream or carry uploaded data. The eventual broker must rate-limit frames.
    """
    shapes = {
        "key": ((0, 0xFFFFFFFF), (0, 1)),
        "mouse": ((0, 8192), (0, 8192), (0, 31)),
        "size": ((320, 3840), (200, 2160)),
        "sync": ((0, 2**53 - 1),),
        "nop": (),
        "disconnect": (),
    }
    if instruction.opcode == "ack":
        if len(instruction.arguments) != 3:
            raise ProtocolFailure("invalid_input_shape")
        stream, message, status = instruction.arguments
        _integer(stream, 0, 2**31 - 1)
        _integer(status, 0, 0xFFFF)
        if len(message) > 128 or any(not 32 <= ord(char) <= 126 for char in message):
            raise ProtocolFailure("invalid_input_value")
        return instruction
    shape = shapes.get(instruction.opcode)
    if shape is None:
        raise ProtocolFailure("input_not_authorized")
    if len(instruction.arguments) != len(shape):
        raise ProtocolFailure("invalid_input_shape")
    for value, bounds in zip(instruction.arguments, shape, strict=True):
        _integer(value, *bounds)
    return instruction
