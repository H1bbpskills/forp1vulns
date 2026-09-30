"""
Input fuzzing harness for protocol and API testing.
Generates mutated inputs and monitors for crashes/unexpected behavior.
"""

import os
import random
import string
import struct
from dataclasses import dataclass, field


@dataclass
class FuzzCase:
    input_data: bytes
    mutation: str
    seed: int


@dataclass
class FuzzResult:
    case: FuzzCase
    crashed: bool = False
    timeout: bool = False
    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    interesting: bool = False


class Fuzzer:
    def __init__(self, config, seed_corpus: list[bytes] | None = None):
        self.config = config
        self.seed_corpus = seed_corpus or []
        self.corpus: list[bytes] = list(self.seed_corpus)
        self.crashes: list[FuzzResult] = []

    def add_seed(self, data: bytes):
        self.corpus.append(data)

    def generate_cases(self, count: int = 100) -> list[FuzzCase]:
        cases = []
        for i in range(count):
            if self.corpus:
                base = random.choice(self.corpus)
            else:
                base = os.urandom(random.randint(1, 256))

            mutated, mutation_name = self._mutate(base)
            cases.append(FuzzCase(input_data=mutated, mutation=mutation_name, seed=i))
        return cases

    def _mutate(self, data: bytes) -> tuple[bytes, str]:
        mutations = [
            self._bit_flip,
            self._byte_flip,
            self._insert_random,
            self._delete_bytes,
            self._duplicate_block,
            self._insert_interesting,
            self._truncate,
            self._extend,
        ]
        mutator = random.choice(mutations)
        return mutator(data)

    def _bit_flip(self, data: bytes) -> tuple[bytes, str]:
        if not data:
            return data, "bit_flip_empty"
        arr = bytearray(data)
        pos = random.randint(0, len(arr) - 1)
        bit = random.randint(0, 7)
        arr[pos] ^= 1 << bit
        return bytes(arr), f"bit_flip@{pos}:{bit}"

    def _byte_flip(self, data: bytes) -> tuple[bytes, str]:
        if not data:
            return data, "byte_flip_empty"
        arr = bytearray(data)
        pos = random.randint(0, len(arr) - 1)
        arr[pos] ^= 0xFF
        return bytes(arr), f"byte_flip@{pos}"

    def _insert_random(self, data: bytes) -> tuple[bytes, str]:
        pos = random.randint(0, len(data))
        length = random.randint(1, 32)
        insert = os.urandom(length)
        return data[:pos] + insert + data[pos:], f"insert_random@{pos}:{length}"

    def _delete_bytes(self, data: bytes) -> tuple[bytes, str]:
        if len(data) < 2:
            return data, "delete_skip"
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(32, len(data) - start))
        return data[:start] + data[start + length:], f"delete@{start}:{length}"

    def _duplicate_block(self, data: bytes) -> tuple[bytes, str]:
        if not data:
            return data, "dup_empty"
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(64, len(data) - start))
        block = data[start:start + length]
        pos = random.randint(0, len(data))
        return data[:pos] + block + data[pos:], f"dup@{start}:{length}->{pos}"

    def _insert_interesting(self, data: bytes) -> tuple[bytes, str]:
        interesting_values = [
            b"\x00", b"\xff", b"\x00\x00\x00\x00",
            b"\xff\xff\xff\xff", b"\x7f\xff\xff\xff",
            b"\x80\x00\x00\x00", struct.pack("<q", -1),
            struct.pack("<q", 2**63 - 1),
            b"\x00" * 256,
            b"A" * 1024,
            b"%s%s%s%s%s",
            b"{{7*7}}",
            b"${7*7}",
        ]
        val = random.choice(interesting_values)
        pos = random.randint(0, len(data))
        return data[:pos] + val + data[pos:], f"interesting@{pos}"

    def _truncate(self, data: bytes) -> tuple[bytes, str]:
        if not data:
            return data, "truncate_empty"
        pos = random.randint(0, len(data) - 1)
        return data[:pos], f"truncate@{pos}"

    def _extend(self, data: bytes) -> tuple[bytes, str]:
        length = random.randint(1, 4096)
        return data + os.urandom(length), f"extend:{length}"
