# Copyright 2026 radium-wang. License: see LICENSE.
"""Read-only GR IV update decoding and embedded firmware component detection.

Shared by static research tools. No emulator, build, launch or camera I/O.
"""
import hashlib
import struct
from dataclasses import dataclass
from inspect_firmware import unpack_frames


FDT_MAGIC = bytes.fromhex("d00dfeed")


ZIMAGE_MAGIC = bytes.fromhex("18286f01")


SQUASHFS_MAGIC = b"hsqs"


@dataclass(frozen=True)
class Part:
    offset: int
    data: bytes

    def describe(self):
        return {
            "offset": f"0x{self.offset:x}",
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }


def occurrences(data, needle):
    at = 0
    while (at := data.find(needle, at)) != -1:
        yield at
        at += 1


def load_payload(path):
    source = path.read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    if source.startswith(b"BOOTPARA"):
        return source, "decoded payload", None, source_hash
    if source[8:20].split(b"\0", 1)[0] != b"GR IV":
        raise ValueError("expected a GR IV update or decoded BOOTPARA payload")
    if len(source) % 4 or sum(word for (word,) in struct.iter_unpack("<I", source)) & 0xFFFFFFFF:
        raise ValueError("GR IV update checksum is invalid")
    payload, consumed, _frames = unpack_frames(source)
    if not payload.startswith(b"BOOTPARA") or consumed >= len(source):
        raise ValueError("update did not decode to the expected BOOTPARA payload")
    version = ".".join(str(component) for component in source[0x38:0x3C])
    return bytes(payload), "GR IV update", version, source_hash


def find_parts(payload):
    trees = []
    for at in occurrences(payload, FDT_MAGIC):
        if at + 40 > len(payload):
            continue
        size = struct.unpack_from(">I", payload, at + 4)[0]
        version = struct.unpack_from(">I", payload, at + 20)[0]
        if 40 <= size <= 1024 * 1024 and at + size <= len(payload) and version == 17:
            blob = payload[at:at + size]
            if b"milbeaut,sc2000a" in blob:
                trees.append(Part(at, blob))

    kernels = []
    for magic_at in occurrences(payload, ZIMAGE_MAGIC):
        at = magic_at - 0x24
        if at < 0 or at + 0x30 > len(payload):
            continue
        start, end = struct.unpack_from("<II", payload, at + 0x28)
        size = end - start
        if start == 0 and 0x10000 <= size <= 64 * 1024 * 1024 and at + size <= len(payload):
            kernels.append(Part(at, payload[at:at + size]))

    filesystems = []
    for at in occurrences(payload, SQUASHFS_MAGIC):
        if at + 96 > len(payload):
            continue
        (magic, _inodes, _time, block_size, _fragments, compression, _log,
         _flags, _ids, major, minor, _root, used, *_tables) = struct.unpack_from(
            "<5I6H8Q", payload, at
        )
        if (magic, compression, major, minor) != (0x73717368, 5, 4, 0):
            continue
        if block_size not in (4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576):
            continue
        if not 96 <= used <= len(payload) - at:
            continue
        padded = (used + 511) & ~511
        size = padded if at + padded <= len(payload) else used
        filesystems.append(Part(at, payload[at:at + size]))

    for kernel in kernels:
        tree = max((part for part in trees if part.offset < kernel.offset),
                   key=lambda part: part.offset, default=None)
        filesystem = min((part for part in filesystems
                          if part.offset >= kernel.offset + len(kernel.data)),
                         key=lambda part: part.offset, default=None)
        if tree and filesystem:
            return {"device_tree": tree, "kernel": kernel, "initfs": filesystem}
    raise ValueError("did not find a matching SC2000A device tree, ARM zImage, and LZ4 SquashFS")
