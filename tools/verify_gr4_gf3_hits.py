#!/usr/bin/env python3
"""Verify all nine raw GF3 hits in the pinned decoded GR IV sample, offline.

Trace SquashFS storage bytes through LZ4 literals to file offsets, check ELF
sections and decode Thumb instruction boundaries. Does not execute firmware.
Requires Capstone and the existing local SquashFS reader; emits metadata only.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from audit_xpan_paths import EXPECTED_SHA256
from gr4_emulator_probe import find_parts
from inspect_initfs_readonly import SquashFS


FILES = (
    (0x1AE690D, "/lib/firmware/nxp/sduart_nw61x_v1.bin.se", 0xC153B),
    (0x1BAC810, "/lib/libblkid.so.1.1.0", 0x1D676),
    (0x1CA9366, "/lib/libfdisk.so.1.1.0", 0x2E8AA),
    (0x1D1EF2E, "/lib/libmount.so.1.1.0", 0x25FE6),
    (0x1D66B83, "/lib/libsmartcols.so.1.1.0", 0x1119A),
    (0x1FC1DBB, "/sbin/cfdisk", 0xA7DE),
    (0x1FD2F77, "/sbin/fdisk.util-linux", 0xBA9A),
)


def occurrences(raw, needle):
    hits = []
    at = raw.find(needle)
    while at != -1:
        hits.append(at)
        at = raw.find(needle, at + 1)
    return hits


def literal_offset(source, target):
    """Decode LZ4 and map three consecutive source literal bytes to output."""
    out = bytearray()
    at = 0
    mapped = None
    while at < len(source):
        token = source[at]
        at += 1
        count = token >> 4
        if count == 15:
            while True:
                extra = source[at]
                at += 1
                count += extra
                if extra != 255:
                    break
        if at <= target and target + 3 <= at + count:
            mapped = len(out) + target - at
        out.extend(source[at:at + count])
        at += count
        if at == len(source):
            break
        distance = int.from_bytes(source[at:at + 2], "little")
        at += 2
        if not 0 < distance <= len(out):
            raise ValueError("invalid LZ4 match distance")
        count = token & 15
        if count == 15:
            while True:
                extra = source[at]
                at += 1
                count += extra
                if extra != 255:
                    break
        for _ in range(count + 4):
            out.append(out[-distance])
    return bytes(out), mapped


def extents(fs, ref):
    node = fs.inode(ref)
    if struct.unpack_from("<H", node)[0] != 2:
        raise ValueError("expected basic file inode")
    start, fragment, offset, size = struct.unpack_from("<4I", node, 16)
    blocks = (size // fs.block_size if fragment != 0xFFFFFFFF
              else (size + fs.block_size - 1) // fs.block_size)
    entries = struct.unpack(f"<{blocks}I", fs.read_metadata(
        fs.inodes, ref >> 16, (ref & 0xFFFF) + 32, blocks * 4)) if blocks else ()
    for index, entry in enumerate(entries):
        yield start, entry, index * fs.block_size, 0, fs.block_size
        start += entry & 0xFFFFFF
    if fragment != 0xFFFFFFFF:
        pointer = struct.unpack_from("<Q", fs.data,
                                     fs.fragments + 8 * (fragment // 512))[0]
        start, entry, _ = struct.unpack("<QII", fs.read_metadata(
            pointer, 0, (fragment % 512) * 16, 16))
        yield start, entry, blocks * fs.block_size, offset, size % fs.block_size


def elf_section(raw, offset):
    if raw[:6] != b"\x7fELF\x01\x01":
        return None
    if struct.unpack_from("<H", raw, 18)[0] != 40:
        raise ValueError("expected ARM ELF")
    table = struct.unpack_from("<I", raw, 32)[0]
    stride, count, strings = struct.unpack_from("<3H", raw, 46)
    sections = [struct.unpack_from("<10I", raw, table + i * stride)
                for i in range(count)]
    names = raw[sections[strings][4]:sections[strings][4] + sections[strings][5]]
    for name, kind, flags, address, start, size, *_ in sections:
        if kind != 8 and start <= offset and offset + 3 <= start + size:
            end = names.index(0, name)
            return {"name": names[name:end].decode("ascii"),
                    "executable": bool(flags & 4),
                    "virtual_address": hex(address + offset - start)}
    raise ValueError("hit outside file-backed ELF sections")


def disassemble(raw, start, end):
    return [{"offset": hex(ins.address), "bytes": bytes(ins.bytes).hex(" "),
             "instruction": (ins.mnemonic + " " + ins.op_str).strip()}
            for ins in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(raw[start:end], start)]


def verify(raw):
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unsupported decoded sample: {digest}")
    hits = occurrences(raw, b"GF3")
    if hits != [0xA26, 0x130E9A] + [item[0] for item in FILES]:
        raise ValueError("unexpected raw GF3 matches")
    part = find_parts(raw)["initfs"]
    fs = SquashFS(part.data)
    records = []
    for hit, begin, end in ((0xA26, 0xA24, 0xA3C),
                            (0x130E9A, 0x130E8C, 0x130EA8)):
        instructions = disassemble(raw, begin, end)
        at_hit = next(item for item in instructions if item["offset"] == hex(hit))
        if at_hit["bytes"] != "47 46" or at_hit["instruction"] != "mov r7, r8":
            raise ValueError("unexpected Thumb instruction boundary")
        records.append({"decoded_offset": hex(hit), "location": "firmware Thumb sequence",
                        "context": instructions})
    for hit, path, expected_offset in FILES:
        ref = fs.resolve(path)
        data = fs.read_file(ref)
        mapped = []
        for start, encoded, file_base, fragment_base, extent_size in extents(fs, ref):
            length = encoded & 0xFFFFFF
            physical = part.offset + start
            if physical <= hit and hit + 3 <= physical + length:
                chunk = fs.data[start:start + length]
                compressed = not bool(encoded & 0x1000000)
                if compressed:
                    decoded, logical = literal_offset(chunk, hit - physical)
                else:
                    decoded, logical = chunk, hit - physical
                if logical is not None and fragment_base <= logical and logical + 3 <= fragment_base + extent_size:
                    file_offset = file_base + logical - fragment_base
                    if decoded[logical:logical + 3] != b"GF3" or data[file_offset:file_offset + 3] != b"GF3":
                        raise ValueError("source/output byte correspondence failed")
                    mapped.append((file_offset, compressed, physical))
        if len(mapped) != 1 or mapped[0][0] != expected_offset:
            raise ValueError(f"physical-to-file mapping failed: {path}")
        file_offset, compressed, physical = mapped[0]
        section = elf_section(data, file_offset)
        record = {"decoded_offset": hex(hit), "path": path,
                  "file_offset": hex(file_offset), "storage_block_offset": hex(physical),
                  "compressed_literal": compressed, "file_size": len(data),
                  "file_sha256": hashlib.sha256(data).hexdigest(), "section": section}
        if section:
            if section["name"] != ".text" or not section["executable"]:
                raise ValueError("expected executable .text section")
            if data[file_offset:file_offset + 4] != bytes.fromhex("47 46 33 68"):
                raise ValueError("unexpected Thumb bytes")
            record["context"] = disassemble(data, file_offset - 8, file_offset + 16)
        else:
            record["context_hex"] = data[file_offset - 8:file_offset + 16].hex(" ")
        records.append(record)
    return {"schema": "gr4-gf3-byte-verification-v1", "sample_sha256": digest,
            "offset_basis": "decoded file; not update-package or RAM addresses",
            "initfs_offset": hex(part.offset), "raw_ascii_hits": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    report = verify(args.image.read_bytes())
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(f"Verified {len(report['raw_ascii_hits'])} raw GF3 matches; {args.output}")


if __name__ == "__main__":
    main()
