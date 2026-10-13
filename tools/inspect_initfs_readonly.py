#!/usr/bin/env python3
"""Read selected files from the local GR IV LZ4 SquashFS initfs, without extracting it.

Supports the small directory and file inode forms used for startup configs.
It reads only; it does not alter the camera, SD card, or firmware image.
"""

import argparse
import struct
from pathlib import Path


def lz4_block(source):
    out = bytearray()
    at = 0
    while at < len(source):
        token = source[at]
        at += 1
        literal = token >> 4
        if literal == 15:
            while True:
                extra = source[at]
                at += 1
                literal += extra
                if extra != 255:
                    break
        out.extend(source[at:at + literal])
        at += literal
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
    return bytes(out)


class SquashFS:
    def __init__(self, source):
        self.data = source
        fields = struct.unpack_from("<5I6H8Q", source)
        (magic, _inodes, _time, self.block_size, _fragments, compression,
         _log, _flags, _ids, major, minor, self.root, _used, _id_table,
         _xattr, self.inodes, self.directories, self.fragments, _lookup) = fields
        if magic != 0x73717368 or (major, minor) != (4, 0) or compression != 5:
            raise ValueError("expected SquashFS 4.0 with LZ4 compression")
        self.metadata_cache = {}

    def metadata(self, absolute):
        if absolute not in self.metadata_cache:
            header = struct.unpack_from("<H", self.data, absolute)[0]
            size = header & 0x7FFF
            chunk = self.data[absolute + 2:absolute + 2 + size]
            decoded = chunk if header & 0x8000 else lz4_block(chunk)
            if len(decoded) > 8192:
                raise ValueError("metadata block exceeds 8192 bytes")
            self.metadata_cache[absolute] = (decoded, absolute + 2 + size)
        return self.metadata_cache[absolute]

    def read_metadata(self, table, block, offset, length):
        cursor = table + block
        output = bytearray()
        while len(output) < length:
            decoded, next_cursor = self.metadata(cursor)
            take = min(len(decoded) - offset, length - len(output))
            if take <= 0:
                raise ValueError("invalid metadata offset")
            output.extend(decoded[offset:offset + take])
            cursor, offset = next_cursor, 0
        return bytes(output)

    def inode(self, ref):
        block, offset = ref >> 16, ref & 0xFFFF
        return self.read_metadata(self.inodes, block, offset, 32)

    def list_dir(self, ref):
        node = self.inode(ref)
        kind = struct.unpack_from("<H", node)[0]
        if kind != 1:
            raise ValueError(f"directory inode type {kind} is unsupported")
        start, _nlink, size, offset, _parent = struct.unpack_from("<IIHHI", node, 16)
        stream = self.read_metadata(self.directories, start, offset, size)
        entries = {}
        at = 0
        while at + 12 <= len(stream) - 3:
            count, inode_block, _inode_no = struct.unpack_from("<III", stream, at)
            at += 12
            for _ in range(count + 1):
                inode_offset, _delta, entry_type, name_size = struct.unpack_from("<HhHH", stream, at)
                at += 8
                name = stream[at:at + name_size + 1].decode("utf-8")
                at += name_size + 1
                entries[name] = ((inode_block << 16) | inode_offset, entry_type)
        return entries

    def resolve(self, path):
        ref = self.root
        for part in path.strip("/").split("/"):
            if part:
                ref, _kind = self.list_dir(ref)[part]
        return ref

    def read_file(self, ref):
        node = self.inode(ref)
        kind = struct.unpack_from("<H", node)[0]
        if kind != 2:
            raise ValueError(f"file inode type {kind} is unsupported")
        start, fragment, offset, size = struct.unpack_from("<IIII", node, 16)
        full_blocks = size // self.block_size if fragment != 0xFFFFFFFF else (size + self.block_size - 1) // self.block_size
        block_sizes = struct.unpack_from(f"<{full_blocks}I", self.read_metadata(self.inodes, ref >> 16, (ref & 0xFFFF) + 32, 4 * full_blocks)) if full_blocks else ()
        output = bytearray()
        cursor = start
        for entry in block_sizes:
            length = entry & 0xFFFFFF
            if length:
                compressed = self.data[cursor:cursor + length]
                output.extend(compressed if entry & 0x1000000 else lz4_block(compressed))
            else:
                output.extend(bytes(self.block_size))
            cursor += length
        if fragment != 0xFFFFFFFF:
            pointer = struct.unpack_from("<Q", self.data, self.fragments + 8 * (fragment // 512))[0]
            record = self.read_metadata(pointer, 0, (fragment % 512) * 16, 16)
            frag_start, encoded, _ = struct.unpack("<QII", record)
            length = encoded & 0xFFFFFF
            chunk = self.data[frag_start:frag_start + length]
            decoded = chunk if encoded & 0x1000000 else lz4_block(chunk)
            output.extend(decoded[offset:offset + size % self.block_size])
        if len(output) != size:
            raise ValueError("decoded file length mismatch")
        return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("path", help="absolute path to list or read inside initfs")
    args = parser.parse_args()
    fs = SquashFS(args.image.read_bytes())
    ref = fs.resolve(args.path)
    kind = struct.unpack_from("<H", fs.inode(ref))[0]
    if kind == 1:
        for name, (_, item_type) in sorted(fs.list_dir(ref).items()):
            print(item_type, name)
    elif kind == 2:
        print(fs.read_file(ref).decode("utf-8", "replace"), end="")
    else:
        print(f"inode type {kind}; content not supported")


if __name__ == "__main__":
    main()
