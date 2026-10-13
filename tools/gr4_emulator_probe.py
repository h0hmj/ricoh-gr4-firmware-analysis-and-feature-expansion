#!/usr/bin/env python3
# Copyright 2026 radium-wang
# License: see LICENSE (earlier Apache-2.0 grants remain in force)
"""Extract GR IV boot components and probe its Linux kernel in QEMU.

This is an offline, read-only experiment. It never connects to a camera and
does not produce an installable firmware update. Firmware files stay local.
"""

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from inspect_firmware import checksum, unpack_frames


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


def manifest(path, kind, version, source_hash, payload, parts):
    info = {
        "source": path.name,
        "source_type": kind,
        "source_sha256": source_hash,
        "decoded_sha256": hashlib.sha256(payload).hexdigest(),
        "parts": {name: part.describe() for name, part in parts.items()},
    }
    if version:
        info["update_version"] = version
    return info


def write_parts(directory, parts, info):
    directory.mkdir(parents=True, exist_ok=True)
    files = {"device_tree": "gr4.dtb", "kernel": "zImage", "initfs": "initfs.squashfs"}
    for filename in (*files.values(), "manifest.json"):
        if (directory / filename).exists():
            raise FileExistsError(f"refusing to overwrite {directory / filename}")
    for name, filename in files.items():
        (directory / filename).write_bytes(parts[name].data)
    (directory / "manifest.json").write_text(json.dumps(info, indent=2) + "\n")


def probe_qemu(parts, seconds, qemu, guest_dtb):
    with tempfile.TemporaryDirectory(prefix="gr4-qemu-") as temporary:
        directory = Path(temporary)
        (directory / "zImage").write_bytes(parts["kernel"].data)
        (directory / "initfs.squashfs").write_bytes(parts["initfs"].data)
        if guest_dtb == "original":
            (directory / "gr4.dtb").write_bytes(parts["device_tree"].data)
        command = [
            qemu, "-M", "virt", "-cpu", "cortex-a7", "-m", "256M",
            "-display", "none", "-serial", "none", "-monitor", "stdio",
            "-nic", "none", "-no-reboot", "-kernel", "zImage",
            "-initrd", "initfs.squashfs", "-append",
            "console=ttyAMA0,115200 earlycon=pl011,0x09000000 root=/dev/ram0 ro loglevel=8",
        ]
        if guest_dtb == "original":
            command += ["-dtb", "gr4.dtb"]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            time.sleep(seconds)
            if process.poll() is not None:
                output, _ = process.communicate(timeout=3)
                raise RuntimeError(f"QEMU exited {process.returncode}: {output[-1000:]!r}")
            output, _ = process.communicate(
                input=b'pmemsave 0x40000000 0x4000000 "ram.bin"\nquit\n', timeout=25
            )
        except (Exception, KeyboardInterrupt):
            if process.poll() is None:
                process.kill()
                process.communicate()
            raise

        dump = directory / "ram.bin"
        if not dump.exists() or dump.stat().st_size != 64 * 1024 * 1024:
            raise RuntimeError(f"QEMU did not produce a complete RAM snapshot: {output[-1000:]!r}")
        memory = dump.read_bytes()
        # The first occurrence is a format string in the kernel image; the
        # rendered line in the printk ring has a numeric CPU identifier.
        rendered = None
        for candidate in re.finditer(rb"Booting Linux on physical CPU 0x[0-9a-fA-F]+", memory):
            rendered = candidate
        log = memory[rendered.start():rendered.start() + 1024 * 1024] if rendered else b""
        milestones = {
            "kernel_started": b"Linux version " in log,
            "qemu_virt_detected": b"Machine model: linux,dummy-virt" in log,
            "socionext_dtb_detected": b"Machine model: Socionext SC2000A" in log,
            "squashfs_found": b"RAMDISK: squashfs filesystem found" in log,
            "root_mounted": b"VFS: Mounted root (squashfs filesystem)" in log,
            "init_exec_attempted": b"Run /sbin/init as init process" in log,
            "init_exec_failure_seen": b"Failed to execute /sbin/init" in log,
            "mmc_reset_timeout_seen": b"Reset 0x1 never completed" in log,
            "mmc_irq_failure_seen": b"Failed to request IRQ" in log,
            "kernel_panic_seen": b"Kernel panic - not syncing:" in log,
        }
        return {"qemu_machine": "virt", "guest_device_tree": guest_dtb,
                "cpu": "cortex-a7", "seconds": seconds,
                "guest_ram_mib": 256, "milestones": milestones,
                "serial_output": False, "camera_ui_shown": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local GR IV update or decoded payload")
    parser.add_argument("--extract", type=Path, metavar="DIRECTORY",
                        help="write zImage, device tree, initfs, and manifest locally")
    parser.add_argument("--probe", action="store_true", help="run a bounded, offline QEMU boot probe")
    parser.add_argument("--guest-dtb", choices=("virt", "original"), default="virt",
                        help="QEMU-generated or original GR IV device tree for the boot probe")
    parser.add_argument("--seconds", type=int, default=5, help="guest run time before RAM snapshot (1–30)")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 30:
        parser.error("--seconds must be between 1 and 30")
    try:
        payload, kind, version, source_hash = load_payload(args.source)
        parts = find_parts(payload)
        info = manifest(args.source, kind, version, source_hash, payload, parts)
        if args.extract:
            write_parts(args.extract, parts, info)
        if args.probe:
            qemu = shutil.which("qemu-system-arm")
            if not qemu:
                raise RuntimeError("qemu-system-arm is required for --probe")
            info["qemu_probe"] = probe_qemu(parts, args.seconds, qemu, args.guest_dtb)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"error: {error}\n")
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
