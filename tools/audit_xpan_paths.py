#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only checks of the GR IV 1.11 crop/aspect firmware paths.

Offsets are for the decoded payload, never for an installable update package.
This script deliberately has no patch or camera I/O operation.
"""

import argparse
import hashlib
import struct
from pathlib import Path


EXPECTED_SHA256 = "c4e597c7c9ca1bc181b30e35139ed90a4fd876ddcca14f12be0e00b6702233ae"
RTOS_FILE_OFFSET = 0x17D10
RTOS_LOAD_ADDRESS = 0x53000000


def file_offset(address):
    return address - RTOS_LOAD_ADDRESS + RTOS_FILE_OFFSET


def require(data, offset, expected, description):
    actual = data[offset : offset + len(expected)]
    if actual != expected:
        raise ValueError(
            f"{description}: expected {expected.hex(' ')} at decoded offset "
            f"0x{offset:x}, got {actual.hex(' ')}"
        )


def audit(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(
            "This audit is mapped only for GR IV 1.11.10.7 decoded payload "
            f"{EXPECTED_SHA256}; supplied payload is {digest}"
        )

    markers = {
        0xDD1238: b"ChangeAspectRatio\0",
        0xDD12A8: b"ChangeCrop\0",
        0xDD5490: b"GetCropModeIcon\0",
        0xEB6DBC: b"35mm\0",
        0xEB6DC4: b"50mm\0",
        0xEC634C: b"LvChangeCrop\0",
        0xFBF39C: b"SetImageAspectRatio\0",
    }
    for offset, marker in markers.items():
        require(data, offset, marker, marker.decode("ascii").rstrip("\0"))

    magnifications = struct.unpack_from("<3f", data, 0xDD2920)
    if not (magnifications[0] == 1.0 and
            1.25 < magnifications[1] < 1.26 and
            1.76 < magnifications[2] < 1.78):
        raise ValueError("Existing crop magnification table differs from this audit")

    # ARM instruction: mov r4, #3 at the start of the crop cycle.
    require(data, file_offset(0x5325AF00), bytes.fromhex("03 40 a0 e3"),
            "three-entry crop cycle")
    # ARM instructions: cmp r3, #3; ldrls pc, [pc, r3, lsl #2].
    require(data, file_offset(0x5380D1EC), bytes.fromhex("03 00 53 e3"),
            "four-entry Makernote aspect metadata dispatch bound")
    require(data, file_offset(0x5380D1F0), bytes.fromhex("03 f1 9f 97"),
            "four-entry Makernote aspect metadata jump table")
    # The user-facing cycle reads only four explicit entries. An unknown ID
    # selects table index 5, outside those four entries.
    require(data, file_offset(0x5325AE58), bytes.fromhex("03 20 d3 e5"),
            "fourth aspect-cycle entry")
    require(data, file_offset(0x5325AE60), bytes.fromhex("05 00 a0 13"),
            "unknown aspect-cycle ID selects index 5")
    # A separate status-text renderer also bounds the aspect ID at 3.
    require(data, file_offset(0x534DF824), bytes.fromhex("03 00 50 e3"),
            "four-entry aspect status-text dispatch bound")
    require(data, file_offset(0x5339E990), bytes.fromhex("03 00 50 e3"),
            "four-entry FocusModel layout dispatch bound A")
    require(data, file_offset(0x5339E9B8), bytes.fromhex("03 00 50 e3"),
            "four-entry FocusModel layout dispatch bound B")
    require(data, file_offset(0x533983D8), bytes.fromhex("d3 01 00 03"),
            "existing crop icon ID 0x1D3")
    require(data, file_offset(0x53398404), bytes.fromhex("63 00 a0 e3"),
            "existing crop icon ID 0x63")
    require(data, file_offset(0x53398450), bytes.fromhex("2f 00 a0 03"),
            "existing crop icon ID 0x2F")

    print("Decoded payload SHA-256:", digest)
    print("Existing crop magnifications:", ", ".join(f"{v:.6f}×" for v in magnifications))
    print("Crop cycle at 0x5325AF00: three entries")
    print("Makernote aspect metadata dispatch at 0x5380D1EC: IDs 0–3 only; no pixel crop")
    print("Aspect cycle at 0x5325AE58: four entries; unknown ID reads index 5")
    print("Aspect status text at 0x534DF824: IDs 0–3 only")
    print("FocusModel layout at 0x5339E990/0x5339E9B8: IDs 0–3; full live image viewport unverified")
    print("Crop icon selector at 0x53398380 uses existing magnifications")
    print("The menu, live view, JPEG/DNG and icon resources are not patched.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_payload", type=Path)
    args = parser.parse_args()
    audit(args.decoded_payload.read_bytes())


if __name__ == "__main__":
    main()
