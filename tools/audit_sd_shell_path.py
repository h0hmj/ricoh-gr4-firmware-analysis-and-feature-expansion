#!/usr/bin/env python3
# Copyright 2026 radium-wang
# License: see LICENSE (earlier Apache-2.0 grants remain in force)
"""Read-only audit of the GR IV 1.11.10.7 TTL sendln -> shell path.

Checks known bytes and call targets in a local decoded image. It does not
execute camera code, write an SD card, or produce an installable update.
"""

import argparse
import hashlib
import re
import struct
from pathlib import Path

from audit_xpan_paths import EXPECTED_SHA256, file_offset, require


def read_word(data, address):
    return struct.unpack_from("<I", data, file_offset(address))[0]


def require_branch(data, address, target, link=True):
    word = read_word(data, address)
    opcode = 0x0B000000 if link else 0x0A000000
    if word & 0x0F000000 != opcode:
        raise ValueError(f"expected ARM {'BL' if link else 'B'} at {address:#x}")
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    actual = address + 8 + displacement * 4
    if actual != target:
        raise ValueError(f"branch at {address:#x}: {actual:#x}, expected {target:#x}")


def audit(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("This audit only supports the original GR IV 1.11.10.7 decoded sample")

    require(data, 0x138B680, b"sendln\0", "sendln keyword")
    require(data, file_offset(0x53B1CA04), bytes.fromhex("4e 30 a0 e3"),
            "sendln token ID 0x4e")
    require(data, file_offset(0x53B1A7D0), struct.pack("<I", 0x53B1AB0C),
            "sendln dispatch table entry")
    require_branch(data, 0x53B1AB0C, 0x53B197EC)
    require_branch(data, 0x538F0DFC, 0x53B151BC)
    require_branch(data, 0x53B15224, 0x53B157E8)

    # Startup code copies 0x5437B640 to writable data at 0x55000000.
    callback_rom = 0x5437B640 + (0x5501A33C - 0x55000000)
    require(data, file_offset(callback_rom), struct.pack("<I", 0x538EF3C8),
            "startup script send callback")
    require(data, file_offset(callback_rom + 0x30), struct.pack("<I", 0x538EF9F0),
            "startup script response callback")
    require(data, file_offset(0x53B19830), bytes.fromhex("33 ff 2f e1"),
            "sendln invokes callback")
    require_branch(data, 0x53B19834, 0x53B18018)
    require(data, file_offset(0x53EA2FC4), b"result\0", "result variable")
    require(data, file_offset(0x5437346C), b"inputstr\0", "inputstr variable")
    require_branch(data, 0x538EF410, 0x538EEFF4, link=False)
    require(data, file_offset(0x538EF1C8), bytes.fromhex("3c ff 2f e1"),
            "shell invokes matched command handler")
    require(data, file_offset(0x538EF2DC), bytes.fromhex("00 00 e0 e3"),
            "shell failure return -1")
    require(data, file_offset(0x530548C0), bytes.fromhex("00 00 a0 e3"),
            "SYS_buildinfo normal return 0")

    shell_at = data.index(b"SHELLCMD")
    shell_length = struct.unpack_from("<I", data, shell_at + 12)[0]
    rows = dict(re.findall(rb"([A-Za-z_][A-Za-z_0-9]*) +, +0x([0-9a-fA-F]{8})",
                           data[shell_at + 16:shell_at + 16 + shell_length]))
    if rows.get(b"SYS_buildinfo") != b"53054854":
        raise ValueError("SYS_buildinfo shell-table mapping differs")
    if rows.get(b"lcmd") != b"5301c5b8":
        raise ValueError("lcmd shell-table mapping differs")
    require(data, file_offset(0x53EA38FC), b'issue ifcmd "ExecLinuxCommand"\0',
            "Linux command-bridge description")
    require_branch(data, 0x5301C714, 0x535CFF8C)
    require(data, file_offset(0x5301C73C), bytes.fromhex("00 00 a0 e3"),
            "lcmd returns 0 without propagating the bridge result")
    if rows.get(b"is_linux_boot") != b"53021d18":
        raise ValueError("is_linux_boot shell-table mapping differs")
    require_branch(data, 0x53021D24, 0x535D70A0)
    require(data, file_offset(0x53021D2C), bytes.fromhex("03 10 a0 e3"),
            "is_linux_boot queries event bits 1 and 2")
    require(data, file_offset(0x53021D34), bytes.fromhex("00 20 a0 e3"),
            "is_linux_boot does not request event-bit output")
    require_branch(data, 0x53021D3C, 0x538DB6B4)
    require(data, file_offset(0x53021D40), bytes.fromhex("00 a8 9d e8"),
            "is_linux_boot returns the query result unchanged")
    require(data, file_offset(0x53FE1668), struct.pack("<I", 0),
            "is_linux_boot uses a zero-timeout poll")
    require(data, file_offset(0x538DB750), bytes.fromhex("00 20 a0 e3"),
            "WaitAnd queries all requested event bits")
    require_branch(data, 0x538DB754, 0x53067284)
    require(data, file_offset(0x538DB774), bytes.fromhex("10 5f 6f e1"),
            "WaitAnd converts OS success into a boolean")
    require(data, file_offset(0x538DB7AC), bytes.fromhex("05 00 a0 e1"),
            "WaitAnd returns that boolean")
    require(data, file_offset(0x535D7148), bytes.fromhex("0a 11 a0 e3"),
            "Linux command bridge waits on event mask 0x80000002")
    require_branch(data, 0x535D7154, 0x538DB594)
    require_branch(data, 0x535CFFBC, 0x535D7118)
    require(data, file_offset(0x535CFFC0), bytes.fromhex("00 00 50 e3"),
            "Linux command bridge checks readiness before dispatch")
    if rows.get(b"llog_export") != b"53016d6c":
        raise ValueError("llog_export shell-table mapping differs")
    require(data, file_offset(0x53E9E478), b"export linux log to sd card.\0",
            "Linux log export description")
    require(data, file_offset(0x53E9E498), b"C:\\linux%02d.log\0",
            "Linux log export output paths on SD")
    require(data, file_offset(0x53E9E4B8), b"C:\0",
            "Linux log export output drive")
    require_branch(data, 0x53016E5C, 0x53A7E208)
    require_branch(data, 0x53016E7C, 0x53A7E364)
    require(data, file_offset(0x53016E54), bytes.fromhex("0a 00 a0 e1"),
            "Linux log export queries log manager")
    require(data, file_offset(0x53016DF4), bytes.fromhex("b8 14 0e e3"),
            "Linux log export uses SD drive string")
    require(data, file_offset(0x53016DD8), bytes.fromhex("43 01 52 e1"),
            "Linux log export validates argument count")
    require(data, file_offset(0x53016E48), bytes.fromhex("01 50 a0 e3"),
            "Linux log export starts at index 1")
    require(data, file_offset(0x53016ED8), bytes.fromhex("06 00 55 e3"),
            "Linux log export stops before index 6")
    if rows.get(b"SYS_md") != b"53053a84":
        raise ValueError("SYS_md shell-table mapping differs")
    require(data, file_offset(0x53FE391C),
            b"<start address> [-e stop] [-s size] [-p parse] [-f filename] [-a]\0",
            "Memory read command usage")
    require(data, file_offset(0x53053B70), struct.pack("<I", 0x53053B74),
            "SYS_md size option dispatch")
    require(data, file_offset(0x53053B3C), struct.pack("<I", 0x53053C44),
            "SYS_md filename option dispatch")
    require(data, file_offset(0x53053C44), bytes.fromhex("08 80 94 e5"),
            "SYS_md takes filename from the next argument")
    require(data, file_offset(0x53053BD8), bytes.fromhex("09 10 a0 e1"),
            "SYS_md passes the read address as source")
    require(data, file_offset(0x53053BDC), bytes.fromhex("06 20 a0 e1"),
            "SYS_md passes explicit byte count")
    require_branch(data, 0x53053BE4, 0x538EF988)
    require_branch(data, 0x538EF9B4, 0x5383BEC4)
    require_branch(data, 0x53B1AA98, 0x53B187D4)
    require_branch(data, 0x53B188D0, 0x53B14DC4)
    require_branch(data, 0x53B1AAF4, 0x53B17388)
    require(data, file_offset(0x53B1746C), bytes.fromhex("04 10 a0 e1"),
            "str2code converts an empty/zero byte to zero")
    require(data, file_offset(0x5301C8EC), bytes.fromhex("74 40 c3 e5"),
            "lcmd_resp changes only the response-output byte")
    require(data, file_offset(0x53EA37A4), b"resp : \0",
            "Linux response logging prefix")
    require(data, file_offset(0x53298EA0), bytes.fromhex("8b 0f d0 e5"),
            "current aspect getter uses property offset 0xf8b")
    require(data, file_offset(0x5323F03C), bytes.fromhex("08 05 45 e3"),
            "imaging property singleton is in 0x5508xxxx")
    require(data, file_offset(0x538D077C), bytes.fromhex("14 00 90 e5"),
            "image calculator holder uses pointer offset 0x14")
    if b"XPAN_NO_SUCH_COMMAND" in rows:
        raise ValueError("probe's unknown command unexpectedly exists")
    print("Decoded payload SHA-256:", digest)
    print("sendln token 0x4e -> 0x53b197ec -> callback 0x538ef3c8")
    print("Callback -> shell dispatcher 0x538eeff4")
    print("Callback return is stored in TTL result; optional response in inputstr")
    print("Expected: SYS_buildinfo result 0; unknown command result -1")
    print("lcmd handler 0x5301c5b8 -> Linux bridge 0x535cff8c (dispatch only)")
    print("lcmd discards bridge status and returns 0; this cannot confirm Linux execution")
    print("is_linux_boot -> zero-timeout WaitAnd(bits 3): 1 = ready, 0 = not ready")
    print("llog_export reads the log manager and exports C:\\linux01.log ... linux05.log")
    print("SYS_md -s size -f filename -> source memory read -> filesystem file write")
    print("This is a static audit; device execution is established by independent SD readback.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_payload", type=Path)
    args = parser.parse_args()
    audit(args.decoded_payload.read_bytes())


if __name__ == "__main__":
    main()
