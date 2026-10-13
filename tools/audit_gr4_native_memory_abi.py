#!/usr/bin/env python3
"""Pin native memory-service ABI evidence offline; no camera I/O or patching."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

from audit_xpan_paths import EXPECTED_SHA256, file_offset, require
from audit_sd_shell_path import require_branch


ALLOCATOR_SLOT = 0x5539FF00  # Registry base 0x5539fef8 + service 2 * 4.
ALLOCATOR_VTABLE = 0x53FE17F0
ALLOCATOR_METHODS = (0x538DEB60, 0x538DEBAC, 0x538DDF48, 0x538DE2A4)


def audit(raw):
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise ValueError("unsupported firmware sample")
    require(raw, file_offset(ALLOCATOR_VTABLE),
            struct.pack("<4I", *ALLOCATOR_METHODS), "heap allocator vtable")
    require(raw, file_offset(ALLOCATOR_VTABLE+24), struct.pack('<I', 0x538DDF1C),
            'default allocation-origin predicate')
    svc_prefix = bytes.fromhex('0f002de90d00a0e100402de90cc09fe5060000ef0040bde810d08de21eff2fe1')
    require(raw, file_offset(0x53065A40), svc_prefix + struct.pack('<I',0x01010311),
            'cache maintenance SVC wrapper with its fixed operation')
    require(raw, file_offset(0x53065A8C), svc_prefix + struct.pack('<I',0x01000311),
            'cache geometry SVC wrapper with its fixed operation')
    for address, encoded, label in [
        (0x538DD620, "f83e0fe3393545e3000193e71eff2fe1", "registry lookup"),
        (0x538E0A44, "0510a0e10020a0e308c093e50430a0e1", "malloc arguments"),
        (0x538E0A80, "0510a0e10420a0e10c3093e5", "free arguments"),
        (0x538DE008, "08c00ae5", "malloc saves allocation origin eight bytes before result"),
        (0x538DE350, "083004e5", "free clears saved origin before kernel release"),
        (0x538DE390, "104f6fe140c8a0e1", "free success converts zero status with CLZ"),
        (0x538DE3A0, "a442a0e1", "free success boolean is CLZ(status) shifted by five"),
        (0x538DE3D0, "0400a0e1", "free returns its success boolean"),
        (0x538DE42C, "0040a0e30400a0e1", "free invalid origin returns zero"),
        (0x53088838, "702408e324d04de2082345e3", "service dispatcher registration address"),
        (0x5308884C, "08208de51100a0e3", "register service 0x11"),
        (0x530884B8, "113300e3013140e3030055e12a00000a", "cache operation ID and branch"),
        (0x530884FC, "003240e3030055e15200000a", "allocation operation ID and branch"),
        (0x530885B0, "113100e3013240e3030055e1", "release operation ID"),
        (0x53088574, "005096e5044096e5083096e50500a0e10410a0e1005083e5", "cache-only arguments"),
        (0x530887D4, "ebfdffeb0410a0e1edfdffeb000086e5", "byte rounding then block allocation"),
        (0x530882C4, "035085e0045084e5", "free increases available blocks"),
        (0x53087C90, "350f07ee", "local instruction-cache invalidate by address"),
        (0x53087D14, "3e0f07ee", "local data-cache clean/invalidate by address"),
    ]:
        require(raw, file_offset(address), bytes.fromhex(encoded), label)
    for address, target in [
        (0x538E0A3C, 0x538DD620), (0x538E0A78, 0x538DD620),
        (0x53088874, 0x53081724), (0x530885C4, 0x5308812C),
        (0x5308858C, 0x53087CFC), (0x53088598, 0x53087C78),
        (0x530887D4, 0x53087F88), (0x530887DC, 0x53087F98),
        (0x53088670, 0x53088890),
    ]:
        require_branch(raw, address, target)
    return {
        "sample_sha256": EXPECTED_SHA256,
        "allocator_registry_slot": hex(ALLOCATOR_SLOT),
        "allocator_vtable_candidate": hex(ALLOCATOR_VTABLE),
        "malloc_wrapper": {"address": "0x538e0a24", "r0": "byte count",
                           "return_r0": "allocated pointer or zero",
                           "dispatch": "service 2 vtable +8; (object, bytes, 0, caller)"},
        "free_wrapper": {"address": "0x538e0a60", "r0": "exact allocated pointer",
                         "dispatch": "service 2 vtable +12; (object, pointer, caller)",
                         "return_r0": "1 on successful nonnull free; 0 on failure",
                         "retry": "never retry a completed free; origin is cleared before kernel release"},
        "memory_service": {
            "registration": "0x53088834", "service_id": "0x11",
            "dispatcher": "0x53088470", "arguments": "r0=argument record, r1=operation ID",
            "allocate": {"operation_id": "0x02000411", "record_words":
                         ["zero input address", "positive byte count", "flags", "output pointer address"],
                         "notes": "allocates when input address is zero; otherwise VA-to-PA plus cache path"},
            "release": {"operation_id": "0x02010111", "record_words": ["allocated block base"]},
            "cache_only": {"operation_id": "0x01010311", "record_words":
                           ["address", "positive length", "output pointer address"],
                           "notes": "stores address to output; returns original length in r0"},
            "block_allocator": {"address": "0x53087f98", "r0_units": "2048-byte blocks"},
            "block_free": {"address": "0x5308812c", "cache_pair_context": "free, not allocation"},
        },
        "cache_helpers": {"data": "0x53087cfc", "instruction": "0x53087c78",
                          "arguments": "r0=address, r1=length",
                          "observed_steps": "64-byte D-cache lines, 32-byte I-cache lines",
                          "barriers_inside_helpers": False,
                          "cross_core_publication_verified": False},
        "cache_svc_wrappers": {
            "maintenance":"0x53065a40", "query":"0x53065a8c",
            "arguments":"r0=address, r1=length, r2=owned output pointer; fourth word unused",
            "transport":"push argument registers, svc #6 with fixed operation in ip",
            "query_output_words":["input address","page base","page size","D-cache line size","covered length"],
            "hardware_verified":False},
        "usb_or_sd_argument_adapter_verified": False,
        "owned_module_allocation_verified": False,
        "camera_installable": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.sample.read_bytes()), indent=2))
