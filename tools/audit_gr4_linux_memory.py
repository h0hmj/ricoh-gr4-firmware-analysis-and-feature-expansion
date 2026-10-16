#!/usr/bin/env python3
"""Audit GR IV Linux/RTOS RAM partitioning offline; never patch an image or device.

Accepts only the pinned 1.11.10.7 payload. Requires Capstone; LZ4 decoding uses
the existing initfs reader. Reported pool addresses are RTOS virtual addresses;
initial section mappings are checked separately, not treated as capacity proof.
"""

import argparse
import gzip
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM

from audit_xpan_paths import EXPECTED_SHA256, file_offset, require
from gr4_firmware_parts import find_parts, load_payload, occurrences
from inspect_initfs_readonly import lz4_block

MIB = 1024 * 1024
POOL_INIT = 0x538DE8C0


def fdt_properties(blob):
    """Read properties and their blob offsets from the pinned flattened tree."""
    magic, total, start, strings, _reserve, version, *_ = struct.unpack_from('>10I', blob)
    if magic != 0xD00DFEED or total != len(blob) or version != 17:
        raise ValueError('unexpected FDT header')
    pos, stack, result = start, [], {}
    while pos < strings:
        token = struct.unpack_from('>I', blob, pos)[0]
        pos += 4
        if token == 1:
            end = blob.index(0, pos)
            stack.append(blob[pos:end].decode('ascii'))
            pos = (end + 4) & ~3
        elif token == 2:
            stack.pop()
        elif token == 3:
            length, name_offset = struct.unpack_from('>II', blob, pos)
            pos += 8
            name_at = strings + name_offset
            name = blob[name_at:blob.index(0, name_at)].decode('ascii')
            path = '/'.join(stack) or '/'
            result[path, name] = (blob[pos:pos + length], pos)
            pos = (pos + length + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            return result
        else:
            raise ValueError(f'unknown FDT token {token}')
    raise ValueError('missing FDT end token')


def kernel_config(kernel):
    # zImage contains a literal copy of the magic in its decoder, so check every
    # candidate rather than accepting the first byte match.
    for start in occurrences(kernel, bytes.fromhex('02214c18')):
        pos, output = start + 4, bytearray()
        while pos + 4 <= len(kernel):
            size = struct.unpack_from('<I', kernel, pos)[0]
            if output and size == len(output):  # Linux LZ4 uncompressed-size footer.
                break
            pos += 4
            if not 0 < size <= 9 * MIB or pos + size > len(kernel):
                break
            try:
                chunk = lz4_block(kernel[pos:pos + size])
            except (IndexError, ValueError):
                break
            if not 0 < len(chunk) <= 8 * MIB or len(output) + len(chunk) > 32 * MIB:
                break
            output.extend(chunk)
            pos += size
        if not output or pos + 4 > len(kernel) or struct.unpack_from('<I', kernel, pos)[0] != len(output):
            continue
        begin, end = output.find(b'IKCFG_ST'), output.find(b'IKCFG_ED')
        if begin < 0 or end <= begin:
            continue
        config = gzip.decompress(output[begin + 8:end]).decode('ascii')
        flags = {}
        for line in config.splitlines():
            if line.startswith('CONFIG_') and '=' in line:
                name, value = line.split('=', 1)
                flags[name] = value
            elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
                flags[line[2:-11]] = 'n'
        return flags, {
            'uncompressed_sha256': hashlib.sha256(output).hexdigest(),
            'config_sha256': hashlib.sha256(config.encode()).hexdigest(),
            'lz4_stream_zimage_offset': hex(start),
            'ikconfig_uncompressed_offset': hex(begin),
        }
    raise ValueError('could not validate LZ4 kernel and embedded configuration')


def pools(raw):
    """Follow immediate MOV/MOVW/MOVT arguments in unrolled pool setup code."""
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    registers, base, result = {}, None, []
    for ins in decoder.disasm(raw[file_offset(0x538E3924):file_offset(0x538E3C50)], 0x538E3924):
        ops = ins.operands
        if ins.mnemonic in ('mov', 'movw', 'movt'):
            dst = ins.reg_name(ops[0].reg)
            src = ops[1]
            value = src.imm if src.type == ARM_OP_IMM else registers.get(ins.reg_name(src.reg))
            if ins.mnemonic == 'movt':
                old = registers.get(dst)
                value = None if old is None else (old & 0xFFFF) | (value << 16)
            registers[dst] = None if value is None else value & 0xFFFFFFFF
        elif ins.mnemonic == 'str' and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            if ins.reg_name(mem.base) == 'sp' and mem.disp == 4:
                base = registers.get(ins.reg_name(ops[0].reg))
        elif ins.mnemonic == 'bl':
            if ops[0].imm == POOL_INIT:
                ident, size, name_at = (registers.get(r) for r in ('r1', 'r3', 'r2'))
                if any(v is None for v in (ident, size, name_at, base)):
                    raise ValueError('unresolved pool arguments')
                offset = file_offset(name_at)
                name = raw[offset:raw.index(0, offset)].decode('ascii')
                result.append(dict(id=ident, name=name, base=base, size=size,
                                   end=base + size, call_address=ins.address))
            for reg in ('r0', 'r1', 'r2', 'r3', 'ip'):
                registers[reg] = None
    if [p['id'] for p in result] != list(range(1, 16)):
        raise ValueError('unexpected pool list')
    if [(p['name'], p['base'], p['size']) for p in result[-2:]] != [
            ('IMAGE1', 0x5D8A0000, 0x22760000), ('IMAGE2', 0xA0000000, 0x40000000)]:
        raise ValueError('unexpected image-pool partition')
    table = struct.unpack_from('<4096I', raw, file_offset(0x53004000))
    for pool in result:
        for section in range(pool['base'] >> 20, (pool['end'] + MIB - 1) >> 20):
            d = table[section]
            if d & 3 != 2 or d & 0xFFF00000 != section << 20:
                raise ValueError('pool has a nonidentity initial mapping')
    return result


def region(base, size, **extra):
    return dict(base=hex(base), end_exclusive=hex(base + size), size_mib=size / MIB, **extra)


def audit(raw):
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise ValueError('unsupported firmware sample')
    require(raw, file_offset(0x538E3C44), bytes.fromhex('0131a0e3'), 'IMAGE2 size instruction')
    parts = find_parts(raw)
    props = fdt_properties(parts['device_tree'].data)
    for key in ('#address-cells', '#size-cells'):
        if props['/', key][0] != struct.pack('>I', 1):
            raise ValueError('unexpected root cell size')
    memory, memory_at = props['/memory', 'reg']
    banks = list(struct.iter_unpack('>II', memory))
    if banks != [(0x40000000, 0x03000000), (0x44F00000, 0x07000000)]:
        raise ValueError('unexpected Linux memory banks')
    bootargs = props['/chosen', 'bootargs'][0].rstrip(b'\0').decode()
    slram = re.search(r'slram=slram0,(0x[0-9a-f]+),\+(0x[0-9a-f]+)', bootargs)
    if not slram:
        raise ValueError('missing slram carveout')
    root_base, root_size = map(lambda value: int(value, 16), slram.groups())
    flags, config_info = kernel_config(parts['kernel'].data)
    pool_list = pools(raw)
    total = sum(size for _, size in banks)
    extra = 1024 * MIB - total
    image2 = pool_list[-1]
    new_size = image2['size'] - extra
    new_base = image2['base'] + new_size
    display = []
    for (path, name), (data, _) in props.items():
        if name == 'draw_addrss' and len(data) == 8:
            base, size = struct.unpack('>II', data)
            display.append(region(base, size, node=path,
                                  within_retained_IMAGE2=(image2['base'] <= base < base + size <= new_base)))
    conflicts = [region(root_base, root_size, role='slram root filesystem'),
                 region(0x4FF00000, MIB, role='RTOS/Linux shared fields'),
                 region(0x53000000, 0x02000000, role='RTOS initial read-only sections'),
                 region(0x55000000, 0x008372D4, role='RTOS initialized data and BSS'),
                 *[region(p['base'], p['size'], role=p['name']) for p in pool_list if p['base'] < 0x80000000]]
    return dict(
        sample_sha256=EXPECTED_SHA256,
        scope='offline static analysis; pool VAs have identity initial mappings; no hardware capacity measurement',
        components={name: part.describe() for name, part in parts.items()},
        linux=dict(banks=[region(*bank) for bank in banks], declared_ram_mib=total / MIB,
                   memory_reg_decoded_offset=hex(parts['device_tree'].offset + memory_at),
                   slram=region(root_base, root_size), bootargs=bootargs),
        kernel=dict(**config_info, settings={name: flags.get(name) for name in (
            'CONFIG_VMSPLIT_2G', 'CONFIG_PAGE_OFFSET', 'CONFIG_HIGHMEM',
            'CONFIG_ARM_LPAE', 'CONFIG_OF_RESERVED_MEM', 'CONFIG_FLATMEM', 'CONFIG_CMA_SIZE_MBYTES')}),
        rtos_pools=[region(p['base'], p['size'], id=p['id'], name=p['name'],
                           initialization_call=hex(p['call_address'])) for p in pool_list],
        naive_contiguous_1gib=dict(window=region(0x40000000, 1024 * MIB), conflicts=conflicts,
                                  safe=False),
        candidate_split_1gib=dict(
            status='design candidate, hardware safety unverified; no patch produced',
            additional_bank=region(new_base, extra), total_linux_ram_mib=1024,
            retained_IMAGE2=region(image2['base'], new_size),
            IMAGE2_capacity_reduction_percent=100 * extra / image2['size'],
            IMAGE2_size_instruction=dict(runtime_address='0x538e3c44',
                                         decoded_offset=hex(file_offset(0x538E3C44)),
                                         original_hex='0131a0e3'),
            display_configs=display,
            prerequisites=[
                'verify DDR controller windows and enabled capacity on the actual camera',
                'audit all IMAGE2 allocation sizes, minimum capacity and independent DMA users',
                'verify bootloader, Linux driver mappings and shared-memory address contracts',
                'validate cold boot, still/RAW/JPEG/burst/video/playback under the smaller pool',
                'establish recovery for a firmware that fails before normal update mode',
                'verify firmware repack/update integrity checks'],
        ), camera_memory_written=False, firmware_patched=False, camera_installable=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    payload, *_ = load_payload(args.source)
    print(json.dumps(audit(payload), indent=2))
