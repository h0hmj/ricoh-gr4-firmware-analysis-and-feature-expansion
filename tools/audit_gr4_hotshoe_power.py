#!/usr/bin/env python3
"""Pinned GR IV hotshoe shutdown/startup evidence audit, entirely offline.

Validates code windows, shutdown-step routing, A6 parameter construction and
the direct callers of the raw transport. Does not execute firmware or send
commands. Checks native SHELLCMD registration; lamp-side wake capability and
live execution of the hotshoe commands remain unverified.
"""

import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import re
import struct

from audit_gr4_hotshoe import audit as audit_hotshoe
from audit_sd_shell_path import audit as audit_shell
from audit_xpan_paths import file_offset, require


PINS = (
    ('shutdown_step_name', 0x53663a38, 0x44, '2694224ee069ebbd7ba60b19788c8e7f8377aeca0a0fe50b00b83571b38d581c'),
    ('shutdown_step_plan', 0x53660b2c, 0x90, '077ac2c43af785470b06c7cd2964197f4a2349cc1891e80767476749775caa20'),
    ('shutdown_step_dispatch', 0x5365c6bc, 0x194, '8eaa2bb39b56f48ebf636cce3be39feb11787b4b8ded0467a9f315bbe0a677ab'),
    ('shutdown_flash_parameter_request', 0x5365b8f4, 0x128, '09918c7c9b9d0acf919655ae77627a032dc6d3c8c028749e7fb63e5836b600b8'),
    ('hotshoe_lifecycle_stubs', 0x53a72970, 0x18, '5a03cd1a67adb4688aa4c7de82c57aa32b6452cf75dff914877d42954b101837'),
    ('hotshoe_close', 0x53a72fcc, 0xc0, '91383450829aa3989a355b4bb12c7d3ca23e8a41e2dfd726cabd561fafc1a1d7'),
    ('hotshoe_raw_test_transfer', 0x530603cc, 0x240, 'a5ac22d8426ea66e82951f5679f37f60307767721f437d143df2c1e21bc4ec1f'),
    ('hotshoe_test_buffer_transfer', 0x5306060c, 0x184, 'a28385dfec033662532445e256acfaa5c4e1fe2ea670b6fc25e6dda2f8031120'),
    ('hotshoe_vtable', 0x543540e8, 0x20, '8c46302d18d8f703bb8294b09bdcdfd877f31f8422f35dc4df8ff1727cdc16fc'),
    ('hotshoe_check_disable_command', 0x53060358, 0x74, '23546368668a7d11944ac62fb56c3a8abb18ccdafb43bccc6813b979d4710e0e'),
    ('hotshoe_adc_command', 0x53060794, 0x34, '1360223b6814251367a6402b14fbf85d35fdef3859b191d2c75ff5688b89e42e'),
    ('decimal_argument_parser', 0x53155f8c, 0xc, 'f238386e67a019f468ba25b7e827d96ed231a4f262d6bfdc908d08706f33a220'),
)

EDGES = (
    (0x53663a6c, 0x53663f54),
    (0x5365c6f8, 0x5365c7f0),
    (0x5365c7f4, 0x5365b8f4),
    (0x5365b980, 0x5377008c),
    (0x53770d44, 0x53771364),
    (0x5377138c, 0x53772890),
    (0x537713a0, 0x53770a30),
    (0x53060544, 0x53a72fcc),
    (0x53060550, 0x53a72e60),
    (0x53060570, 0x53a7308c),
    (0x53060578, 0x53a72fcc),
)

TRANSPORT_CALLERS = (
    0x53060570, 0x53060748, 0x53a73334, 0x53a73404,
    0x53a734cc, 0x53a734f0, 0x53a73514, 0x53a73538,
    0x53a73600, 0x53a7371c, 0x53a73780, 0x53a737a0,
    0x53a737c0, 0x53a737e0, 0x53a73800, 0x53a73834,
)


def branch_target(word, site):
    if word & 0x0e000000 != 0x0a000000 or word >> 28 == 15:
        raise ValueError(f'not ARM B/BL at {site:#x}')
    displacement = word & 0xffffff
    if displacement & 0x800000:
        displacement -= 0x1000000
    return site + 8 + 4 * displacement


def immediate_mov(raw, address):
    word = struct.unpack_from('<I', raw, file_offset(address))[0]
    if word & 0x0fff0000 != 0x03a00000:
        raise ValueError(f'not immediate ARM MOV at {address:#x}')
    rotation = 2 * ((word >> 8) & 15)
    value = word & 255
    value = ((value >> rotation) | (value << ((32 - rotation) % 32))) & 0xffffffff
    return value


def audit(raw):
    baseline = audit_hotshoe(raw)
    with redirect_stdout(io.StringIO()):
        audit_shell(raw)
    pins = []
    for role, address, length, expected in PINS:
        digest = hashlib.sha256(raw[file_offset(address):file_offset(address) + length]).hexdigest()
        if digest != expected:
            raise ValueError(f'changed {role} at {address:#x}')
        pins.append(dict(role=role, address=hex(address), length=length, sha256=digest))
    edges = []
    for site, target in EDGES:
        word = struct.unpack_from('<I', raw, file_offset(site))[0]
        actual = branch_target(word, site)
        if actual != target:
            raise ValueError(f'changed branch at {site:#x}')
        edges.append(dict(site=hex(site), target=hex(target), condition=word >> 28))
    name = 'SHUT_DOWN_STEP_PREPARE_SHUT_DOWN_START'
    require(raw, file_offset(0x53eb3a90), name.encode() + b'\0', name)
    require(raw, file_offset(0x53eb25b4), struct.pack('<I', 0x5365c6bc), 'shutdown event vtable slot')
    parameter = immediate_mov(raw, 0x5365b954)
    request = immediate_mov(raw, 0x5365b964)
    state = immediate_mov(raw, 0x5377139c)
    raw_mode = immediate_mov(raw, 0x5306054c)
    if (parameter, request, state, raw_mode) != (0x100, 15, 18, 1):
        raise ValueError('shutdown/raw-mode constants changed')
    constructor_vtable = struct.unpack_from('<I', raw, file_offset(0x53a72e5c))[0]
    if constructor_vtable != 0x543540f0:
        raise ValueError('unexpected HotshoeControl vtable')
    lifecycle = struct.unpack_from('<5I', raw, file_offset(constructor_vtable))
    if lifecycle != (0x53a72970, 0x53a729a4, 0x53a72974, 0x53a729c0, 0x53a7297c):
        raise ValueError('lifecycle vtable changed')
    callers = []
    for index, (word,) in enumerate(struct.iter_unpack('<I', raw[0x17d10:0x17d10 + 0x1400000])):
        site = 0x53000000 + 4 * index
        if word & 0x0f000000 == 0x0b000000 and word >> 28 != 15:
            if branch_target(word, site) == 0x53a7308c:
                callers.append(site)
    if tuple(callers) != TRANSPORT_CALLERS:
        raise ValueError('raw transport direct BL callers changed')
    shell_at = raw.index(b'SHELLCMD')
    shell_length = struct.unpack_from('<I', raw, shell_at + 12)[0]
    shell_data = raw[shell_at + 16:shell_at + 16 + shell_length]
    shell_hash = hashlib.sha256(shell_data).hexdigest()
    if (shell_at, shell_length, shell_hash) != (
            0x2e89810, 41664, 'd42cc163675ffc69e1556482e28bfd762bf05eb064e1bb102702ecac891e18c1'):
        raise ValueError('SHELLCMD text registry changed')
    rows = list(re.finditer(rb'([A-Za-z_][A-Za-z_0-9]*) +, +0x([0-9a-fA-F]{8})', shell_data))
    if len(rows) != 651:
        raise ValueError('unexpected shell command count')
    commands = []
    for index, name, handler in (
            (626, 'HotshoeCheckDisable', 0x53060358),
            (627, 'ExeHotshoeCommType1', 0x530603cc),
            (628, 'HotshoeCommType1', 0x5306060c),
            (629, 'HotshoeGetHotDetAd', 0x53060794)):
        row = rows[index]
        if (row[1].decode(), int(row[2], 16)) != (name, handler):
            raise ValueError(f'shell entry changed: {name}')
        commands.append(dict(index=index, name=name, handler=hex(handler),
                             decoded_text_offset=hex(shell_at + 16 + row.start())))
    if immediate_mov(raw, 0x53155f90) != 10:
        raise ValueError('numeric argument base changed')
    parser_branch = struct.unpack_from('<I', raw, file_offset(0x53155f94))[0]
    if branch_target(parser_branch, 0x53155f94) != 0x5315a1e0:
        raise ValueError('decimal parser tail call changed')
    return {
        'schema': 'gr4-hotshoe-power-static-audit-v2',
        'sample_sha256': baseline['sample_sha256'],
        'baseline_windows': len(baseline['baseline_pins']) + len(baseline['additional_pins']),
        'additional_pins': pins, 'additional_edges': edges,
        'shutdown': {'step': '0x601', 'step_name': name,
                     'parameter': hex(parameter), 'accessory_request': request,
                     'camera_state': state, 'candidate_wire_bytes': [0xa6, parameter >> 8, parameter & 255]},
        'raw_test_transfer': {'function': '0x530603cc', 'mode': raw_mode,
                              'normal_detection_called_in_body': False,
                              'native_command': 'ExeHotshoeCommType1',
                              'static_registration_verified': True,
                              'runtime_entry_verified': False},
        'shell_registry': {'decoded_offset': hex(shell_at), 'text_length': shell_length,
                           'text_sha256': shell_hash, 'total_entries': len(rows),
                           'hotshoe_commands': commands, 'numeric_argument_base': 10,
                           'candidate_c0_query': 'ExeHotshoeCommType1 192 0 1',
                           'buffer_c0_sequence': ['HotshoeCommType1 0 0 0',
                                                  'HotshoeCommType1 1 192 1',
                                                  'HotshoeCommType1 2 0']},
        'hotshoe_lifecycle_vtable': [hex(value) for value in lifecycle],
        'transport_direct_bl_callers': [hex(site) for site in callers],
        'camera_accessed': False, 'firmware_executed': False,
        'limits': ['A6 field units and lamp-side hard-off versus sleep are unknown.',
                   'Candidate wire bytes come from a static chain, not an electrical capture.',
                   'Direct ARM BL scan does not exclude indirect or Thumb callers.',
                   'Native hotshoe entries are statically registered but have not been run on a camera.',
                   'A working wake signal/command is not established.'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists')
    try:
        report = audit(args.image.read_bytes())
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        print(f"Verified {report['baseline_windows']} baseline windows, {len(PINS)} new windows, "
              f"{len(EDGES)} edges and {len(TRANSPORT_CALLERS)} transport callers; {args.output}")
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
