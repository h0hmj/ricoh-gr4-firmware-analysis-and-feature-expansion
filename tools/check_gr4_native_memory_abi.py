#!/usr/bin/env python3
"""Execute pinned native dispatcher instructions with simulated OS operations.

Only argument decoding is tested. Allocation, context checks and cache work
are intercepted, so this cannot prove real execution-memory ownership,
cache coherence, scheduling, or a camera deployment path.
"""

import argparse
import ctypes
import json
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR

from audit_gr4_native_memory_abi import audit
from audit_xpan_paths import file_offset


PARAM = 0x60001000
OUT = 0x60001100
ALLOCATED = 0x59100000
STOP = 0x60002000


def check_host_cache_access():
    # Unicorn 2.1.4 falls back to CTR_EL0 after a failed Darwin sysctl.
    # This host traps that instruction; reject before initializing the engine.
    if sys.platform != 'darwin':
        return
    libc = ctypes.CDLL(None, use_errno=True)
    query = libc.sysctlbyname
    query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                     ctypes.c_void_p, ctypes.c_size_t]
    query.restype = ctypes.c_int
    value = ctypes.c_size_t()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    if query(b'hw.cachelinesize', ctypes.byref(value), ctypes.byref(size), None, 0) != 0 or value.value == 0:
        raise RuntimeError('Host cache information is unavailable. Run this local-only test outside the restricted sandbox.')


def run(raw, operation, words, allocation=ALLOCATED):
    check_host_cache_access()
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x53087000, 0x2000)
    uc.mem_write(0x53087000, raw[file_offset(0x53087000):file_offset(0x53089000)])
    uc.mem_map(0x60000000, 0x3000)
    uc.mem_write(PARAM, struct.pack('<' + 'I' * len(words), *words))
    uc.mem_write(OUT, struct.pack('<I', 0xDEADBEEF))
    uc.reg_write(UC_ARM_REG_SP, 0x60000F00)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    uc.reg_write(UC_ARM_REG_R0, PARAM)
    uc.reg_write(UC_ARM_REG_R1, operation)
    events = []

    def intercept(machine, address, _size, _context):
        if address == 0x53087960:
            events.append({'operation': 'simulated context check'})
            value = 0
        elif address == 0x53087F98:
            events.append({'operation': 'simulated allocation',
                           'blocks': machine.reg_read(UC_ARM_REG_R0),
                           'flags': machine.reg_read(UC_ARM_REG_R1)})
            value = allocation
        elif address == 0x5308812C:
            events.append({'operation': 'simulated release',
                           'address': machine.reg_read(UC_ARM_REG_R0)})
            value = 0
        elif address in (0x53087CFC, 0x53087C78):
            events.append({'operation': 'simulated data cache' if address == 0x53087CFC else 'simulated instruction cache',
                           'address': machine.reg_read(UC_ARM_REG_R0),
                           'length': machine.reg_read(UC_ARM_REG_R1)})
            value = 0
        else:
            return
        machine.reg_write(UC_ARM_REG_R0, value)
        machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, intercept)
    uc.emu_start(0x53088470, STOP, timeout=1000000, count=10000)
    if uc.reg_read(UC_ARM_REG_PC) != STOP:
        raise AssertionError('dispatcher did not return within the instruction budget')
    return {'return_r0': uc.reg_read(UC_ARM_REG_R0),
            'output_word': struct.unpack('<I', uc.mem_read(OUT, 4))[0], 'events': events}


def check(raw):
    evidence = audit(raw)
    cases = []
    for size in (1, 2048, 2049, 8192):
        result = run(raw, 0x02000411, [0, size, 0x20, OUT])
        assert result == {'return_r0': 0, 'output_word': ALLOCATED, 'events': [
            {'operation': 'simulated context check'},
            {'operation': 'simulated allocation', 'blocks': (size + 2047) // 2048, 'flags': 0x300}]}
        cases.append({'case': 'allocation byte count ' + str(size), **result})
    result = run(raw, 0x02000411, [0, 1, 0x20, OUT], allocation=0)
    assert result['return_r0'] == 0xFFDF0000 and result['output_word'] == 0
    cases.append({'case': 'allocation failure', **result})
    result = run(raw, 0x02000411, [0, 0, 0x20, OUT])
    assert result['return_r0'] == 0xFFEF0000 and len(result['events']) == 1
    cases.append({'case': 'zero size rejected', **result})
    result = run(raw, 0x02010111, [ALLOCATED])
    assert result['return_r0'] == 0 and result['events'][-1] == {
        'operation': 'simulated release', 'address': ALLOCATED}
    cases.append({'case': 'release exact address', **result})
    result = run(raw, 0x01010311, [ALLOCATED, 4096, OUT])
    assert result == {'return_r0': 4096, 'output_word': ALLOCATED, 'events': [
        {'operation': 'simulated context check'},
        {'operation': 'simulated data cache', 'address': ALLOCATED, 'length': 4096},
        {'operation': 'simulated instruction cache', 'address': ALLOCATED, 'length': 4096}]}
    cases.append({'case': 'cache-only order and nonzero success return', **result})
    result = run(raw, 0x7FFFFFFF, [0, 0, 0, OUT])
    assert result['return_r0'] == 0xFFF60000 and len(result['events']) == 1
    cases.append({'case': 'unsupported ID rejected', **result})
    return {'sample_sha256': evidence['sample_sha256'], 'cases_passed': len(cases),
            'execution': 'original ARM dispatcher; intercepted OS/context/cache functions',
            'camera_accessed': False, 'real_allocation_or_cache_verified': False,
            'camera_installable': False, 'cases': cases}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.sample.read_bytes()), indent=2))
    except RuntimeError as error:
        parser.exit(1, str(error) + '\n')
