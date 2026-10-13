#!/usr/bin/env python3
"""Check v5 macro control flow with synthetic native calls and lamp replies.

This is not a camera, electrical, or GF-2 emulator. It checks the exact frame
sequence, reply gating, failure restoration and restart behavior of this macro.
"""
import argparse
import hashlib
import json
from pathlib import Path

from validate_sd_batch_probe import FlowCheck


LOG = 'C:\\HSM5.TXT'


class InterruptedTransfer(Exception):
    pass


class ManualPowerFlow(FlowCheck):
    def __init__(self, replies=None, kind=17, fail_call=None,
                 interrupt_frame=None, existing=False, initial_disabled=0):
        super().__init__()
        self.replies = {0: 165, 2: 0, 4: 0, 6: 165}
        if replies is not None:
            self.replies.update(replies)
        self.kind = kind
        self.fail_call = fail_call
        self.interrupt_frame = interrupt_frame
        self.disabled = initial_disabled
        self.tx = [0] * 256
        self.rx = [0] * 256
        self.frames = []
        if existing:
            self.files[LOG] = bytearray(b'PREEXISTING')

    def send(self, command):
        self.commands.append(command)
        self.env['result'] = 0
        if len(self.commands) == self.fail_call:
            self.env['result'] = -7
            return
        words = command.split()
        if words[0] == 'SYS_buildinfo':
            assert len(words) == 1
        elif words[0] == 'HotshoeCheckDisable':
            assert words[1] in ('0', '1') and len(words) == 2
            self.disabled = int(words[1])
        elif words[0] == 'HotshoeCommType1':
            action = int(words[1])
            if action == 0:
                index, value = map(int, words[2:])
                assert index in (0, 1) and value in (0, 1, 2)
                self.tx[index] = value
            elif action == 1:
                opcode, count = map(int, words[2:])
                assert self.disabled == 1
                expected_count = {192: 1, 193: 2, 194: 2, 166: 2}[opcode]
                assert count == expected_count
                step = self.env['s']
                frame = {'step': step, 'command': opcode, 'tx': self.tx[:count]}
                self.frames.append(frame)
                if len(self.frames) == self.interrupt_frame:
                    raise InterruptedTransfer()
                self.rx = [0] * 256
                if opcode == 192:
                    assert self.tx[0] == 0
                    self.rx[0] = self.replies[step]
                elif opcode == 193:
                    assert self.env['a'] == 165 and self.tx[:2] == [0, 0]
                    self.rx[:2] = [self.kind, 0]
                elif opcode == 194:
                    assert self.env['a'] == 165 and self.tx[:2] == [0, 0]
                    self.rx[:2] = [1, 0]
                else:
                    assert opcode == 166 and self.tx[:2] == [1, 2]
                self.tx = [0] * 256
            elif action == 2:
                index = int(words[2])
                assert index in (0, 1) and len(words) == 3
                self.env['result'] = self.rx[index]
            else:
                raise AssertionError('Unexpected buffer action')
        else:
            raise AssertionError('Unexpected native command: ' + command)


def validate(program):
    assert program.isascii()
    assert not any(line.strip().startswith(('call ', 'while '))
                   for line in program.splitlines())
    normal = ManualPowerFlow().run(program)
    assert [f['step'] for f in normal.frames] == [0, 1, 2, 3, 4, 6, 7, 8]
    assert [f['command'] for f in normal.frames] == [192, 193, 192, 166, 192, 192, 193, 194]
    assert normal.disabled == 0
    assert b'ALL STEPS COMPLETE' in normal.files[LOG]
    assert len(normal.frames) == 8
    variants = {
        'manual-off C0 responder': dict(replies={2: 165, 4: 165}),
        'responds only after A6': dict(replies={4: 165}),
        'manual-on still has no A5': dict(replies={6: 0}),
        'manual-off C9 byte': dict(replies={2: 201, 4: 201}),
        'baseline lacks A5': dict(replies={0: 0}),
        'unaccepted baseline kind': dict(kind=99),
        'kind 0x12': dict(kind=18),
        'existing marker': dict(existing=True, initial_disabled=1),
    }
    for name, options in variants.items():
        model = ManualPowerFlow(**options).run(program)
        assert model.disabled == 0, name
        if name == 'existing marker':
            assert model.commands == ['HotshoeCheckDisable 0']
            assert model.files[LOG] == b'PREEXISTING'
        elif name in ('baseline lacks A5', 'unaccepted baseline kind'):
            assert b'ABORT step' in model.files[LOG]
            assert not any(f['command'] == 166 for f in model.frames)
        elif name == 'manual-on still has no A5':
            assert not any(f['step'] in (7, 8) for f in model.frames)
            assert b'ALL STEPS COMPLETE' in model.files[LOG]
        else:
            assert b'ALL STEPS COMPLETE' in model.files[LOG]
    # The responder variant executes conditional C2, so check both paths.
    failure_checks = 0
    for replies in ({}, {2: 165, 4: 165}):
        good = ManualPowerFlow(replies=replies).run(program)
        for position in range(1, len(good.commands) + 1):
            model = ManualPowerFlow(replies=replies, fail_call=position).run(program)
            assert model.commands[-1] == 'HotshoeCheckDisable 0'
            assert model.disabled == 0
            if position > 1:
                assert b'ABORT step' in model.files[LOG]
            failure_checks += 1
    interrupted = 0
    responder = ManualPowerFlow(replies={2: 165, 4: 165}).run(program)
    for position in range(1, len(responder.frames) + 1):
        model = ManualPowerFlow(replies={2: 165, 4: 165}, interrupt_frame=position)
        try:
            model.run(program)
        except InterruptedTransfer:
            step = model.frames[-1]['step']
            tail = f'BEGIN step:\r\n{step}\r\n'.encode()
            assert model.files[LOG].endswith(tail)
            assert not model.handles
        else:
            raise AssertionError('Expected transfer interruption')
        restart = ManualPowerFlow(initial_disabled=model.disabled)
        restart.files[LOG] = model.files[LOG].copy()
        restart.run(program)
        assert restart.disabled == 0
        assert restart.commands == ['HotshoeCheckDisable 0']
        assert restart.files[LOG] == model.files[LOG]
        interrupted += 1
    return {
        'schema': 'gr4-hotshoe-manual-power-host-flow-v5',
        'normal_native_calls': len(normal.commands),
        'normal_frames': len(normal.frames),
        'responder_frames': len(responder.frames),
        'explicit_wait_ms': 103000,
        'native_failure_positions_checked': failure_checks,
        'nonreturn_frame_positions_checked': interrupted,
        'variants': list(variants),
        'only_a6_payload': [1, 2],
        'later_boot_restore_then_skip': True,
        'camera_executed': False,
        'firmware_emulated': False,
        'limits': 'Synthetic host flow only; no evidence of lamp state, wake, electrical timing or camera interpreter execution.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('script', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.script.read_bytes()
    record = validate(data.decode('ascii'))
    record['source_sha256'] = hashlib.sha256(data).hexdigest()
    with args.output.open('x') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    print(json.dumps(record, ensure_ascii=False))


if __name__ == '__main__':
    main()
