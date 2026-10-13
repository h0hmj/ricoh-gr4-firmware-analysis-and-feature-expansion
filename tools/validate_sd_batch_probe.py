#!/usr/bin/env python3
"""Offline flow checks for the generated probe with synthetic memory/files.

Not a camera emulator or a general TTL interpreter. It checks guarded reads,
zero-byte decoding, repeat-run protection, and temporary-setting restoration.
"""
import ast
import re
import shlex
import struct

from build_sd_batch_probe import FIXED, build


class FlowCheck:
    def __init__(self, old_response=0, bad_pointer=False, bad_size=False,
                 bad_decoder=False, existing=False, fail_after_queries=False):
        self.env = {"result": 0}
        self.files = {}
        self.handles = {}
        self.memory = {}
        self.commands = []
        self.eof_reads = 0
        self.old_response = old_response
        self.bridge = 0x59604000
        self.fail_after_queries = fail_after_queries
        for name, addr, size, _ in FIXED:
            self.memory[addr] = bytearray(size)
        struct.pack_into('<I', self.memory[0x5380D1EC], 12,
                         0 if bad_decoder else 0x5380D220)
        struct.pack_into('<I', self.memory[0x553A08E4], 12, 0x59100040)
        struct.pack_into('<I', self.memory[0x550A0300], 188,
                         0xDEADBEEF if bad_pointer else self.bridge)
        meta = bytearray(32)
        struct.pack_into('<I', meta, 8, 2097152 if bad_size else 512)
        struct.pack_into('<I', meta, 16, 0x591F0700)
        self.memory[0x59100040] = meta
        self.memory[0x591F0700] = bytearray(512)
        self.memory[self.bridge] = bytearray(117)
        self.memory[self.bridge][116] = old_response
        struct.pack_into('<I', self.memory[0x5539FC64], 20, 0x59605000)
        obj = bytearray(32)
        struct.pack_into('<I', obj, 0, 0x53F80000)
        self.memory[0x59605000] = obj
        self.memory[0x53F80000] = bytearray(64)
        struct.pack_into('<I', self.memory[0x553A094C], 0, 0x59606000)
        struct.pack_into('<H', self.memory[0x553A094C], 4, 2)
        self.memory[0x59606000] = bytearray(104)
        if existing:
            self.files['C:\\XPBATCH.TXT'] = bytearray(b'PREEXISTING')

    def evaluate(self, expression):
        expression = expression.strip()
        if expression.startswith("'") and expression.endswith("'"):
            return expression[1:-1]
        expression = re.sub(r'(?<![<>=!])=(?!=)', '==', expression)
        node = ast.parse(expression, mode='eval').body

        def visit(n):
            if isinstance(n, ast.Constant):
                return n.value
            if isinstance(n, ast.Name):
                return self.env.get(n.id, 0)
            if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub):
                return -visit(n.operand)
            if isinstance(n, ast.BinOp):
                a, b = visit(n.left), visit(n.right)
                if isinstance(n.op, ast.Add):
                    return a + b
                if isinstance(n.op, ast.Sub):
                    return a - b
                if isinstance(n.op, ast.Mult):
                    return a * b
                if isinstance(n.op, ast.Div):
                    if not b: raise ValueError('division by zero')
                    return (abs(a)//abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
                raise ValueError('unsupported binary operation')
            if isinstance(n, ast.Compare) and len(n.ops) == 1:
                a, b = visit(n.left), visit(n.comparators[0])
                op = n.ops[0]
                if isinstance(op, ast.Eq): return a == b
                if isinstance(op, ast.NotEq): return a != b
                if isinstance(op, ast.Gt): return a > b
                if isinstance(op, ast.GtE): return a >= b
                if isinstance(op, ast.LtE): return a <= b
                if isinstance(op, ast.Lt): return a < b
            raise ValueError('unsupported expression')

        return visit(node)

    def value(self, word):
        return self.env.get(word, int(word) if re.fullmatch(r'-?\d+', word) else word)

    def read_memory(self, address, size):
        for base, data in self.memory.items():
            if base <= address and address + size <= base + len(data):
                return data[address-base:address-base+size]
        raise AssertionError(f'out-of-model memory read {address:#x} + {size:#x}')

    def send(self, cmd):
        self.commands.append(cmd)
        args = shlex.split(cmd, posix=False)
        self.env['result'] = 0
        if args[0] == 'SYS_md':
            addr = int(args[1], 0)
            size = int(args[3], 0)
            name = args[5]
            assert args[2] == '-s' and args[4] == '-f'
            if self.fail_after_queries and name == 'C:\\XPRPOST.BIN':
                return
            self.files[name] = bytearray(self.read_memory(addr, size))
        elif cmd == 'is_linux_boot':
            self.env['result'] = 1
        elif cmd in ('lcmd_resp on', 'lcmd_resp off'):
            self.memory[self.bridge][116] = int(cmd.endswith('on'))
        elif cmd.startswith('lcmd '):
            assert self.memory[self.bridge][116] == 1
            data = ('SIMULATED output: ' + cmd + '\n').encode()
            ring = self.memory[0x591F0700]
            i = ring.find(b'\0')
            ring[i:i+len(data)] = data
        else:
            raise AssertionError('unexpected command ' + cmd)

    def run(self, program=None):
        code = [s.strip() for s in (build() if program is None else program).splitlines()
                if s.strip() and not s.lstrip().startswith(';')]
        labels = {s[1:]: i for i, s in enumerate(code) if s.startswith(':')}
        if program is None:
            enabled = code.index("sendln 'lcmd_resp on'")
            restored = code.index("sendln 'lcmd_resp off'")
            assert not any(s.startswith(('call ', 'file')) for s in code[enabled+1:restored]), \
                'no SD operation or subroutine may run while the temporary flag is changed'
        ends, false, stack = {}, {}, []
        for i, s in enumerate(code):
            if s.startswith('if ') and s.endswith(' then'):
                stack.append([i, None, 'if'])
            elif s.startswith('while '):
                stack.append([i, None, 'while'])
            elif s == 'else':
                assert stack[-1][2] == 'if'
                stack[-1][1] = i
            elif s == 'endif':
                start, other, kind = stack.pop()
                assert kind == 'if'
                false[start] = (other if other is not None else i) + 1
                if other is not None: ends[other] = i + 1
            elif s == 'endwhile':
                start, other, kind = stack.pop()
                assert kind == 'while' and other is None
                false[start] = i + 1; ends[i] = start
        assert not stack
        calls = []
        pc = steps = 0
        while pc < len(code):
            s = code[pc]
            steps += 1
            assert steps < 50000, 'unexpected loop'
            if s.startswith(':') or s == 'endif':
                pc += 1
                continue
            if s.startswith('if ') and s.endswith(' then'):
                pc = pc + 1 if self.evaluate(s[3:-5]) else false[pc]
                continue
            if s.startswith('while '):
                pc = pc + 1 if self.evaluate(s[6:]) else false[pc]
                continue
            if s == 'endwhile': pc = ends[pc]; continue
            if s == 'else': pc = ends[pc]; continue
            if s == 'end': break
            if s.startswith('goto '): pc = labels[s[5:]] + 1; continue
            if s.startswith('call '):
                calls.append(pc + 1)
                pc = labels[s[5:]] + 1
                continue
            if s == 'return': pc = calls.pop(); continue
            if ' = ' in s:
                var, expr = s.split(' = ', 1)
                val = self.evaluate(expr)
                if isinstance(val, int):
                    val = (val + 2**31) % 2**32 - 2**31
                self.env[var] = val
            else:
                op, tail = (s.split(' ', 1) + [''])[:2]
                if op == 'sendln': self.send(self.evaluate(tail))
                elif op == 'mpause': pass
                else:
                    args = shlex.split(tail)
                    if op == 'filesearch':
                        self.env['result'] = int(self.value(args[0]) in self.files)
                    elif op == 'filecreate':
                        name = self.value(args[1]); self.files[name] = bytearray()
                        fd = max(self.handles, default=-1) + 1
                        self.handles[fd] = [name, 0]; self.env[args[0]] = fd
                    elif op == 'filestat':
                        status, size = self.stat_file(self.value(args[0]))
                        self.env['result'] = status
                        self.env[args[1]] = size
                    elif op == 'fileopen':
                        name = self.value(args[1])
                        if name not in self.files:
                            self.env[args[0]] = -1
                            pc += 1
                            continue
                        fd = max(self.handles, default=-1) + 1
                        pos = len(self.files[name]) if self.value(args[2]) == 1 else 0
                        self.handles[fd] = [name, pos]; self.env[args[0]] = fd
                    elif op == 'fileclose': del self.handles[self.value(args[0])]
                    elif op == 'filewriteln':
                        fd = self.value(args[0]); name, pos = self.handles[fd]
                        data = str(self.value(args[1])).encode('latin1') + b'\r\n'
                        self.files[name][pos:pos+len(data)] = data
                        self.handles[fd][1] += len(data)
                    elif op == 'fileseek':
                        assert self.value(args[2]) == 0
                        self.handles[self.value(args[0])][1] = self.value(args[1])
                    elif op == 'fileread':
                        name, pos = self.handles[self.value(args[0])]
                        assert self.value(args[1]) == 1
                        data = self.files[name][pos:pos+1]
                        self.handles[self.value(args[0])][1] += len(data)
                        # Observed GR IV behavior: EOF still returns 0 and can
                        # expose a stale byte. Do not model upstream TTL here.
                        if not data:
                            self.eof_reads += 1
                        self.env[args[2]] = (bytes(data) if data else b'\xa7').decode('latin1').split('\0')[0]
                        self.env['result'] = 0
                    elif op == 'str2code':
                        data = self.value(args[1])
                        self.env[args[0]] = ord(data[0]) if data else 0
                    elif op == 'int2str': self.env[args[0]] = str(self.value(args[1]))
                    elif op == 'strconcat': self.env[args[0]] += self.value(args[1])
                    else: raise AssertionError('unsupported command ' + op)
            pc += 1
        assert not self.handles
        assert not calls
        assert self.memory[self.bridge][116] == self.old_response
        return self

    def stat_file(self, name):
        return (0, len(self.files[name])) if name in self.files else (-1, -1)


def main():
    for flag in (0, 1):
        check = FlowCheck(old_response=flag).run()
        assert check.env['decoder'] == 1
        assert check.env['ring_ok'] == 1 and check.env['bridge_ok'] == 1
        assert len([x for x in check.commands if x.startswith('lcmd ')]) == 4
        assert 'C:\\XPCMDS.BIN' in check.files
        assert 'C:\\XPIMVT.BIN' in check.files
        assert b'XPAN batch finished' in check.files['C:\\XPBATCH.TXT']
    for options in ({'bad_pointer': True}, {'bad_size': True}, {'bad_decoder': True}):
        check = FlowCheck(**options).run()
        assert not any(x.startswith('lcmd') for x in check.commands)
        assert b'XPAN batch finished' in check.files['C:\\XPBATCH.TXT']
    check = FlowCheck(existing=True).run()
    assert not check.commands and check.files['C:\\XPBATCH.TXT'] == b'PREEXISTING'
    check = FlowCheck(fail_after_queries=True).run()
    assert 'C:\\XPRPOST.BIN' not in check.files
    assert check.memory[check.bridge][116] == 0
    print('7 synthetic flow checks passed: zero bytes, bounded pointers/sizes,')
    print('original response setting 0/1, no repeat overwrite, restoration before file failure.')
    print('This validates generated control flow, not camera execution or Linux access.')


if __name__ == '__main__':
    main()
