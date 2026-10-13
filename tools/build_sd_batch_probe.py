#!/usr/bin/env python3
"""Build a GR IV 1.11.10.7 SD diagnostic; never contact a camera.

Fixed mapped reads plus same-boot, bounded pointer reads. The only setting
change is lcmd_resp, restored to the value read before querying Linux.
"""
import argparse
from pathlib import Path

# All addresses are from the SHA-pinned local 1.11.10.7 sample.
FIXED = [
    ("XPCHECK.BIN", 0x5380D1EC, 16, "decoder/version check"),
    ("XPASPC.BIN", 0x5325ADFC, 208, "aspect selection"),
    ("XPLVC.BIN", 0x5339E900, 512, "view layout"),
    ("XPICON.BIN", 0x53398380, 224, "crop icon selection"),
    ("XPSTILL.BIN", 0x5380D1D0, 384, "still aspect setting"),
    ("XPTEXT.BIN", 0x534DF800, 256, "aspect status text"),
    ("XPDNG.BIN", 0x5387B024, 424, "DNG crop window"),
    ("XPLVTASK.BIN", 0x5362CF14, 512, "live view crop task"),
    ("XPORDER.BIN", 0x53DBB034, 16, "aspect order"),
    ("XPMAG.BIN", 0x53DBAC10, 12, "crop magnifications"),
    ("XPPROP.BIN", 0x55085D40, 192, "current imaging properties"),
    ("XPLOGST.BIN", 0x553A08E4, 128, "logger state"),
    ("XPBOOT.BIN", 0x550A0300, 768, "Linux bridge holder/boot state"),
    ("XPMGR.BIN", 0x553A4658, 88, "saved log manager"),
    ("XPSHELL.BIN", 0x553A094C, 84, "shell table state"),
    ("XPIMROOT.BIN", 0x5539FC64, 32, "image size calculator holder"),
]
DYNAMIC_FILES = ["XPRMETA.BIN", "XPRPRE.BIN", "XPRPOST.BIN",
                 "XPBPRE.BIN", "XPBPOST.BIN", "XPIMOBJ.BIN",
                 "XPIMVT.BIN", "XPCMDS.BIN", "XPPEND.BIN"]
OUTPUTS = ["XPBATCH.TXT"] + [row[0] for row in FIXED] + DYNAMIC_FILES


def build():
    lines = [
        "; GR IV 1.11.10.7 only. One boot, allow 90 seconds.",
        "; SD diagnostic: fixed reads, bounded same-boot pointer reads, Linux queries.",
        "; No firmware/code/property writes. lcmd_resp is temporarily enabled and restored.",
        "; An existing XPBATCH.TXT stops the script to preserve previous results.",
        "filesearch 'C:\\XPBATCH.TXT'",
        "if result = 1 then", "    end", "endif",
        "filecreate bf 'C:\\XPBATCH.TXT'",
        "filewriteln bf 'XPAN batch started'", "fileclose bf", "mpause 10000",
    ]

    def emit(s):
        lines.extend(s.strip().splitlines())

    for name, address, size, reason in FIXED:
        emit(f"""
; {reason}
da = {address}
ds = {size}
dn = '{name}'
call dump_fixed
""")
    emit("""
; Check binary decoding against a known positive pointer in the code snapshot.
ufile = 'C:\\XPCHECK.BIN'
uoff = 12
call read_u32
decoder = 0
if uok = 1 then
    if uv = 1400951328 then
        decoder = 1
    endif
endif
tag = 'binary decoder check'
value = decoder
call record_value
ring_ok = 0
bridge_ok = 0
if decoder = 1 then
    ; Locate the current print ring, never reuse a pointer from an earlier boot.
    ufile = 'C:\\XPLOGST.BIN'
    uoff = 12
    call read_u32
    if uok = 1 then
        da = uv
        ds = 32
        dn = 'XPRMETA.BIN'
        call dump_heap
        if dok = 1 then
            ufile = 'C:\\XPRMETA.BIN'
            uoff = 8
            call read_u32
            ring_size = uv
            size_ok = uok
            uoff = 16
            call read_u32
            ring_addr = uv
            if uok = 1 then
                if size_ok = 1 then
                    da = ring_addr
                    ds = ring_size
                    dn = 'XPRPRE.BIN'
                    call dump_heap
                    ring_ok = dok
                endif
            endif
        endif
    endif

    ; Resolve the actual image size calculator and its method table.
    ufile = 'C:\\XPIMROOT.BIN'
    uoff = 20
    call read_u32
    if uok = 1 then
        da = uv
        ds = 32
        dn = 'XPIMOBJ.BIN'
        call dump_heap
        if dok = 1 then
            ufile = 'C:\\XPIMOBJ.BIN'
            uoff = 0
            call read_u32
            if uok = 1 then
                if uv >= 1392508928 then
                    if uv <= 1412937216 then
                        da = uv
                        ds = 64
                        dn = 'XPIMVT.BIN'
                        call dump_fixed
                    endif
                endif
            endif
        endif
    endif

    ; Read the current engineering command table, at most 1,024 rows of 52 bytes.
    ufile = 'C:\\XPSHELL.BIN'
    uoff = 0
    call read_u32
    command_addr = uv
    command_ok = uok
    uoff = 4
    call read_u16
    if uok = 1 then
        if command_ok = 1 then
            if uv >= 1 then
                if uv <= 1024 then
                    da = command_addr
                    ds = uv * 52
                    dn = 'XPCMDS.BIN'
                    call dump_heap
                endif
            endif
        endif
    endif

    ; Read the prior response-output setting before any temporary change.
    ufile = 'C:\\XPBOOT.BIN'
    uoff = 188
    call read_u32
    if uok = 1 then
        bridge_addr = uv
        da = bridge_addr
        ds = 117
        dn = 'XPBPRE.BIN'
        call dump_heap
        if dok = 1 then
            ufile = 'C:\\XPBPRE.BIN'
            uoff = 116
            call read_byte
            if uok = 1 then
                if uv >= 0 then
                    if uv <= 1 then
                        old_response = uv
                        bridge_ok = 1
                    endif
                endif
            endif
        endif
    endif
endif

; Only query Linux if both the output buffer and original setting were read.
if ring_ok = 1 then
    if bridge_ok = 1 then
        sendln 'is_linux_boot'
        linux_ready = result
        tag = 'Linux readiness before queries'
        value = linux_ready
        call record_value
        if linux_ready = 1 then
            if old_response = 0 then
                sendln 'lcmd_resp on'
            endif
            ; The complete reply marker is absent from the command text.
            sendln 'lcmd "printf XPAN_SD_%s_REPLY EXECUTED"'
            marker_result = result
            sendln 'lcmd "/bin/uname -sr"'
            uname_result = result
            sendln 'lcmd "/bin/cat /proc/mounts"'
            mounts_result = result
            sendln 'lcmd "/bin/ls -ld /run/SD /run/SD/* /media/card"'
            paths_result = result
            ; Restore immediately; subsequent file/read failures cannot leave it enabled.
            if old_response = 0 then
                sendln 'lcmd_resp off'
            endif
            value = marker_result
            tag = 'computed marker handler return (not execution status)'
            call record_value
            value = uname_result
            tag = 'uname handler return (not execution status)'
            call record_value
            value = mounts_result
            tag = 'mount query handler return (not execution status)'
            call record_value
            value = paths_result
            tag = 'SD path query handler return (not execution status)'
            call record_value
            mpause 1000
        endif
        da = ring_addr
        ds = ring_size
        dn = 'XPRPOST.BIN'
        call dump_heap
        da = bridge_addr
        ds = 117
        dn = 'XPBPOST.BIN'
        call dump_heap
    endif
endif
tag = 'ring read available'
value = ring_ok
call record_value
tag = 'bridge setting read available'
value = bridge_ok
call record_value

; A later property snapshot allows comparison while the camera is operating.
mpause 15000
da = 1426611520
ds = 192
dn = 'XPPEND.BIN'
call dump_fixed
fileopen bf 'C:\\XPBATCH.TXT' 1
filewriteln bf 'XPAN batch finished'
fileclose bf
end

:record_value
int2str number value
fileopen bf 'C:\\XPBATCH.TXT' 1
filewriteln bf tag
filewriteln bf number
fileclose bf
return

:dump_fixed
path = 'C:\\'
strconcat path dn
filesearch path
dok = 0
if result = 0 then
    cmd = 'SYS_md '
    int2str number da
    strconcat cmd number
    strconcat cmd ' -s '
    int2str number ds
    strconcat cmd number
    strconcat cmd ' -f '
    strconcat cmd path
    sendln cmd
    filesearch path
    dok = result
endif
tag = dn
value = dok
call record_value
return

:dump_heap
; Bound every pointer read to the observed RTOS heap window and 1 MiB maximum.
dok = 0
if da >= 1493172224 then
    if ds >= 1 then
        if ds <= 1048576 then
            last = da + ds
            if last > da then
                if last <= 1509949440 then
                    call dump_fixed
                endif
            endif
        endif
    endif
endif
return

:read_byte
uok = 0
uv = 0
fileopen uf ufile 0
if uf >= 0 then
    fileseek uf uoff 0
    fileread uf 1 uc
    if result = 0 then
        str2code uv uc
        uok = 1
    endif
    fileclose uf
endif
return

:read_u16
call read_byte
ua = uv
ua_ok = uok
uoff = uoff + 1
call read_byte
uv = ua + uv * 256
if ua_ok = 0 then
    uok = 0
endif
return

:read_u32
call read_byte
ua = uv
ua_ok = uok
uoff = uoff + 1
call read_byte
ub = uv
ub_ok = uok
uoff = uoff + 1
call read_byte
ucode = uv
uc_ok = uok
uoff = uoff + 1
call read_byte
uv = ua + ub * 256 + ucode * 65536 + uv * 16777216
if ua_ok = 0 then
    uok = 0
endif
if ub_ok = 0 then
    uok = 0
endif
if uc_ok = 0 then
    uok = 0
endif
return
""")
    # These numbers are emitted in decimal because the camera TTL integer
    # parser need not support C-style hex literals.
    text = "\n".join(lines) + "\n"
    assert "1400951328" == str(0x5380D220)
    assert "1426611520" == str(0x55085D40)
    assert "1412937216" == str(0x5437B600)
    for name in OUTPUTS:
        assert len(name.split('.')[0]) <= 8
    return text


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    args.output.write_text(build(), encoding="ascii")
    print("Built", args.output, "fixed bytes", sum(row[2] for row in FIXED),
          "maximum dynamic bytes", 2 * 1048576 + 53248 + 3 * 32 + 64 + 234 + 192)


if __name__ == "__main__":
    main()
