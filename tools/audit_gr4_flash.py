#!/usr/bin/env python3
# License: see LICENSE.
"""Pinned GR IV flash settings and hotshoe routing audit, entirely offline.

Optional --emulate executes original settings instructions using synthetic
RAM and intercepted assertion/factory services. It does not emulate the flash,
GPIO, serial controller, charging, shutter or camera scheduling.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from audit_xpan_paths import EXPECTED_SHA256, file_offset, require


PINS = (
    ("project_default_selection", 0x538e7d1c, 0x68, "a63cd27424b3b2972db6add9ac15a427b9cdc6aae20d9c953aeb1ef7655b03db"),
    ("project_model_selection", 0x538e7d94, 0x210, "f4c2b0077d8749b98c9e03be73f3c8f63db61edd9154050703b77518130d3ba6"),
    ("project_type_getter", 0x538e7fd0, 0xa4, "69cfcc326fed44c112bc4cc22e80ba2f8c1251d828bba5354179bebb85812ece"),
    ("flash_mode_string_parser", 0x533f2fe8, 0xf0, "d4e0c51b5a786551c4591435a560dafcba8dbb5b51d448224272037267e2eb93"),
    ("flash_output_labels", 0x53399c1c, 0xa8, "904f8dc9fa5561629110ca3ed706023025fc0eb2c2d080782cad9cd0e142a681"),
    ("flash_correct_property", 0x5329de48, 0x98, "c5f62d2657c1d890720395ee0be1ec4db8b7a770db6f40038ec40b1248b2ca21"),
    ("flash_control_property", 0x5329dee0, 0x70, "fbb32224c06792c418741ba9f8ce17d233b3ee6f5d9db8905b5f3d694e94b1c3"),
    ("flash_property_publish", 0x5329e108, 0x18, "32ded01cf4cd53f4e1c378b01e0c1282b4131bbaa2b9dd46f43629886a8e3340"),
    ("flash_mode_enable", 0x533e005c, 0xb8, "d879d7cc1e7ba57af4cf9494c027a6cd20ea22d2ec857f23f487922ec7501d8d"),
    ("flash_mode_replace", 0x533e0114, 0x9c, "9e21b542a8355e43fc827e0fbc7af7d0e93dd1b1d9e1c0cf3d3f53c8fc140b11"),
    ("flash_interface_selection", 0x53771cc4, 0x74, "546504edc4a6bcaa0bbbcdd702e4f260150087f1dfa731c9bc49596fd6126108"),
    ("flash_input", 0x53771f88, 0xc8, "225dbea186d58c8745295ffa752d068ec04b03348733435a7dc35154cf8d2b49"),
    ("flash_output", 0x53772204, 0x16c, "0538c9933f40dc8153c40918c9003c933e415159af244383a1a0bb18f5adcb7e"),
    ("hotshoe_initialize", 0x53a729c0, 0x454, "8f7cc185241fb2c7dcf8d4de5d1afa0c1ba339e3ecc181354fcac0cf7dadd486"),
    ("hotshoe_detect_thresholds", 0x53a731c4, 0x8c, "112a08b1c618089c8a4624c60726366dfa172f5e6f1e4a834af0f09b8f2665c0"),
    ("hotshoe_accessory_detection", 0x53a73250, 0x1f8, "784b1896eb4a78dd2acd5088b664c5037ebf39c5571ffbf253927466832c1200"),
    ("hotshoe_input", 0x53a73448, 0x10c, "650b58e95f25871fb9d6027c8890a3d4f6f8d70b43b17e872c039662d92bf9d3"),
    ("hotshoe_output", 0x53a73638, 0x298, "f934ae45b8dac9ba0f0953b96cb873c2b801649aa42ce008b9c7047d5c7f5375"),
    ("hotshoe_transfer", 0x53a7308c, 0x138, "73b683427ce32170a114132e0a8a82a16c8971c6b4509097f0a728d69219d41d"),
    ("legacy_timeout_reset", 0x53a6dac0, 0x44, "96a2caeeb98618a986ed9a8b56423d05ce0d3f5049acd98835e6cfa9e51c4e5a"),
    ("flash_charge_wait_registration", 0x53662d14, 0x50, "74b4491d21725243f6550d113fe792b5eba7c78789ea550a9d34347844e37357"),
    ("standard_project_configuration", 0x53fe50d0, 0x18, "72e8b52e4a5e73414a94b8846c2d8fb92448f1e46c873d75c3e15354f38ec3c7"),
    ("hotshoe_command_table", 0x54354054, 0x1c, "37f2d3e854ac312f5c31b6957127561f91acf1a00715742f1ab3f291ddaa36ae"),
)

MARKERS = {
    0x53d7cfd8: "Model/FlashModel.cpp",
    0x53d7e854: "StillFlashMode",
    0x53d7e864: "StillFlashCorrectValue",
    0x53d7e87c: "StillFlashControl",
    0x53d7c7e4: "1/1",
    0x53d7c7e8: "1/4",
    0x53dbf354: "ReplaceFlashMode",
    0x53eb5354: "AeCalculation/AeAlgorithm/src/AeFlashAlgorithm.cpp",
    0x53eb53d0: "AeCalculation/AeProgramDiagram/src/AeFlashSetupPrepare.cpp",
    0x53eb5438: "AeCalculation/AeProgramDiagram/src/AeFlashSetup.cpp",
    0x53eb5560: "AeCalculation/AeProgramDiagram/src/AeProgramDiagramFlash.cpp",
    0x53eb56c0: "AeCalculation/AeInternalInformation/src/AeFlashComData.cpp",
    0x53eb33a4: "RELEASE_STEP_FLASH_CHARGE_CHECK",
    0x53eb33c4: "RELEASE_STEP_FLASH_CHARGE_WAIT",
    0x53eb384c: "RELEASE_STEP_AE_FLASH_COM_BEFORE_SHUTTER",
    0x53f8fce8: "ExtFlashInput TIMEOUT",
    0x54353b28: "src/HotshoeControl.cpp",
    0x543540a4: "CheckAccessoryAttachment",
}


def audit(raw):
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unsupported decoded sample: {digest}")
    pins = []
    for role, address, size, expected in PINS:
        offset = file_offset(address)
        actual = hashlib.sha256(raw[offset:offset + size]).hexdigest()
        if actual != expected:
            raise ValueError(f"changed {role} at 0x{address:08x}")
        pins.append({"role": role, "runtime_address": hex(address),
                     "decoded_offset": hex(offset), "length": size, "sha256": actual})
    for address, marker in MARKERS.items():
        require(raw, file_offset(address), marker.encode("ascii") + b"\0", marker)
    require(raw, file_offset(0x53dbb070), b"\0\1\2", "flash output menu order")
    project = struct.unpack_from("<6I", raw, file_offset(0x53fe50d0))
    if project != (2, 0x27c, 0x132e0, 2, 0x27c, 0x132e0):
        raise ValueError("standard GR IV project configuration changed")
    commands = []
    table = raw[file_offset(0x54354054):file_offset(0x54354070)]
    for i in range(0, len(table), 2):
        if table[i] == 0 and table[i + 1] == 0:
            break
        commands.append({"command": hex(table[i]), "data_bytes": table[i + 1]})
    return {
        "schema": "gr4-flash-offline-audit-v1", "sample_sha256": digest,
        "decoded_length": len(raw), "firmware_version": "1.11.10.7",
        "address_mapping": {"rtos_decoded_offset": "0x17d10", "rtos_base": "0x53000000"},
        "pins": pins,
        "markers": [{"runtime_address": hex(a), "decoded_offset": hex(file_offset(a)),
                     "text": s} for a, s in MARKERS.items()],
        "settings": {"native_object_output_field": "0xc00",
                     "output_ids": {"0": "AUTO", "1": "1/1", "2": "1/4"},
                     "common_property_output_offsets": {"correction_float": "0xa0", "manual_byte": "0xa4"},
                     "manual_correction_ev": {"1": 0.0, "2": -2.0},
                     "movie_flag_forces_automatic_and_zero_correction": True,
                     "slow_sync_fallback": {"2": 0, "3": 1,
                                            "condition": "Tv automatic flag returned by native exposure-mode decoder is zero"}},
        "hotshoe": {"standard_project_type": project[0], "standard_product_id": hex(project[2]),
                    "new_interface_project_types": [2, 3, 4, 5, 6],
                    "new_interface_flag_offset": "0x54", "new_interface_object_offset": "0x48",
                    "legacy_interface_object_offset": "0x44", "communication_mode_offset": "0x30",
                    "serial_mode": 1, "identification_reply_byte": "0xa5",
                    "accepted_kind_bytes": ["0x11", "0x12"], "accepted_protocol_state": "0x10",
                    "command_table": commands,
                    "physical_accessory_kind_mapping_verified": False},
        "camera_accessed": False, "firmware_modified": False,
        "limits": ["Original instruction fingerprints and static routing only unless --emulate is used.",
                   "No P-TTL, wireless, high-speed-sync, power calibration or GPIO pinout established.",
                   "Legacy timeout logs are on a different branch from the GR IV hotshoe path.",
                   "No hardware timing, charging or physical flash-output measurements."],
    }


def emulate(raw):
    # Guard the known Unicorn/Darwin cache-query failure before engine startup.
    from check_gr4_native_memory_abi import check_host_cache_access
    check_host_cache_access()
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_S0,
                                   UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC)
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(0x53000000, 0x1400000)
    uc.mem_write(0x53000000, raw[file_offset(0x53000000):file_offset(0x54400000)])
    ram, obj, factory, stop = 0x61000000, 0x61001000, 0x61004000, 0x6100f000
    uc.mem_map(ram, 0x10000)
    uc.reg_write(UC_ARM_REG_C1_C0_2, 0xf00000)
    uc.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
    events = []
    allowed = []
    project_type = 2

    def intercept(machine, address, _size, _context):
        if address == 0x538ed930:
            events.append("assertion service intercepted")
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
        elif address in (0x53771ad8, 0x538e7fd0, 0x53a72900):
            events.append(hex(address))
            machine.reg_write(UC_ARM_REG_R0,
                              project_type if address == 0x538e7fd0 else factory)
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
        elif not any(lo <= address < hi for lo, hi in allowed):
            raise AssertionError(f"unexpected execution at 0x{address:08x}")

    uc.hook_add(UC_HOOK_CODE, intercept)

    def run(entry, r0, r1=0, spans=()):
        events.clear()
        allowed[:] = spans
        uc.reg_write(UC_ARM_REG_SP, ram + 0xe000)
        uc.reg_write(UC_ARM_REG_LR, stop)
        uc.reg_write(UC_ARM_REG_R0, r0)
        uc.reg_write(UC_ARM_REG_R1, r1)
        uc.reg_write(UC_ARM_REG_S0, 0x7fc00000)
        uc.emu_start(entry, stop, timeout=1000000, count=1000)
        if uc.reg_read(UC_ARM_REG_PC) != stop:
            raise AssertionError("native function did not return within instruction budget")
        return uc.reg_read(UC_ARM_REG_R0)

    cases = []
    for movie in (0, 1):
        for output in (0, 1, 2, 3):
            uc.mem_write(obj, bytes(0x1000))
            uc.mem_write(obj + 0xb1e, bytes([movie]))
            uc.mem_write(obj + 0xc00, bytes([output]))
            uc.mem_write(obj + 0xbfc, struct.pack("<f", 1.25))
            run(0x5329de48, obj, spans=[(0x5329de48, 0x5329dee0)])
            correction = struct.unpack("<f", struct.pack("<I", uc.reg_read(UC_ARM_REG_S0)))[0]
            correction_assert = bool(events)
            expected_correction = 0.0 if movie or output == 3 else (1.25, 0.0, -2.0)[output]
            if correction != expected_correction or correction_assert != (movie == 0 and output == 3):
                raise AssertionError("flash correction branch differs")
            manual = run(0x5329dee0, obj, spans=[(0x5329dee0, 0x5329df50)])
            if manual != int(not movie and output in (1, 2)) or bool(events) != correction_assert:
                raise AssertionError("flash control branch differs")
            cases.append({"movie": movie, "output_id": output,
                          "correction_ev": correction, "manual": manual,
                          "assertion_intercepted": correction_assert})
    # Use the original Tv/Av/Sv flag decoder, including its lookup jump table.
    for exposure in (0, 1, 2, 7):
        for mode in range(4):
            actual = run(0x533e0114, mode, exposure,
                         [(0x533e005c, 0x533e01b0), (0x53256d78, 0x53256ea8)])
            expected = mode - 2 if exposure in (1, 7) and mode in (2, 3) else mode
            if actual != expected or events:
                raise AssertionError("slow sync replacement differs")
            cases.append({"exposure_id": exposure, "requested_flash_mode": mode,
                          "effective_flash_mode": actual})
    # Factory objects and project getter are simulated; the branch/store code
    # selecting the legacy or new interface is the original firmware.
    for project_type in (0, 1, 2, 3, 4, 5, 6, 7, 255):
        uc.mem_write(obj, bytes(0x1000))
        uc.mem_write(factory, struct.pack("<5I", 0, 0x11110000, 0x22220000, 0, 0x33330000))
        returned = run(0x53771cc4, obj, spans=[(0x53771cc4, 0x53771d38)])
        use_new = int(2 <= project_type <= 6)
        flag = bytes(uc.mem_read(obj + 0x54, 1))[0]
        selected = struct.unpack("<I", uc.mem_read(obj + (0x48 if use_new else 0x44), 4))[0]
        if returned != 1 or flag != use_new or selected != (0x22220000 if use_new else 0x11110000):
            raise AssertionError("flash interface routing differs")
        cases.append({"project_type": project_type, "new_hotshoe_interface": bool(flag)})
    return {"cases_passed": len(cases), "cases": cases,
            "execution": "original ARM settings/branch instructions; synthetic RAM",
            "intercepted_services": ["assertion diagnostics", "factory singleton", "project-type getter"],
            "physical_flash_and_timing_verified": False, "camera_accessed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path, help="decoded GR IV 1.11.10.7 payload")
    parser.add_argument("--emulate", action="store_true", help="also run bounded native ARM logic checks")
    parser.add_argument("--output", type=Path, help="new JSON file, never overwrites an existing file")
    args = parser.parse_args()
    try:
        raw = args.sample.read_bytes()
        result = audit(raw)
        if args.emulate:
            result["emulation"] = emulate(raw)
        rendered = json.dumps(result, indent=2) + "\n"
        if args.output:
            with args.output.open("x") as stream:
                stream.write(rendered)
            print(f"Saved {len(PINS)} verified windows to {args.output}")
            if args.emulate:
                print(f"Native ARM cases passed: {result['emulation']['cases_passed']}")
        else:
            print(rendered, end="")
    except (OSError, ValueError, RuntimeError, AssertionError, ImportError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
