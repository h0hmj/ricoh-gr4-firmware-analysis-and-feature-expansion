#!/usr/bin/env python3
# License: see LICENSE.
"""Offline, pinned GR IV hotshoe/AE evidence audit; no device or CPU execution.

Fingerprints establish sample identity. Direct branches, constants and tables
are decoded from the sample; command meanings are static research annotations,
not an electrically validated accessory implementation.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from audit_gr4_flash import audit as audit_flash
from audit_xpan_paths import file_offset


PINS = (
    ('hotshoe_open', 0x53a72e60, 0x16c, '0f63392ddc74af6452054537f1591816f25536712108682c3fa0c87734089344'),
    ('sio_configure', 0x53a37cc4, 0x1ac, '8ccc733bbb5636470b73ffba650ce77d9ed398905d0e6a86214434eb79132cfa'),
    ('sio_divisor', 0x53abc740, 0x2c, '6911abc7cb3087a06d65be59630db7650583f5f8d57be71194981ba4b135c3d8'),
    ('sio_transfer_byte', 0x53a384f4, 0x148, '90c5b83b6c237fb66911c2f534ff24f9f3c414d1752017006ea9dc51004cbce7'),
    ('elapsed_conversion', 0x538f4e9c, 0x6c, '8dbd3fadaf94eca25bb118788bcffdc581b28c7ccde52a98026d1dbaebcbd0f6'),
    ('elapsed_wait', 0x538f4f4c, 0x44, 'da827c9ea36f6aa8488376a1271b6e3417a3a683cd7abb1b9233fbb9ed9a48ab'),
    ('manager_accessors', 0x53772758, 0x180, '67d33ff70d0c20bb331b9c80a340bfb206a8b5f1972e16710f67c9630d896ff0'),
    ('ae_assist_accessors', 0x5367f28c, 0xb8, '755d1889f1ee3cb17536d6048cbfb1106d1b29a8985e8e5f79e885a5ffc19893'),
    ('ae_output_publish', 0x5367fadc, 0x6c, '50a62224584bc08b02e6772845d5185fb676f7c9e42b0f653da42b62ba9f6788'),
    ('ae_input_snapshot', 0x5367fb48, 0xec, '4afe81ef8cb850b5d4b9b1397fbcd0128cd4b88c67d861d3af6417e9a45f3651'),
    ('ae_ready_gate', 0x5367f410, 0x40, '768e463bd04baeb3643457e543ff8ea021a5c7b3968d0dc811677b3e0583e54b'),
    ('ae_main_code', 0x53680940, 0x120, '899ae1582e76ea7faa1834595a3d752d63ff1ba8018dcc1aa4eb7de2892a39cb'),
    ('ae_new_payload', 0x53680e98, 0x21c, '06025c0ad56efe00031e27c358bd7ca30fae0a58994246adc21dd974104564ed'),
    ('ae_main_sum', 0x536784f0, 0x9c, '03fb4f4969693bda018fb09ba4209d30693e39d7d14e45d451316113ba6115fc'),
    ('ae_internal_accessors', 0x536834f4, 0x218, '14fdf0f5435208bc3e5de8e471f497d31c44b54a7f7ce387d9fcbc683f669c54'),
    ('ae_distance_transform', 0x53681e6c, 0x48, '0eb8c8004e1381ff45d57e1e84c63c97e9cd1c542287d28ea9e44a7e187b84a2'),
    ('ae_distance_update', 0x53681f04, 0x9c, 'a57073ba22302664a6dc03223f89d2a5dcc6921da39166de27c27f5df7d9b6b5'),
    ('lens_distance', 0x5394252c, 0x80, '6e7c8e8cdd0c169b2deef61aef6e03d7651aaaa74e10388bec8f572111f0560e'),
    ('kind11_input_correction', 0x53771ed8, 0xb0, '1ec4c607378e3a980227cd50deb5ed17159716a19d21504d7d6ea473d9181060'),
    ('kind11_output_polynomial', 0x53772050, 0xa8, '22b098b30ec2979005f079b83350e2cb2ca364bbadc3ff553f8acdb72a512814'),
    ('kind11_output_correction', 0x537720f8, 0x10c, 'bd000c8ab3a527e601443cb3f86ade1e3f1b891edeae4fe50a22fa998a5f4f8a'),
    ('ae_settings_read', 0x5368159c, 0x2c, '510cc344a12b18ab0a8efc765a158684430e14e0713a0b341c780cb0a73f490b'),
    ('auto_power_off_dispatch', 0x53771364, 0xc0, '948e020c95ea848247c897d80d2726b1a36d710fc6a28141c44f6c7145011516'),
    ('hotshoe_extended_input', 0x53a73554, 0xe4, 'a6af3ba68c4f26ea6031fac3b23c812889762851db43a7c90053d68eb3991c96'),
    ('flash_service_output', 0x53770a30, 0xcc, '00fc941d4b4135095c334dd4b163f7179bef3ef9e1f515e83cc6f0fa110ae016'),
    ('math_sqrt_wrapper', 0x5316a038, 0x78, 'e7b5d671bc08726e64cebabe743b1d7626fec2005a47f294b9c62e2346deb8f2'),
    ('math_log_wrapper', 0x5316a244, 0x88, '39e3cb24153a86f5d33e92ab77923dfa959ca6b23bb6e43fc7e0dc50de41cc7e'),
    ('math_log2f', 0x531695cc, 0x18, '9abbc1a73e221d8a49e5984d4ed3db4929b53ea23f41c67b1becf4ac8a94e270'),
)

# These include the easily confused C4 reset and C3 capability replacement.
EDGES = (
    (0x53a73334, 0x53a7308c), (0x53a73404, 0x53a7308c),
    (0x53a734dc, 0x53772788), (0x53a73500, 0x537727e0),
    (0x53a73524, 0x537727fc), (0x53a73544, 0x53772818),
    (0x53771f1c, 0x537727fc), (0x53771f6c, 0x537727e0),
    (0x53772008, 0x53771ed8), (0x53772330, 0x537720f8),
    (0x53680ea0, 0x53680940), (0x53680eb4, 0x5367f28c),
    (0x53680ee4, 0x5367f29c), (0x53680f0c, 0x5367f2ac),
    (0x53680f40, 0x5367f2bc), (0x53680f68, 0x5367f2cc),
    (0x53680f74, 0x5367f2dc), (0x53680f90, 0x5367f2ec),
    (0x5367fb44, 0x53772890), (0x5367f44c, 0x537727a4),
    (0x53a73128, 0x53a384f4), (0x53a73164, 0x53a384f4),
    (0x53a73600, 0x53a7308c), (0x53771dd8, 0x53a73554),
)

COMMANDS = (
    (0xc0, 1, 'read', '0x74', 'identification_ack'),
    (0xc1, 2, 'read', '0x75/0x76', 'kind_and_subkind'),
    (0xc2, 2, 'read', '0x77/0x78', 'status_and_flags'),
    (0xc3, 2, 'read', '0x79/0x7a', 'automatic_lower_and_upper_code'),
    (0xc4, 2, 'read', '0x7b/0x7c', 'manual_anchor_in_second_byte'),
    (0xc5, 1, 'read', '0x7d', 'kind11_correction_input_physical_unit_unknown'),
    (0xa0, 1, 'write', '0x6c', 'main_output_code_with_possible_kind11_correction'),
    (0xa1, 1, 'write', '0x6d', 'sensitivity_encoding_candidate'),
    (0xa2, 1, 'write', '0x6e', 'aperture_encoding_candidate'),
    (0xa3, 1, 'write', '0x6f', 'sign_magnitude_correction_field'),
    (0xa4, 1, 'write', '0x70', 'lens_derived_logarithmic_field'),
    (0xa5, 1, 'write', '0x71', 'default_zero_not_sent_by_bulk_output'),
    (0xa6, 2, 'write', '0x72/0x73', 'auto_power_off_setting_high_byte_first'),
)


def audit(raw):
    base = audit_flash(raw)
    pins = []
    for role, address, length, expected in PINS:
        offset = file_offset(address)
        digest = hashlib.sha256(raw[offset:offset + length]).hexdigest()
        if digest != expected:
            raise ValueError(f'changed {role} at 0x{address:08x}')
        pins.append(dict(role=role, runtime_address=hex(address),
                         decoded_offset=hex(offset), length=length, sha256=digest))
    edges = []
    for site, expected in EDGES:
        word = struct.unpack_from('<I', raw, file_offset(site))[0]
        if word & 0x0e000000 != 0x0a000000 or word >> 28 != 14:
            raise ValueError(f'not an unconditional ARM B/BL at {site:#x}')
        displacement = word & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        target = site + 8 + 4 * displacement
        if target != expected:
            raise ValueError(f'branch target changed at {site:#x}')
        edges.append(dict(site=hex(site), target=hex(target),
                          link=bool(word & 0x01000000)))
    table = base['hotshoe']['command_table']
    if [(int(c['command'], 16), c['data_bytes']) for c in table] != [c[:2] for c in COMMANDS]:
        raise ValueError('unexpected command table')
    destinations = struct.unpack_from('<11I', raw, file_offset(0x53a736b8))
    expected = (0x53a73870, 0x53a73870, 0x53a73840, 0x53a73894,
                0x53a73758, 0x53a73758, 0x53a73728, 0x53a73728,
                0x53a73728, 0x53a73728, 0x53a736e4)
    if destinations != expected:
        raise ValueError('output jump table changed')
    meanings = ('A1', 'A1', 'diagnostic/false', 'success/no transfer',
                'A0,A1,A2,A3,A4,A6', 'A0,A1,A2,A3,A4,A6',
                'diagnostic/false', 'diagnostic/false', 'diagnostic/false',
                'diagnostic/false', 'A6')
    constants = {hex(a): struct.unpack_from('<f', raw, file_offset(a))[0]
                 for a in (0x53680a5c, 0x536810b0, 0x536810b4, 0x53681eb0)}
    if list(constants.values()) != [52.0, 32.0, 68.0, 1000.0]:
        raise ValueError('AE encoding constants changed')
    extended = struct.unpack_from('<H', raw, file_offset(0x53b4e7b8))[0]
    if extended != 0x0b50:
        raise ValueError('extended read descriptor changed')
    coefficients = {hex(a): struct.unpack_from('<d', raw, file_offset(a))[0]
                    for a in (0x53771f70, 0x53771f78, 0x53771f80,
                              *range(0x537720c0, 0x537720f8, 8))}
    return {
        'schema': 'gr4-hotshoe-static-audit-v1',
        'sample_sha256': base['sample_sha256'], 'firmware_version': base['firmware_version'],
        'evidence': 'static instruction tracing, tables and constants; no CPU execution',
        'baseline_pins': base['pins'], 'additional_pins': pins, 'branch_edges': edges,
        'commands': [dict(command=hex(c), payload_bytes=n, direction=d,
                          manager_offset=o, annotation=m) for c, n, d, o, m in COMMANDS],
        'output_states': [dict(camera_state=8+i, destination=hex(a), behavior=m)
                          for i, (a, m) in enumerate(zip(destinations, meanings))],
        'extended_read': {'command': hex(extended & 255), 'payload_bytes': extended >> 8,
                          'first_tx_payload_byte': '0x21', 'manager_result_offset': '0x80',
                          'physical_meaning': 'unknown'},
        'ae_constants': constants, 'kind11_polynomial_constants': coefficients,
        'transport': {'configured_serial_rate': 100000, 'rate_unit': 'Hz inferred from divisor',
                      'chip_select_during_transfer': 0, 'chip_select_after_transfer': 1,
                      'command_reply_discarded': True, 'read_dummy_byte': 0,
                      'gap_timer_value': 200, 'per_byte_delay_timer_value': 100,
                      'timer_unit_verified': False, 'checksum_in_transfer': False,
                      'sio_poll_iteration_limit': 65536, 'rx_failure_sentinel': '0xc9',
                      'sio_failure_return_checked_by_hotshoe': False},
        'camera_accessed': False, 'firmware_modified': False,
        'limits': ['No physical pin locations, voltages, clock phase or bit order established.',
                   'Nominal GN interpretation applies before accessory-specific correction.',
                   'Kind 0x11/0x12 physical model mapping and C5 units remain unverified.',
                   'No measured X-sync/preflash/shutter sequence or real flash output.',
                   'A software output-success event is not proof of accessory receipt.'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', type=Path)
    parser.add_argument('--output', type=Path, help='new JSON file; never overwrites')
    args = parser.parse_args()
    try:
        result = audit(args.sample.read_bytes())
        rendered = json.dumps(result, indent=2) + '\n'
        if args.output:
            with args.output.open('x') as stream:
                stream.write(rendered)
            print(f"Saved {len(result['baseline_pins']) + len(PINS)} windows, "
                  f'{len(EDGES)} branch edges and 13 commands to {args.output}')
        else:
            print(rendered, end='')
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'error: {error}\n')


if __name__ == '__main__':
    main()
