import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('collect_lemonades', ROOT / 'tools/collect_lemonades.py')
lemonades = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lemonades)
ANALYSIS_SPEC = importlib.util.spec_from_file_location('analyze_lemonades', ROOT / 'tools/analyze_lemonades.py')
analysis = importlib.util.module_from_spec(ANALYSIS_SPEC)
ANALYSIS_SPEC.loader.exec_module(analysis)


class LemonadesGuardTests(unittest.TestCase):
    def test_accept_exact_device(self):
        lemonades.validate_identity({'ro.product.device': 'lemonades', 'ro.board.platform': 'kona', 'ro.soc.model': 'SM8250'})

    def test_reject_related_but_different_phone(self):
        for device, platform, soc in (('cmi', 'kona', 'SM8250'), ('lemonades', 'taro', 'SM8450'),
                                      ('mako', 'msm8960', ''), ('lemonades', 'kona', 'SM8550')):
            with self.assertRaises(ValueError):
                lemonades.validate_identity({'ro.product.device': device, 'ro.board.platform': platform,
                                       'ro.soc.model': soc})

    def test_wrong_phone_never_queries_root(self):
        calls = []

        def value(command):
            calls.append(command)
            return 'cmi' if command == 'getprop ro.product.device' else ''

        with patch.object(lemonades.Adb, 'value', side_effect=value), patch('sys.argv', ['collect_lemonades.py', '--serial', 'test']):
            with self.assertRaisesRegex(ValueError, 'not verified'):
                lemonades.main()
        self.assertNotIn('id', calls)

    def test_userdata_never_read_as_image(self):
        with patch.object(lemonades.Adb, 'value') as mock:
            with self.assertRaisesRegex(ValueError, 'allowlist'):
                lemonades.Adb('test').copy_partition('/dev/block/by-name/userdata', Path('/unused'))
        mock.assert_not_called()

    def test_mismatched_backup_not_accepted(self):
        def copy(command, **kwargs):
            kwargs['stdout'].write(b'boot')
            return type('Result', (), {'returncode': 0})()

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'boot.img'
            with patch.object(lemonades.Adb, 'value', side_effect=['4', '0' * 64]), patch.object(lemonades.subprocess, 'run', side_effect=copy):
                with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
                    lemonades.Adb('test').copy_partition('/dev/block/by-name/boot', destination)
            self.assertFalse(destination.exists())


class GptTests(unittest.TestCase):
    @staticmethod
    def image(overlap=False, count=128):
        sector = 4096
        data = bytearray(6 * sector)
        table = bytearray(128 * 128)
        for index, (name, first, last) in enumerate([('userdata', 256, 511)] +
                                                   ([('other', 500, 800)] if overlap else [])):
            offset = index * 128
            table[offset:offset + 16] = b'\x01' * 16
            struct.pack_into('<QQQ', table, offset + 32, first, last, 0)
            encoded = name.encode('utf-16-le')
            table[offset + 56:offset + 56 + len(encoded)] = encoded
        data[sector * 2:] = table
        struct.pack_into('<8sIIIIQQQQ16sQIII', data, sector,
                         b'EFI PART', 0x10000, 92, 0, 0, 1, 10000, 6, 9999,
                         bytes(16), 2, count, 128, zlib.crc32(table))
        struct.pack_into('<I', data, sector + 16, zlib.crc32(data[sector:sector + 92]))
        return data

    def test_lbas_use_logical_4096_not_sysfs_512(self):
        result = lemonades.parse_gpt(self.image(), 4096)[0]
        self.assertEqual(result['name'], 'userdata')
        self.assertEqual(result['first_lba'], 256)
        self.assertEqual(result['offset_bytes'], 1024 * 1024)
        self.assertEqual(result['size_bytes'], 1024 * 1024)

    def test_reject_corrupted_header_and_table(self):
        for offset in (4096 + 32, 8192 + 128):
            data = self.image()
            data[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'CRC'):
                lemonades.parse_gpt(data, 4096)

    def test_reject_overlap(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            lemonades.parse_gpt(self.image(overlap=True), 4096)

    def test_limit_metadata_read_size(self):
        data = self.image()
        struct.pack_into('<Q', data, 4096 + 72, 300)
        struct.pack_into('<I', data, 4096 + 16, 0)
        struct.pack_into('<I', data, 4096 + 16, zlib.crc32(data[4096:4096 + 92]))
        with self.assertRaisesRegex(ValueError, 'limit'):
            lemonades.parse_gpt(data, 4096)

    def test_adb_transfer_suppresses_dd_statistics(self):
        image = self.image()

        class FakeAdb:
            def value(self, command):
                return '4096'

            def raw(self, command):
                if not command.endswith('2>/dev/null'):
                    raise AssertionError('Remote stderr must not contaminate GPT bytes')
                return image[:8192] if 'count=2 ' in command else image

        sector, data, partitions = lemonades.read_gpt(FakeAdb(), 'sda')
        self.assertEqual(sector, 4096)
        self.assertEqual(partitions[0]['name'], 'userdata')


class EvidenceParserTests(unittest.TestCase):
    @staticmethod
    def fdt():
        strings = b'#address-cells\0#size-cells\0reg\0'

        def prop(name, value):
            return struct.pack('>III', 3, len(value), strings.index(name.encode() + b'\0')) + value

        structure = (struct.pack('>I', 1) + bytes(4)
                     + prop('#address-cells', struct.pack('>I', 2))
                     + prop('#size-cells', struct.pack('>I', 2))
                     + struct.pack('>I', 4)  # NOP is legal between properties/nodes.
                     + struct.pack('>I', 1) + b'memory\0\0'
                     + prop('reg', struct.pack('>4I', 2, 0, 1, 0x80000000))
                     + struct.pack('>3I', 2, 2, 9))
        return (struct.pack('>10I', 0xd00dfeed, 56 + len(structure) + len(strings),
                            56, 56 + len(structure), 40, 17, 16, 0, len(strings), len(structure))
                + bytes(16) + structure + strings)

    def test_preserve_ram_addresses_above_4g(self):
        nodes = analysis.fdt_nodes(self.fdt())
        values = analysis.reg_ranges(nodes, '/memory')
        self.assertEqual(values[0]['address'], '0x200000000')
        self.assertEqual(values[0]['size'], '0x180000000')

    def test_reject_truncated_fdt(self):
        with self.assertRaisesRegex(ValueError, 'FDT header'):
            analysis.fdt_nodes(self.fdt()[:-1])

    @staticmethod
    def boot_image():
        data = bytearray(16384)
        data[:8] = b'ANDROID!'
        struct.pack_into('<10I', data, 8, 4, 0x8000, 4, 0x1000000, 0, 0, 0x100, 4096, 2, 0)
        struct.pack_into('<I', data, 1644, 1660)
        struct.pack_into('<IQ', data, 1648, 4, 0x1f00000)
        return data

    def test_boot_v2_payload_ranges(self):
        image = analysis.boot_v2(self.boot_image())
        self.assertEqual(image['segments']['dtb']['file_offset'], 12288)
        self.assertEqual(image['segments']['dtb']['header_load_address'], '0x1f00000')

    def test_truncated_dtb_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated or empty boot DTB'):
            analysis.boot_v2(self.boot_image()[:12290])

    def test_dtbo_table_bounds(self):
        fdt = self.fdt()
        header = struct.pack('>8I', 0xd7b7ab1e, 64 + len(fdt), 32, 32, 1, 32, 4096, 0)
        entry = struct.pack('>8I', len(fdt), 64, 0, 0, 0, 0, 0, 0)
        self.assertEqual(len(analysis.dtbo_entries(header + entry + fdt)['entries']), 1)
        bad = bytearray(header + entry + fdt)
        struct.pack_into('>I', bad, 36, 0xfffffff0)
        with self.assertRaisesRegex(ValueError, 'out of bounds'):
            analysis.dtbo_entries(bad)


if __name__ == '__main__':
    unittest.main()
