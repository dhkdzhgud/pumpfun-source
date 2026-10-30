#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from window_elf_reader import Elf
from types import SimpleNamespace
import deep_section_analysis
import analyze
from compare import compare
class InferredStructExtentTests(unittest.TestCase):
    def analyze_offsets(self, offsets):
        code = b''.join(struct.pack('<BBhi', 0x79, 0x21, offset, 0) for offset in offsets)
        header = bytearray(64)
        struct.pack_into('<Q', header, 24, 64)
        elf = SimpleNamespace(b=bytes(header) + code, lo=64, hi=64+len(code),
                              entries=[64], funcs=[], secs={})
        return deep_section_analysis.recover_anchor_idl(elf)

    def test_size_inference_is_not_limited_to_twenty_displayed_fields(self):
        for count in (20, 21, 35):
            with self.subTest(count=count):
                result = self.analyze_offsets(list(range(0, count*8, 8)))
                row = result['deserialization_patterns'][0]
                self.assertEqual(row['field_offsets'], list(range(0, min(count, 20)*8, 8)))
                self.assertEqual(row['field_sizes'], [8]*min(count, 20))
                self.assertEqual(row['likely_struct_size'], count*8)
                self.assertEqual(result['inferred_struct_sizes'], [count*8])

    def test_duplicate_reads_do_not_change_the_observed_extent(self):
        offsets = list(range(0, 21*8, 8))
        result = self.analyze_offsets(offsets + offsets[-5:])
        self.assertEqual(result['deserialization_patterns'][0]['likely_struct_size'], 168)
        self.assertEqual(len(result['deserialization_patterns'][0]['field_offsets']), 20)

    def test_retained_patterns_use_the_full_observed_load_extent(self):
        checked = capped = 0
        for path in sorted(analyze.ROOT.glob('evidence/**/deployed.so')):
            elf = Elf(path)
            ends = dict(zip(elf.entries, elf.entries[1:] + [elf.hi]))
            result = deep_section_analysis.recover_anchor_idl(elf)
            for row in result['deserialization_patterns']:
                start = int(row['window'], 16)
                offsets = {struct.unpack_from('<h', elf.b, at+2)[0]
                           for at in range(start, ends[start], 8)
                           if elf.b[at] in (0x61, 0x69, 0x71, 0x79)
                           and elf.b[at+1] >> 4 == row['base_reg']}
                self.assertEqual(row['likely_struct_size'], max(offsets)+8,
                                 f'{path.parent.name}:{start:#x}:r{row["base_reg"]}')
                self.assertLessEqual(len(row['field_offsets']), 20)
                checked += 1
                capped += len(offsets) > 20
        self.assertGreater(checked, 0)
        self.assertGreater(capped, 0)


class ComparisonTests(unittest.TestCase):
    def test_equal(self): self.assertTrue(compare(b'abc\0\0',b'abc\0\0')['full_byte_equality'])
    def test_code_mutation(self): self.assertEqual(compare(b'abc\0\0',b'axc\0\0')['first_difference'],1)
    def test_padding_mutation(self): self.assertEqual(compare(b'abc\0\0',b'abc\0x')['first_difference'],4)
    def test_truncated_padding(self): self.assertFalse(compare(b'abc\0\0',b'abc\0')['full_byte_equality'])
    def test_extended_padding(self): self.assertFalse(compare(b'abc\0',b'abc\0\0')['full_byte_equality'])
    def test_empty(self): self.assertEqual(compare(b'a',b'')['first_difference'],0)


class RelocationTargetTests(unittest.TestCase):
    def test_target_section_uses_address_not_file_offset(self):
        blob = bytearray(64)
        struct.pack_into('<QQ', blob, 0, 0x1000, 2)
        elf = SimpleNamespace(
            b=bytes(blob),
            symbols={},
            lo=0x2000,
            hi=0x3000,
            secs={
                '.rel.dyn': (0, 9, 0, 0, 0, 16, 0, 0, 1, 16),
                '.rodata': (0, 1, 2, 0x1000, 0x20, 0x100, 0, 0, 1, 0),
            },
        )
        report = deep_section_analysis.analyze_relocations(elf)
        self.assertEqual(report['entries'][0]['target_section'], '.rodata')


class InstructionLogNameTests(unittest.TestCase):
    def names(self, name):
        blob = (analyze.ROOT / 'evidence/original' / name / 'deployed.so').read_bytes()
        return set(analyze.instruction_log_names(blob, analyze.known_instruction_names(name)))

    def test_idl_names_do_not_absorb_adjacent_text(self):
        pump = self.names('pump')
        self.assertIn('Buy', pump)
        self.assertIn('UpdateBuybackConfig', pump)
        self.assertIn('IdlResizeAccount', pump)
        self.assertNotIn('BuyCreateV2Disabled', pump)
        self.assertNotIn('UpdateBuybackConfigAn', pump)
        self.assertNotIn('IdlResizeAccountdata', pump)

        amm = self.names('pump_amm')
        self.assertIn('ClaimCashback', amm)
        self.assertIn('IdlCreateAccount', amm)
        self.assertNotIn('ClaimCashbacksol', amm)
        self.assertNotIn('IdlCreateAccountanchor', amm)

        fees = self.names('pump_fees')
        self.assertIn('Withdraw', fees)
        self.assertIn('CrankDonationFeePda', fees)
        self.assertNotIn('Withdrawaccountsol', fees)
        self.assertNotIn('CrankDonationFeePdaFee', fees)

    def test_program_names_fall_back_to_captures(self):
        self.assertEqual(
            analyze.program_names(),
            ['pump', 'pump_amm', 'pump_fees', 'mayhem'],
        )

    def test_mayhem_fallback_is_unchanged(self):
        names = self.names('mayhem')
        self.assertEqual(len(names), 25)
        self.assertIn('Buy', names)
        self.assertIn('InitializeGlobalParams', names)


if __name__=='__main__': unittest.main()
