#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import bytecode_signatures
from window_elf_reader import Elf
from compare import compare
class ComparisonTests(unittest.TestCase):
    def test_equal(self): self.assertTrue(compare(b'abc\0\0',b'abc\0\0')['full_byte_equality'])
    def test_code_mutation(self): self.assertEqual(compare(b'abc\0\0',b'axc\0\0')['first_difference'],1)
    def test_padding_mutation(self): self.assertEqual(compare(b'abc\0\0',b'abc\0x')['first_difference'],4)
    def test_truncated_padding(self): self.assertFalse(compare(b'abc\0\0',b'abc\0')['full_byte_equality'])
    def test_extended_padding(self): self.assertFalse(compare(b'abc\0',b'abc\0\0')['full_byte_equality'])
    def test_empty(self): self.assertEqual(compare(b'a',b'')['first_difference'],0)


class SerializationBoundaryTests(unittest.TestCase):
    def detect(self, opcodes):
        raw = b''.join(struct.pack('<BBhi', opcode, 0, 0, 0) for opcode in opcodes)
        return bytecode_signatures.detect_serialization_patterns(SimpleNamespace(b=raw), 0, len(raw))

    def test_terminal_store_run_meets_the_existing_threshold(self):
        result = self.detect([0x63, 0x6b, 0x73, 0x7b])
        self.assertEqual(result['sequential_stores'], 4)
        self.assertEqual(result['max_store_run'], 4)
        self.assertTrue(result['likely_serialization'])

    def test_short_and_interrupted_runs_do_not_meet_threshold(self):
        for opcodes in ([0x63] * 3, [0x63, 0x63, 0xb7, 0x63, 0x63], []):
            with self.subTest(opcodes=opcodes):
                self.assertFalse(self.detect(opcodes)['likely_serialization'])

    def test_classification_does_not_depend_on_a_trailing_exit(self):
        for opcodes in ([0x63] * 4, [0x63] * 5, [0x63] * 2 + [0xb7] + [0x63] * 4):
            with self.subTest(opcodes=opcodes):
                self.assertEqual(self.detect(opcodes), self.detect([*opcodes, 0x95]))

    def test_retained_four_store_ranges(self):
        ranges = {'pump': 0x1788, 'pump_amm': 0xe50, 'pump_fees': 0x1bf0, 'mayhem': 0x5720}
        for name, start in ranges.items():
            with self.subTest(program=name):
                elf = Elf(analyze.ROOT / 'evidence/original' / name / 'deployed.so')
                self.assertTrue(all(elf.b[at] in (0x63, 0x6b, 0x73, 0x7b) for at in range(start, start + 32, 8)))
                result = bytecode_signatures.detect_serialization_patterns(elf, start, start + 32)
                self.assertEqual(result['max_store_run'], 4)
                self.assertTrue(result['likely_serialization'])


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
