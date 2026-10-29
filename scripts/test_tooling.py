#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import deep_disassembly
from window_elf_reader import Elf
from compare import compare
class ComparisonTests(unittest.TestCase):
    def test_equal(self): self.assertTrue(compare(b'abc\0\0',b'abc\0\0')['full_byte_equality'])
    def test_code_mutation(self): self.assertEqual(compare(b'abc\0\0',b'axc\0\0')['first_difference'],1)
    def test_padding_mutation(self): self.assertEqual(compare(b'abc\0\0',b'abc\0x')['first_difference'],4)
    def test_truncated_padding(self): self.assertFalse(compare(b'abc\0\0',b'abc\0')['full_byte_equality'])
    def test_extended_padding(self): self.assertFalse(compare(b'abc\0',b'abc\0\0')['full_byte_equality'])
    def test_empty(self): self.assertEqual(compare(b'a',b'')['first_difference'],0)


class NegationDecodeTests(unittest.TestCase):
    def test_negation_has_only_a_destination_operand(self):
        for opcode, mnemonic in ((0x84, 'neg32'), (0x87, 'neg64')):
            for register in (0, 3, 10):
                with self.subTest(opcode=opcode, register=register):
                    raw = struct.pack('<BBhi', opcode, register, 0, 0)
                    result, size = deep_disassembly.decode_instruction(raw, 0, None)
                    self.assertEqual(result['mnemonic'], f'{mnemonic} r{register}')
                    self.assertEqual(result['hex'], raw.hex())
                    self.assertEqual(result['imm'], 0)
                    self.assertEqual(size, 8)

    def test_binary_alu_operands_are_unchanged(self):
        for raw, expected in (
            (struct.pack('<BBhi', 0x07, 3, 0, -2), 'add64 r3, -2'),
            (struct.pack('<BBhi', 0x0f, 0x23, 0, 0), 'add64 r3, r2'),
            (struct.pack('<BBhi', 0x17, 3, 0, 0), 'sub64 r3, 0'),
        ):
            self.assertEqual(deep_disassembly.decode_instruction(raw, 0, None)[0]['mnemonic'], expected)

    def test_captured_negations_have_no_invented_immediate(self):
        expected_counts = {'pump': 25, 'pump_amm': 24, 'pump_fees': 16, 'mayhem': 30}
        for name, expected_count in expected_counts.items():
            elf = Elf(analyze.ROOT / 'evidence/original' / name / 'deployed.so')
            count = 0
            offset = elf.lo
            while offset < elf.hi:
                opcode = elf.b[offset]
                if opcode in (0x84, 0x87):
                    result, size = deep_disassembly.decode_instruction(elf.b, offset, elf)
                    self.assertEqual(result['mnemonic'], f"neg{32 if opcode == 0x84 else 64} r{elf.b[offset + 1] & 15}")
                    self.assertEqual(size, 8)
                    count += 1
                offset += 16 if opcode == 0x18 else 8
            self.assertEqual(count, expected_count, name)


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
