#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import deep_disassembly
from compare import compare


class StackAddressOperandTests(unittest.TestCase):
    def analyze(self, *instructions):
        raw = b''.join(struct.pack('<BBhi', *instruction) for instruction in instructions)
        decoded = []
        for offset in range(0, len(raw), 8):
            decoded.append(deep_disassembly.decode_instruction(raw, offset, None)[0])
        return deep_disassembly.analyze_stack_frame(decoded)

    def test_storing_frame_pointer_value_is_not_a_stack_address(self):
        # stxdw [r1-64], r10: r1 is the address; r10 is only the stored value.
        result = self.analyze((0x7b, 0xa1, -64, 0))
        self.assertEqual(result, {'max_stack_depth': 0, 'stack_slots': 0, 'most_accessed_offsets': []})

    def test_frame_pointer_as_both_base_and_value_counts_once(self):
        result = self.analyze((0x7b, 0xaa, -16, 0))
        self.assertEqual(result['max_stack_depth'], 16)
        self.assertEqual(result['most_accessed_offsets'], [{'offset': -16, 'count': 1}])

    def test_load_and_store_address_bases_keep_real_stack_accesses(self):
        result = self.analyze(
            (0x79, 0xa2, -24, 0),  # ldxdw r2, [r10-24]
            (0x7b, 0x2a, -24, 0),  # stxdw [r10-24], r2
            (0x7a, 0x0a, -8, 5),  # stdw [r10-8], 5
        )
        self.assertEqual(result['max_stack_depth'], 24)
        self.assertEqual(result['stack_slots'], 2)
        self.assertEqual(result['most_accessed_offsets'], [{'offset': -24, 'count': 2}, {'offset': -8, 'count': 1}])

    def test_nonmemory_frame_pointer_operand_does_not_count(self):
        self.assertEqual(self.analyze((0xbf, 0xa1, 0, 0))['stack_slots'], 0)
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
