#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
import copy
import json
import pump_validate_all as corpus
import pump_validate_parallel as parallel
from types import SimpleNamespace
import deep_section_analysis
import analyze
from compare import compare
class CaseComparisonReceiptTests(unittest.TestCase):
    original = analyze.ROOT / 'evidence/original/pump/deployed.so'
    candidate = analyze.ROOT / 'evidence/original/mayhem/deployed.so'

    def report(self, row):
        return json.loads(json.dumps({
            'original_sha256': corpus.sha(self.original),
            'candidate_sha256': corpus.sha(self.candidate),
            'case_count': corpus.EXPECTED_CASES['volume'],
            'mismatches': [],
            'cases': [copy.deepcopy(row) for _ in range(corpus.EXPECTED_CASES['volume'])],
        }))

    def validate(self, report):
        return parallel.validate_result('volume', report, self.candidate, self.original)

    def test_explicit_case_differences_cannot_hide_behind_empty_summary(self):
        for field in ('different_fields', 'diff', 'differences', 'mismatched_fields'):
            with self.subTest(field=field):
                report = self.report({'original': {}, 'candidate': {}, field: []})
                report['cases'][0][field] = ['account']
                with self.assertRaises(AssertionError):
                    self.validate(report)

    def test_false_case_match_cannot_hide_behind_empty_summary(self):
        report = self.report({'original': {}, 'candidate': {}, 'match': True})
        report['cases'][0]['match'] = False
        with self.assertRaises(AssertionError):
            self.validate(report)

    def test_missing_paired_outcomes_or_comparison_are_rejected(self):
        for row in ({'original': {}, 'match': True},
                    {'original': {}, 'candidate': None, 'diff': []},
                    {'original': {}, 'candidate': {}},
                    {'original': {}, 'candidate': {}, 'diff': None},
                    {'original': {}, 'candidate': {}, 'match': 1}):
            with self.subTest(row=row), self.assertRaises(AssertionError):
                self.validate(self.report(row))

    def test_all_published_generic_case_comparison_encodings_still_pass(self):
        for field in ('different_fields', 'diff', 'differences', 'mismatched_fields', 'match'):
            with self.subTest(field=field):
                self.assertEqual(self.validate(self.report({
                    'original': {}, 'candidate': {}, field: True if field == 'match' else [],
                })), corpus.EXPECTED_CASES['volume'])


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
