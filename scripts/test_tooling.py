#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import pump_validate_parallel
from compare import compare


class ParallelCaseCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = analyze.ROOT / 'evidence/original/pump/deployed.so'
        cls.digest = pump_validate_parallel.sha(cls.artifact)

    def suites(self):
        return {name: count for name, count in pump_validate_parallel.base.EXPECTED_CASES.items()
                if name not in ('quote_control', 'multi_hop_curve_partial', 'tokenkeg_two_curve')}

    def report(self, count):
        return self.artifact, {'original_sha256': self.digest, 'candidate_sha256': self.digest,
                          'case_count': count, 'mismatches': []}

    def test_missing_or_nonarray_cases_cannot_support_a_declared_count(self):
        for name, count in self.suites().items():
            for cases in (None, {}, 'not a case list'):
                with self.subTest(suite=name, cases=cases):
                    artifact, report = self.report(count)
                    if cases is not None:
                        report['cases'] = cases
                    with self.assertRaises(AssertionError):
                        pump_validate_parallel.validate_result(name, report, artifact, artifact)

    def test_declared_count_must_equal_the_retained_case_list(self):
        for name, count in self.suites().items():
            for length in (0, count - 1, count + 1):
                with self.subTest(suite=name, length=length):
                    artifact, report = self.report(count)
                    report['cases'] = [{'case': index} for index in range(length)]
                    with self.assertRaises(AssertionError):
                        pump_validate_parallel.validate_result(name, report, artifact, artifact)

    def test_consistent_explicit_and_derived_counts_remain_accepted(self):
        # These are shape-validation fixtures, not newly executed VM cases.
        for name, count in self.suites().items():
            for explicit_count in (True, False):
                with self.subTest(suite=name, explicit_count=explicit_count):
                    artifact, report = self.report(count)
                    report['cases'] = [{'case': index} for index in range(count)]
                    if not explicit_count:
                        del report['case_count']
                    self.assertEqual(pump_validate_parallel.validate_result(name, report, artifact, artifact), count)

    def test_special_suite_count_protocols_are_unchanged(self):
        artifact = self.artifact
        reports = {
            'quote_control': {'bound_inputs_sha256': {str(artifact.relative_to(analyze.ROOT)): self.digest},
                              'cases': 507, 'results': [{'matches': True, 'different_fields': []} for _ in range(507)]},
            'multi_hop_curve_partial': {'candidate_sha256': self.digest, 'original_pump_sha256': self.digest,
                                        'passed': 56, 'case_count': 56, 'cases': [{'mismatches': []} for _ in range(56)]},
            'tokenkeg_two_curve': {'candidate_sha256': self.digest,
                                  'provenance': {'repository_inputs': {'evidence/original/pump/deployed.so': self.digest}},
                                  'inputs_unchanged': True, 'case_count': 20, 'original_successes': 16,
                                  'original_pump_cpi_cases': 18, 'verified_outer_signatures': 40,
                                  'cases': [{'candidate': {}, 'mismatches': []} for _ in range(20)]},
        }
        for name, special in reports.items():
            with self.subTest(suite=name):
                self.assertEqual(pump_validate_parallel.validate_result(name, special, artifact, artifact),
                                 pump_validate_parallel.base.EXPECTED_CASES[name])
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
