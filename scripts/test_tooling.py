#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import pump_diagnostic_audit
from compare import compare


class PanicPayloadTests(unittest.TestCase):
    def audit(self, left, right):
        return pump_diagnostic_audit.audit({'synthetic': {'cases': [{
            'original': {'logs': [left]}, 'candidate': {'logs': [right]},
        }]}})

    def test_legacy_multiline_first_line_is_not_discarded(self):
        result = self.audit("Program log: panicked at 'first A\nshared tail', src/lib.rs:1:2",
                            "Program log: panicked at 'first B\nshared tail', src/lib.rs:1:2")
        self.assertEqual(result['log_bearing_cases'], 1)
        self.assertEqual(len(result['mismatches']), 1)
        self.assertEqual(result['mismatches'][0]['original']['panic'], ['first A\nshared tail'])

    def test_legacy_source_locations_are_excluded_from_the_payload(self):
        for message in ('same message', "same 'quoted' message\nsecond line"):
            with self.subTest(message=message):
                result = self.audit(f"Program log: panicked at '{message}', old/src.rs:1:2",
                                    f"Program log: panicked at '{message}', new/src.rs:90:7")
                self.assertEqual(result['mismatches'], [])

    def test_modern_payload_and_location_boundary_are_preserved(self):
        result = self.audit('Program log: panicked at old/src.rs:1:2:\nfirst\nsecond',
                            'Program log: panicked at new/src.rs:90:7:\nfirst\nsecond')
        self.assertEqual(result['mismatches'], [])
        self.assertEqual(pump_diagnostic_audit.messages(['Program log: panicked at src.rs:1:2:\nfirst\nsecond'])['panic'], ['first\nsecond'])

    def test_unrecognized_multiline_text_is_compared_in_full(self):
        for left, right in (
            ('custom first A\nshared tail', 'custom first B\nshared tail'),
            ('message A:١:٢:\nshared tail', 'message B:١:٢:\nshared tail'),
        ):
            with self.subTest(left=left):
                result = self.audit('Program log: panicked at ' + left, 'Program log: panicked at ' + right)
                self.assertEqual(len(result['mismatches']), 1)

    def test_real_cli_fails_for_a_changed_legacy_first_line(self):
        temporary_root = analyze.ROOT / 'work'
        temporary_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='panic-audit-', dir=temporary_root) as folder:
            report, output = Path(folder) / 'input.json', Path(folder) / 'output.json'
            data = {'suites': {'synthetic': {'cases': [{
                'original': {'logs': ["Program log: panicked at 'A\nshared', src.rs:1:2"]},
                'candidate': {'logs': ["Program log: panicked at 'B\nshared', src.rs:1:2"]},
            }]}}}
            raw = json.dumps(data).encode('utf-8')
            report.write_bytes(raw)
            result = subprocess.run([sys.executable, pump_diagnostic_audit.__file__, '--report', str(report), '--output', str(output)], capture_output=True)
            self.assertEqual(result.returncode, 1)
            audited = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(len(audited['mismatches']), 1)
            self.assertEqual(audited['source_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(report.read_bytes(), raw)
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
