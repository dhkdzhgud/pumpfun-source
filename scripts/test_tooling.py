#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import deep_section_analysis
import analyze
from compare import compare
class DiagnosticOutputPreservationTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, str(analyze.ROOT / 'scripts/pump_diagnostic_audit.py'),
                               '--report', str(source), '--output', str(output)],
                              capture_output=True, text=True)

    def test_input_report_cannot_be_its_own_output(self):
        parent = analyze.ROOT / 'work'
        parent.mkdir(exist_ok=True)
        for compressed in (False, True):
            with self.subTest(compressed=compressed), tempfile.TemporaryDirectory(dir=parent) as folder:
                source = Path(folder) / 'report.json'
                raw = json.dumps({'suites': {}}).encode()
                if compressed:
                    raw = gzip.compress(raw, mtime=0)
                source.write_bytes(raw)
                result = self.invoke(source, source)
                self.assertEqual(source.read_bytes(), raw)
                self.assertNotEqual(result.returncode, 0)

    def test_prior_audit_is_preserved(self):
        parent = analyze.ROOT / 'work'
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as folder:
            source, output = Path(folder) / 'report.json', Path(folder) / 'audit.json'
            raw = b'{"suites":{}}'
            prior = b'previous bounded audit\n'
            source.write_bytes(raw)
            output.write_bytes(prior)
            result = self.invoke(source, output)
            self.assertEqual(output.read_bytes(), prior)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(source.read_bytes(), raw)

    def test_fresh_outputs_preserve_success_and_mismatch_receipts(self):
        parent = analyze.ROOT / 'work'
        parent.mkdir(exist_ok=True)
        for different in (False, True):
            with self.subTest(different=different), tempfile.TemporaryDirectory(dir=parent) as folder:
                source, output = Path(folder) / 'report.json', Path(folder) / 'audit.json'
                logs = ['Program log: AnchorError. Error Code: One. Error Number: 6000. Error Message: original']
                other = [logs[0].replace('original', 'different')] if different else logs
                raw = json.dumps({'suites': {'fixture': {'original': {'logs': logs}, 'candidate': {'logs': other}}}}).encode()
                source.write_bytes(raw)
                result = self.invoke(source, output)
                self.assertEqual(result.returncode, int(different), result.stderr)
                receipt = json.loads(output.read_bytes())
                self.assertEqual(receipt['source_report_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(receipt['log_bearing_cases'], 1)
                self.assertEqual(len(receipt['mismatches']), int(different))
                self.assertEqual(source.read_bytes(), raw)


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
