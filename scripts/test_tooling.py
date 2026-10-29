#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import codecs
import gzip
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
import check_sbf_backend_diagnostics as backend_diagnostics
import test_sbf_backend_diagnostics as backend_cases
from compare import compare


class BackendLogSignatureTests(unittest.TestCase):
    def setUp(self):
        folder = analyze.ROOT / 'work'
        folder.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='backend-bom-', dir=folder)
        self.path = Path(self.temporary.name) / 'build.log'

    def tearDown(self):
        self.temporary.cleanup()

    def test_bom_errors_reject_in_plain_gzip_and_ansi_logs(self):
        for compressed in (False, True):
            for colored in (False, True):
                with self.subTest(compressed=compressed, colored=colored):
                    line = ('\x1b[31m' if colored else '') + backend_cases.ERROR + ('\x1b[0m' if colored else '')
                    decoded = codecs.BOM_UTF8 + (line + '\nCargo exit: 0\nstrip exit: 0\n').encode('utf-8')
                    raw = gzip.compress(decoded, mtime=0) if compressed else decoded
                    self.path.write_bytes(raw)
                    result = backend_diagnostics.check([self.path])
                    self.assertFalse(result['diagnostic_gate_passed'])
                    self.assertEqual(result['backend_error_count'], 1)
                    record = result['logs'][0]
                    self.assertEqual(record['backend_errors'][0]['kind'], 'stack_offset_exceeded')
                    self.assertEqual(record['backend_errors'][0]['line_number'], 1)
                    self.assertEqual(record['input_sha256'], hashlib.sha256(raw).hexdigest())
                    self.assertEqual(record['decoded_sha256'], hashlib.sha256(decoded).hexdigest())
                    self.assertEqual(self.path.read_bytes(), raw)

    def test_clean_bom_log_still_makes_no_readiness_claim(self):
        self.path.write_bytes(codecs.BOM_UTF8 + b'Finished release\n')
        result = backend_diagnostics.check([self.path])
        self.assertTrue(result['diagnostic_gate_passed'])
        self.assertFalse(result['program_readiness_proven'])

    def test_only_the_initial_signature_is_removed(self):
        self.path.write_bytes(codecs.BOM_UTF8 + 'Error: internal \ufeff payload\n'.encode('utf-8'))
        errors = backend_diagnostics.inspect(self.path)['backend_errors']
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['text'], 'Error: internal \ufeff payload')

    def test_actual_cli_rejects_a_bom_prefixed_error(self):
        self.path.write_bytes(codecs.BOM_UTF8 + (backend_cases.ERROR + '\n').encode('utf-8'))
        result = subprocess.run([sys.executable, backend_diagnostics.__file__, '--log', str(self.path)], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['diagnostic_gate_passed'])
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
