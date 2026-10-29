#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import warnings
from types import SimpleNamespace
import deep_section_analysis
import analyze
import analyze_program
import deep_disassembly
from window_elf_reader import Elf
from compare import compare


class AnalysisInputSnapshotTests(unittest.TestCase):
    def check_generation(self, module, replace):
        parent = analyze.ROOT / 'work'
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='analysis-input-', dir=parent) as folder:
            view = Path(folder)
            source = view / 'evidence/original/mayhem/deployed.so'
            source.parent.mkdir(parents=True)
            shutil.copyfile(analyze.ROOT / 'evidence/original/mayhem/deployed.so', source)
            snapshot = Elf(source)
            original = snapshot.b
            replacement = bytearray(original)
            replacement[snapshot.entries[0] + 4] ^= 1
            replacement.extend(b'\0' * 8)
            output = view / 'packet'
            original_repo, original_reader, original_argv = module.REPO, module.Elf, sys.argv

            class ReplaceAfterRealRead(original_reader):
                def __init__(self, path):
                    super().__init__(path)
                    if replace:
                        path.write_bytes(replacement)

            try:
                module.REPO = view
                module.Elf = ReplaceAfterRealRead
                sys.argv = [module.__file__, '--program', 'mayhem', '--output', str(output)]
                with contextlib.redirect_stdout(io.StringIO()), warnings.catch_warnings():
                    warnings.simplefilter("ignore", ResourceWarning)
                    if module is analyze_program:
                        result = module.analyze_program('mayhem', output)
                    else:
                        result = module.main()
                self.assertEqual(result, 0)
            finally:
                module.REPO, module.Elf, sys.argv = original_repo, original_reader, original_argv

            self.assertEqual(source.read_bytes(), replacement if replace else original)
            summary = json.loads((output / 'summary.json').read_bytes())
            digest = hashlib.sha256(original).hexdigest()
            self.assertEqual(summary['deployed_sha256'], digest)
            self.assertIn(digest, (output / 'README.md').read_text(encoding='utf-8'))
            if module is analyze_program:
                self.assertEqual(summary['file_size'], len(original))
                self.assertIn(f'File size: {len(original):,} bytes', (output / 'README.md').read_text(encoding='utf-8'))
                windows = json.loads((output / 'window-inventory.json').read_bytes())
                first = windows[0]
                self.assertEqual(first['raw_sha256'], hashlib.sha256(original[first['address_decimal']:first['address_decimal'] + first['size']]).hexdigest())

    def test_replaced_files_do_not_rebind_already_parsed_analysis(self):
        # The instrumented read parses real ELF bytes before replacing only
        # the temporary path. No analysis results or digest values are mocked.
        for module in (analyze_program, deep_disassembly, deep_section_analysis):
            with self.subTest(generator=module.__name__):
                self.check_generation(module, True)

    def test_unchanged_inputs_keep_their_existing_identity(self):
        for module in (analyze_program, deep_disassembly, deep_section_analysis):
            with self.subTest(generator=module.__name__):
                self.check_generation(module, False)


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
