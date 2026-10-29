#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
from compare import compare


class GeneratedPacketMembershipTests(unittest.TestCase):
    generators = (
        ('analyze_program.py', 'function-index.json'),
        ('deep_disassembly.py', 'fingerprints.json'),
        ('deep_section_analysis.py', 'summary.json'),
        ('bytecode_signatures.py', 'shared-signatures.json'),
    )

    @classmethod
    def run_python(cls, script, *arguments):
        env = dict(os.environ, PYTHONUTF8='1')
        return subprocess.run([sys.executable, str(script), *map(str, arguments)],
                              env=env, capture_output=True, timeout=60)

    @classmethod
    def setUpClass(cls):
        folder = analyze.ROOT / 'work'
        folder.mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix='packet-membership-', dir=folder)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.packets = {}
        for script, _ in cls.generators:
            output = cls.root / Path(script).stem
            arguments = [] if script == 'bytecode_signatures.py' else ['--program', 'mayhem']
            result = cls.run_python(analyze.ROOT / 'scripts' / script, *arguments, '--output', output)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            cls.packets[script] = output

    def test_complete_generated_packets_verify(self):
        for name, output in self.packets.items():
            with self.subTest(generator=name):
                result = self.run_python(output / 'verify.py')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_artifact_cannot_be_removed_from_the_manifest(self):
        for script, target in self.generators:
            with self.subTest(generator=script):
                output = self.packets[script]
                manifest_path = output / 'manifest.json'
                raw, artifact = manifest_path.read_bytes(), (output / target).read_bytes()
                manifest = json.loads(raw)
                del manifest[target]
                try:
                    (output / target).unlink()
                    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
                    self.assertNotEqual(self.run_python(output / 'verify.py').returncode, 0)
                finally:
                    (output / target).write_bytes(artifact)
                    manifest_path.write_bytes(raw)

    def test_existing_artifact_cannot_be_left_unmanifested(self):
        for script, target in self.generators:
            with self.subTest(generator=script):
                output = self.packets[script]
                path = output / 'manifest.json'
                raw = path.read_bytes()
                manifest = json.loads(raw)
                del manifest[target]
                try:
                    path.write_text(json.dumps(manifest), encoding='utf-8')
                    self.assertNotEqual(self.run_python(output / 'verify.py').returncode, 0)
                finally:
                    path.write_bytes(raw)

    def test_unrelated_file_cannot_be_admitted_by_adding_its_hash(self):
        for script, _ in self.generators:
            with self.subTest(generator=script):
                output = self.packets[script]
                path = output / 'manifest.json'
                raw = path.read_bytes()
                manifest = json.loads(raw)
                extra = output / 'unrelated.txt'
                data = b'not produced by the generator'
                try:
                    extra.write_bytes(data)
                    manifest[extra.name] = hashlib.sha256(data).hexdigest()
                    path.write_text(json.dumps(manifest), encoding='utf-8')
                    self.assertNotEqual(self.run_python(output / 'verify.py').returncode, 0)
                finally:
                    extra.unlink()
                    path.write_bytes(raw)

    def test_existing_digest_checks_still_reject_changed_bytes(self):
        for script, target in self.generators:
            with self.subTest(generator=script):
                output = self.packets[script]
                artifact = output / target
                raw = artifact.read_bytes()
                try:
                    artifact.write_bytes(raw + b'\n ')
                    self.assertNotEqual(self.run_python(output / 'verify.py').returncode, 0)
                finally:
                    artifact.write_bytes(raw)

    def test_partial_signature_packet_keeps_its_generated_program_set(self):
        view = self.root / 'partial-view'
        (view / 'scripts').mkdir(parents=True)
        capture = view / 'evidence/original/mayhem/deployed.so'
        capture.parent.mkdir(parents=True)
        shutil.copyfile(analyze.ROOT / 'evidence/original/mayhem/deployed.so', capture)
        for name in ('bytecode_signatures.py', 'window_elf_reader.py'):
            shutil.copyfile(analyze.ROOT / 'scripts' / name, view / 'scripts' / name)
        output = view / 'packet'
        generated = self.run_python(view / 'scripts/bytecode_signatures.py', '--output', output)
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        self.assertEqual(self.run_python(output / 'verify.py').returncode, 0)
        manifest = json.loads((output / 'manifest.json').read_bytes())
        self.assertIn('mayhem-signatures.json', manifest)
        self.assertNotIn('pump-signatures.json', manifest)
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
