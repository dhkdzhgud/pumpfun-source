#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import deep_disassembly
import bytecode_signatures
from compare import compare


def symbol_hash(name):
    """Independent seed-zero MurmurHash3 x86_32 reference for table checks.

    SBPF ebpf::hash_symbol_name uses hash32::Murmur3Hasher::default().
    Reference: aappleby/smhasher, MurmurHash3.cpp, MurmurHash3_x86_32.
    """
    data = name.encode('utf-8')
    mask = 0xffffffff
    def rotate(n, bits):
        return ((n << bits) | (n >> (32 - bits))) & mask
    def mix(k):
        return (rotate((k * 0xcc9e2d51) & mask, 15) * 0x1b873593) & mask
    h = 0
    complete = len(data) // 4 * 4
    for at in range(0, complete, 4):
        h ^= mix(int.from_bytes(data[at:at+4], 'little'))
        h = (rotate(h, 13) * 5 + 0xe6546b64) & mask
    if complete != len(data):
        h ^= mix(int.from_bytes(data[complete:], 'little'))
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85ebca6b & mask
    h ^= h >> 13
    h = h * 0xc2b2ae35 & mask
    return h ^ (h >> 16)


class SyscallHashTests(unittest.TestCase):
    def test_reference_vectors(self):
        self.assertEqual(symbol_hash(''), 0)
        self.assertEqual(symbol_hash('foo'), 0xf6a5c420)
        self.assertEqual(symbol_hash('sol_log_'), 0x207559bd)

    def test_each_table_key_is_the_hash_of_its_symbol(self):
        for module in (deep_disassembly, bytecode_signatures, deep_section_analysis):
            for value, name in module.SYSCALL_NAMES.items():
                with self.subTest(module=module.__name__, symbol=name):
                    self.assertEqual(value, symbol_hash(name))

    def test_literal_calls_decode_and_fingerprint_the_hashed_name(self):
        for name in deep_disassembly.SYSCALL_NAMES.values():
            with self.subTest(symbol=name):
                raw = struct.pack('<BBhI', 0x85, 0, 0, symbol_hash(name))
                result, size = deep_disassembly.decode_instruction(raw, 0, None)
                self.assertEqual(result['syscall'], name)
                self.assertEqual(size, 8)
                self.assertEqual(deep_disassembly.fingerprint_window(SimpleNamespace(b=raw), 0, 8)['syscall_sequence'], [name])

    def test_cpi_and_memcpy_selectors_use_the_same_hash_rule(self):
        cpi = b''.join(struct.pack('<BBhI', 0x85, 0, 0, symbol_hash(name))
                       for name in ('sol_invoke_signed_c', 'sol_invoke_signed_rust'))
        patterns = bytecode_signatures.detect_cpi_patterns(SimpleNamespace(b=cpi), 0, len(cpi))
        self.assertEqual([p['syscall'] for p in patterns], ['sol_invoke_signed_c', 'sol_invoke_signed_rust'])
        memcpy = struct.pack('<BBhI', 0x85, 0, 0, symbol_hash('sol_memcpy_'))
        self.assertEqual(bytecode_signatures.detect_serialization_patterns(SimpleNamespace(b=memcpy), 0, 8)['memcpy_calls'], 1)
        clock = struct.pack('<BBhI', 0x85, 0, 0, symbol_hash('sol_get_clock_sysvar'))
        self.assertEqual(bytecode_signatures.detect_cpi_patterns(SimpleNamespace(b=clock), 0, 8), [])
        self.assertEqual(bytecode_signatures.detect_serialization_patterns(SimpleNamespace(b=cpi), 0, len(cpi))['memcpy_calls'], 0)

    def test_unknown_hash_keeps_the_existing_fallback(self):
        raw = struct.pack('<BBhI', 0x85, 0, 0, 0x12345678)
        self.assertEqual(deep_disassembly.decode_instruction(raw, 0, None)[0]['syscall'], 'syscall_0x12345678')
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
