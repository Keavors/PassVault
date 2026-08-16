# -*- coding: utf-8 -*-
import unittest

from pvault import generator as gen


class GeneratorTest(unittest.TestCase):
    def opts(self, **kw):
        o = dict(gen.DEFAULT_GEN)
        o.update(kw)
        return o

    def test_exact_length_and_constraints(self):
        o = self.opts(exact_mode=True, exact_len=20, required_chars="Ж#",
                      excluded_chars="abcdef", no_ambiguous=True,
                      require_each=True)
        for _ in range(200):
            p, pool = gen.generate_password(o)
            self.assertEqual(len(p), 20)
            self.assertIn("Ж", p)
            self.assertIn("#", p)
            self.assertFalse((set("abcdef") | set(gen.AMBIGUOUS)) & set(p))
            self.assertTrue(any(c in gen.GROUP_LOWER for c in p))
            self.assertTrue(any(c in gen.GROUP_UPPER for c in p))
            self.assertTrue(any(c in gen.GROUP_DIGITS for c in p))
            self.assertGreater(pool, 0)

    def test_range_length_varies(self):
        o = self.opts(exact_mode=False, min_len=10, max_len=14)
        lengths = {len(gen.generate_password(o)[0]) for _ in range(300)}
        self.assertTrue(lengths <= set(range(10, 15)))
        self.assertGreaterEqual(len(lengths), 3)

    def test_reversed_range_is_tolerated(self):
        o = self.opts(exact_mode=False, min_len=20, max_len=10)
        for _ in range(50):
            self.assertTrue(10 <= len(gen.generate_password(o)[0]) <= 20)

    def test_only_required_chars_mode(self):
        o = self.opts(use_lower=False, use_upper=False, use_digits=False,
                      use_symbols=False, required_chars="XY",
                      exact_mode=True, exact_len=8, require_each=False)
        p, _ = gen.generate_password(o)
        self.assertEqual(len(p), 8)
        self.assertTrue(set(p) <= {"X", "Y"})

    def test_empty_alphabet_errors(self):
        o = self.opts(use_lower=False, use_upper=False, use_digits=False,
                      use_symbols=False, required_chars="")
        with self.assertRaises(gen.GeneratorError):
            gen.generate_password(o)

    def test_empty_symbol_set_is_not_ignored(self):
        """Галочка стоит, набор пуст — раньше это молча игнорировалось."""
        o = self.opts(use_symbols=True, symbols="")
        with self.assertRaises(gen.GeneratorError) as ctx:
            gen.generate_password(o)
        self.assertIn("пуст", str(ctx.exception))

    def test_required_longer_than_length(self):
        o = self.opts(exact_mode=True, exact_len=3, required_chars="ABCDE",
                      require_each=False)
        with self.assertRaises(gen.GeneratorError):
            gen.generate_password(o)

    def test_required_and_excluded_conflict(self):
        o = self.opts(required_chars="a", excluded_chars="a")
        with self.assertRaises(gen.GeneratorError):
            gen.generate_password(o)

    def test_group_fully_excluded_errors(self):
        o = self.opts(use_upper=False, use_symbols=False, use_lower=False,
                      use_digits=True, excluded_chars="0123456789",
                      required_chars="Z")
        with self.assertRaises(gen.GeneratorError) as ctx:
            gen.generate_password(o)
        self.assertIn("цифры", str(ctx.exception))

    def test_entropy_estimate_is_conservative(self):
        plain = gen.estimate_bits(gen.DEFAULT_GEN, 20, 70)
        forced = gen.estimate_bits(self.opts(required_chars="ABCDE"), 20, 70)
        self.assertLess(forced, plain)
        self.assertEqual(gen.estimate_bits(gen.DEFAULT_GEN, 20, 1), 0.0)

    def test_ambiguous_set_matches_android(self):
        """Набор обязан совпадать с Android: иначе одна галочка работает
        по-разному на двух устройствах."""
        self.assertEqual(gen.AMBIGUOUS, "Il1O0o5S2Z8B|`'\"{}[]()<>")

    def test_rating_thresholds(self):
        self.assertEqual(gen.rate_bits(30), "слабый")
        self.assertEqual(gen.rate_bits(50), "средний")
        self.assertEqual(gen.rate_bits(70), "хороший")
        self.assertEqual(gen.rate_bits(100), "отличный")
