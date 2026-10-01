"""Ensure family matching preserves header structure and ambiguity."""
import unittest
from search_remaining_families import record
from al5_segment import occurrences, START


class FamilySearchTests(unittest.TestCase):
    def test_whole_family_distinguishes_repeated_individual_records(self):
        first = record({'cells': [[20], [20]]}, 0)
        second = record({'cells': [[45], [45]]}, 0)
        other = record({'cells': [[49], [49]]}, 0)
        data = first+other+b'\xFF\xFF'+first+second
        self.assertEqual(len(occurrences(data, first)), 2)
        self.assertEqual(occurrences(data, first+second), [START+14])

    def test_identical_complete_families_remain_ambiguous(self):
        family = record({'cells': [[45], [45]]}, 0)+record({'cells': [[62], [62]]}, 0)
        self.assertEqual(len(occurrences(family+b'\xFF\xFF'+family, family)), 2)

    def test_header_is_required_and_scaling_error_rejected(self):
        needle = record({'cells': [[20], [20]]}, 0)
        self.assertEqual(occurrences(b'\x00\x03'+needle[2:], needle), [])
        with self.assertRaises(ValueError):
            record({'cells': [[20.003], [20]]}, 0)


if __name__ == '__main__':
    unittest.main()
