"""Keep the replicated-messaging source's author and publication identity exact."""
import csv
from pathlib import Path
import unittest


class MessagingBibliography(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / 'reference-audit.csv'
        with path.open(encoding='utf-8-sig', newline='') as stream:
            cls.rows = [row for row in csv.DictReader(stream) if row['key'] == 'huang01']

    def test_exact_authors(self):
        self.assertEqual(len(self.rows), 1)
        self.assertEqual(self.rows[0]['authors'], 'Yongqiang Huang and Hector Garcia-Molina')

    def test_publication_identity(self):
        self.assertEqual(len(self.rows), 1)
        row = self.rows[0]
        self.assertEqual(row['year'], '2001')
        self.assertEqual(row['pages'], '3--12')
        self.assertEqual(row['doi'].lower(), '10.1109/icde.2001.914808')
        self.assertEqual(row['scholarly_or_official_locator'].lower(), 'https://doi.org/' + row['doi'].lower())


if __name__ == '__main__':
    unittest.main()
