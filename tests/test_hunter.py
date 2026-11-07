import unittest
from hunter import classify, parse_catalog

class TestHunter(unittest.TestCase):
    def test_prohibited(self):
        label, _ = classify('Customers may not use the Service to engage in cryptocurrency mining.')
        self.assertEqual(label, 'possible_prohibition_review')
    def test_allowed_not_authorization(self):
        label, _ = classify('For the avoidance of doubt, cryptocurrency mining is not a prohibited activity.')
        self.assertEqual(label, 'possible_permission_review')
    def test_silence_is_not_permission(self):
        self.assertEqual(classify('Free CPU instance included for web applications.')[0], 'no_explicit_mining_permission_found')
    def test_catalog_section_filter(self):
        md='## PaaS\n* [Alpha](https://a.example/) - free\n## DNS\n* [B](https://b.example/) - free\n'
        self.assertEqual([x['name'] for x in parse_catalog(md)], ['Alpha'])

if __name__ == '__main__': unittest.main()
