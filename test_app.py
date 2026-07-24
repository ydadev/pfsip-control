import os
import unittest
from pathlib import Path

os.environ["ROUTE_PORTAL_DATA"] = str(Path(__file__).parent / ".test-data")
os.environ["ROUTE_PORTAL_ADMIN_PASSWORD"] = "temporary-test-password"

import app


class PortalTests(unittest.TestCase):
    def test_normalize_and_collapse(self):
        result, source, output = app.normalize_list(
            "10.0.0.0/25, 10.0.0.128/25\n192.0.2.10/24"
        )
        self.assertEqual(source, 3)
        self.assertEqual(output, 2)
        self.assertEqual(result, "10.0.0.0/24\n192.0.2.0/24\n")

    def test_password_hash(self):
        encoded = app.password_hash("correct horse battery staple")
        self.assertTrue(app.password_ok("correct horse battery staple", encoded))
        self.assertFalse(app.password_ok("wrong", encoded))

    def test_slug_validation(self):
        self.assertEqual(app.slugify("Office-Bypass_1"), "office-bypass_1")
        with self.assertRaises(ValueError):
            app.slugify("../../bad")

if __name__ == "__main__":
    unittest.main()
