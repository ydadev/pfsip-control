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

    def test_alias_validation(self):
        self.assertEqual(app.validate_alias("ROUTE_VIA_AMNEZIA"), "ROUTE_VIA_AMNEZIA")
        self.assertEqual(app.validate_alias(""), "")
        with self.assertRaises(ValueError):
            app.validate_alias("bad; command")

if __name__ == "__main__":
    unittest.main()
