"""Security boundary checks for untrusted BOM file paths."""

import tempfile
import unittest
from pathlib import Path

from bomtrace import firmware_path


class FirmwarePathTests(unittest.TestCase):
    def test_rejects_paths_outside_firmware_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for value in ("../outside", "etc/../../outside", "C:/Windows/win.ini", "//server/share", "\\\\server\\share"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    firmware_path(root, value)

    def test_absolute_firmware_path_is_root_relative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target, relative = firmware_path(root, "/etc/device/edge.pem")
            self.assertEqual(target, root / "etc/device/edge.pem")
            self.assertEqual(relative, "etc/device/edge.pem")


if __name__ == "__main__":
    unittest.main()
