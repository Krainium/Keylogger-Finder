\
\
\
\
   

import plistlib
import tempfile
import unittest
from pathlib import Path

from keylogger_finder.platforms import macos_checks

class MacLaunchAgentTests(unittest.TestCase):
    def test_known_signature_plist_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            plist_path = folder / "com.example.spyrixupdater.plist"
            with plist_path.open("wb") as handle:
                plistlib.dump(
                    {
                        "Label": "com.example.spyrixupdater",
                        "ProgramArguments": ["/usr/local/bin/spyrix"],
                    },
                    handle,
                )

            original_locations = macos_checks.LAUNCH_LOCATIONS
            macos_checks.LAUNCH_LOCATIONS = [folder]
            try:
                findings = macos_checks.check_launch_agents()
            finally:
                macos_checks.LAUNCH_LOCATIONS = original_locations

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_apple_plist_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            plist_path = folder / "com.apple.something.plist"
            with plist_path.open("wb") as handle:
                plistlib.dump({"Label": "com.apple.something"}, handle)

            original_locations = macos_checks.LAUNCH_LOCATIONS
            macos_checks.LAUNCH_LOCATIONS = [folder]
            try:
                findings = macos_checks.check_launch_agents()
            finally:
                macos_checks.LAUNCH_LOCATIONS = original_locations

        self.assertEqual(findings, [])

    def test_normal_third_party_plist_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            plist_path = folder / "com.dropbox.dropbox.plist"
            with plist_path.open("wb") as handle:
                plistlib.dump(
                    {
                        "Label": "com.dropbox.dropbox",
                        "ProgramArguments": ["/Applications/Dropbox.app/Contents/MacOS/Dropbox"],
                    },
                    handle,
                )

            original_locations = macos_checks.LAUNCH_LOCATIONS
            macos_checks.LAUNCH_LOCATIONS = [folder]
            try:
                findings = macos_checks.check_launch_agents()
            finally:
                macos_checks.LAUNCH_LOCATIONS = original_locations

        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
