\
\
\
\
   

import importlib
import sys
import types
import unittest

def _install_fake_winreg():
    fake = types.ModuleType("winreg")
    fake.HKEY_CURRENT_USER = "HKCU"
    fake.HKEY_LOCAL_MACHINE = "HKLM"
    fake.registry = {}

    def open_key(hive, subkey):
        entry = fake.registry.get((hive, subkey))
        if entry is None:
            raise OSError("key not found")
        return (hive, subkey)

    def enum_value(key, index):
        values = fake.registry.get(key, [])
        if index >= len(values):
            raise OSError("no more values")
        name, value = values[index]
        return name, value, 1

    def close_key(_key):
        return None

    fake.OpenKey = open_key
    fake.EnumValue = enum_value
    fake.CloseKey = close_key
    sys.modules["winreg"] = fake
    return fake

FAKE_WINREG = _install_fake_winreg()

from keylogger_finder.platforms import windows_checks              

importlib.reload(windows_checks)

class WindowsRegistryTests(unittest.TestCase):
    def setUp(self):
        FAKE_WINREG.registry = {}

    def test_known_signature_in_run_key_is_critical(self):
        FAKE_WINREG.registry[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
            ("Updater", r"C:\Users\Public\ardamax\ardamax.exe"),
        ]
        findings = windows_checks.check_registry_run_keys()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_temp_path_in_run_key_is_low(self):
        FAKE_WINREG.registry[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
            ("Helper", r"C:\Users\bob\AppData\Local\Temp\helper.exe"),
        ]
        findings = windows_checks.check_registry_run_keys()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")

    def test_normal_entry_is_not_flagged(self):
        FAKE_WINREG.registry[("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")] = [
            ("OneDrive", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"),
        ]
        findings = windows_checks.check_registry_run_keys()
        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
