import tempfile
import unittest
from pathlib import Path

from src.auth import (
    create_session_token,
    get_session_username,
    hash_password,
    verify_password,
    verify_teacher,
)


class AuthTests(unittest.TestCase):
    def test_password_hash_verifies_only_the_original_password(self):
        credential = hash_password("correct horse battery staple")

        self.assertTrue(verify_password("correct horse battery staple", credential))
        self.assertFalse(verify_password("wrong password", credential))

    def test_teacher_credentials_are_loaded_from_json(self):
        credential = hash_password("assigned-password")
        with tempfile.TemporaryDirectory() as directory:
            teachers_file = Path(directory) / "teachers.json"
            teachers_file.write_text(
                '{"teachers":{"ms.smith":'
                + __import__("json").dumps(credential)
                + "}}",
                encoding="utf-8",
            )

            self.assertTrue(
                verify_teacher("ms.smith", "assigned-password", teachers_file)
            )
            self.assertFalse(
                verify_teacher("ms.smith", "wrong-password", teachers_file)
            )

    def test_session_token_is_signed_and_expires(self):
        secret = b"test-session-secret"
        token = create_session_token("ms.smith", secret, now=100)

        self.assertEqual(get_session_username(token, secret, now=101), "ms.smith")
        self.assertIsNone(get_session_username(token + "x", secret, now=101))
        self.assertIsNone(get_session_username(token, secret, now=100 + 8 * 60 * 60))


if __name__ == "__main__":
    unittest.main()