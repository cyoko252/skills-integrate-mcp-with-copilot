import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional


PASSWORD_ITERATIONS = 310_000
SESSION_TTL_SECONDS = 8 * 60 * 60
TEACHERS_FILE = Path(__file__).with_name("teachers.json")


def hash_password(password: str, salt: Optional[bytes] = None) -> Dict[str, Any]:
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(password_hash).decode("ascii"),
        "iterations": PASSWORD_ITERATIONS,
    }


def verify_password(password: str, credential: Dict[str, Any]) -> bool:
    try:
        salt = base64.b64decode(credential["salt"], validate=True)
        expected_hash = base64.b64decode(credential["password_hash"], validate=True)
        iterations = int(credential["iterations"])
        if iterations < 1:
            return False
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False

    return hmac.compare_digest(actual_hash, expected_hash)


def load_teachers(path: Path = TEACHERS_FILE) -> Dict[str, Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Unable to read teacher credentials") from error

    teachers = data.get("teachers", {}) if isinstance(data, dict) else None
    if not isinstance(teachers, dict):
        raise RuntimeError("Teacher credentials must contain a teachers object")
    return teachers


def verify_teacher(username: str, password: str, path: Path = TEACHERS_FILE) -> bool:
    credential = load_teachers(path).get(username)
    return isinstance(credential, dict) and verify_password(password, credential)


def _encode_urlsafe(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def create_session_token(
    username: str, secret: bytes, now: Optional[int] = None
) -> str:
    issued_at = int(time.time()) if now is None else now
    payload = json.dumps(
        {"username": username, "expires_at": issued_at + SESSION_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = _encode_urlsafe(payload)
    signature = hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_encode_urlsafe(signature)}"


def get_session_username(
    token: Optional[str], secret: bytes, now: Optional[int] = None
) -> Optional[str]:
    if not token:
        return None

    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected_signature = hmac.new(
            secret, encoded_payload.encode("ascii"), hashlib.sha256
        ).digest()
        signature_padding = "=" * (-len(encoded_signature) % 4)
        supplied_signature = base64.urlsafe_b64decode(
            encoded_signature + signature_padding
        )
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return None

        payload_padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(encoded_payload + payload_padding)
        )
        username = payload["username"]
        expires_at = int(payload["expires_at"])
    except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
        return None

    current_time = int(time.time()) if now is None else now
    if not isinstance(username, str) or not username or expires_at <= current_time:
        return None
    return username