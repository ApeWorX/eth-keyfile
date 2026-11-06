import pytest
from eth_utils import (
    decode_hex,
)

from eth_keyfile.exceptions import (
    EthKeyfileValueError,
)
from eth_keyfile.keyfile import (
    create_keyfile_json,
    decode_keyfile_json,
)

# The password used by the EIP-2335 test vectors, before processing. NFKD turns
# the mathematical fraktur letters into plain ASCII: "testpassword🔑".
EIP2335_PASSWORD = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
EIP2335_PROCESSED_PASSWORD = "testpassword🔑"

PRIVATE_KEY = decode_hex(
    "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)

# Passwords that EIP-2335 processing changes: compatibility characters that
# NFKD rewrites, and C0 / C1 / Delete control codes that are stripped.
PASSWORDS_CHANGED_BY_PROCESSING = [
    EIP2335_PASSWORD,
    "\u2126mega",  # OHM SIGN -> GREEK CAPITAL LETTER OMEGA
    "\ufb01le",  # LATIN SMALL LIGATURE FI -> "fi"
    "pass\x7fword",  # DEL
    "pass\x00word",  # NUL
    "pass\tword\n",  # C0 controls
    "pass\x85word",  # C1 control (NEXT LINE)
]

LOW_WORK_FACTORS = {"pbkdf2": 2, "scrypt": 16}


@pytest.mark.parametrize("kdf", ["scrypt", "pbkdf2"])
def test_v4_decode_eip2335_vector_with_unprocessed_password(kdf, v4_keyfile_data):
    keyfile_json = v4_keyfile_data[kdf]["json"]
    expected = decode_hex(v4_keyfile_data[kdf]["priv"])

    assert decode_keyfile_json(keyfile_json, EIP2335_PASSWORD.encode()) == expected


@pytest.mark.parametrize("kdf", ["scrypt", "pbkdf2"])
def test_v4_decode_eip2335_vector_with_processed_password(kdf, v4_keyfile_data):
    keyfile_json = v4_keyfile_data[kdf]["json"]
    expected = decode_hex(v4_keyfile_data[kdf]["priv"])

    assert (
        decode_keyfile_json(keyfile_json, EIP2335_PROCESSED_PASSWORD.encode())
        == expected
    )


@pytest.mark.parametrize("kdf", ["scrypt", "pbkdf2"])
@pytest.mark.parametrize("password", PASSWORDS_CHANGED_BY_PROCESSING)
def test_v4_round_trip_with_password_changed_by_processing(kdf, password):
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password.encode(),
        version=4,
        kdf=kdf,
        iterations=LOW_WORK_FACTORS[kdf],
    )

    assert decode_keyfile_json(keyfile_json, password.encode()) == PRIVATE_KEY


@pytest.mark.parametrize("kdf", ["scrypt", "pbkdf2"])
def test_v4_wrong_password_still_fails(kdf):
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        b"pass\x7fword",
        version=4,
        kdf=kdf,
        iterations=LOW_WORK_FACTORS[kdf],
    )

    with pytest.raises(EthKeyfileValueError, match="Checksum mismatch"):
        decode_keyfile_json(keyfile_json, b"pass-word")


@pytest.mark.parametrize("kdf", ["scrypt", "pbkdf2"])
def test_v3_password_is_not_processed(kdf):
    # Web3 Secret Storage (v3) has no password processing: the password bytes
    # go into the KDF unchanged, so only the exact same bytes decrypt it.
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        b"pass\x7fword",
        version=3,
        kdf=kdf,
        iterations=LOW_WORK_FACTORS[kdf],
    )

    assert decode_keyfile_json(keyfile_json, b"pass\x7fword") == PRIVATE_KEY
    with pytest.raises(EthKeyfileValueError, match="MAC mismatch"):
        decode_keyfile_json(keyfile_json, b"password")
