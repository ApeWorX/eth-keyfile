import copy
import hashlib

import pytest
from eth_utils import (
    big_endian_to_int,
    keccak,
)

from eth_keyfile.exceptions import (
    EthKeyfileValueError,
)
from eth_keyfile.keyfile import (
    _pbkdf2_hash,
    _scrypt_hash,
    create_keyfile_json,
    decode_keyfile_json,
    encrypt_aes_ctr,
)

PRIVATE_KEY = b"\x11" * 32
PASSWORD = b"correct horse"
SALT = b"\x22" * 16
IV = b"\x33" * 16


def _derive(kdf, dklen):
    if kdf == "pbkdf2":
        return _pbkdf2_hash(PASSWORD, "sha256", SALT, 2, dklen)
    return _scrypt_hash(PASSWORD, salt=SALT, n=2, r=1, p=1, buflen=dklen)


def _kdf_params(kdf, dklen):
    if kdf == "pbkdf2":
        return {"c": 2, "dklen": dklen, "prf": "hmac-sha256", "salt": SALT.hex()}
    return {"dklen": dklen, "n": 2, "r": 1, "p": 1, "salt": SALT.hex()}


def _v3_keyfile(kdf, dklen):
    # Build a v3 keyfile the same way create_keyfile_json does, but with the
    # given dklen.
    derived_key = _derive(kdf, dklen)
    ciphertext = encrypt_aes_ctr(PRIVATE_KEY, derived_key[:16], big_endian_to_int(IV))
    return {
        "version": 3,
        "address": "00" * 20,
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": IV.hex()},
            "ciphertext": ciphertext.hex(),
            "kdf": kdf,
            "kdfparams": _kdf_params(kdf, dklen),
            "mac": keccak(derived_key[16:32] + ciphertext).hex(),
        },
    }


def _v4_keyfile(kdf, dklen):
    derived_key = _derive(kdf, dklen)
    message = encrypt_aes_ctr(PRIVATE_KEY, derived_key[:16], big_endian_to_int(IV))
    return {
        "version": 4,
        "crypto": {
            "kdf": {"function": kdf, "params": _kdf_params(kdf, dklen), "message": ""},
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": hashlib.sha256(derived_key[16:32] + message).hexdigest(),
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": IV.hex()},
                "message": message.hex(),
            },
        },
    }


@pytest.mark.parametrize("make_keyfile", (_v3_keyfile, _v4_keyfile), ids=("v3", "v4"))
@pytest.mark.parametrize("kdf", ("pbkdf2", "scrypt"))
def test_dklen_16_keyfile_does_not_accept_wrong_password(make_keyfile, kdf):
    # With dklen=16, derived_key[16:32] is empty, so the MAC/checksum does not
    # depend on the password and any password used to "decrypt" the keyfile.
    keyfile_json = make_keyfile(kdf, 16)
    for password in (PASSWORD, b"wrong password", b""):
        with pytest.raises(EthKeyfileValueError, match="dklen"):
            decode_keyfile_json(keyfile_json, password)


@pytest.mark.parametrize("make_keyfile", (_v3_keyfile, _v4_keyfile), ids=("v3", "v4"))
@pytest.mark.parametrize("kdf", ("pbkdf2", "scrypt"))
@pytest.mark.parametrize("dklen", (0, 8, 31, -1, "32", 32.0, True, None))
def test_invalid_dklen_is_rejected(make_keyfile, kdf, dklen):
    keyfile_json = copy.deepcopy(make_keyfile(kdf, 32))
    if keyfile_json["version"] == 3:
        keyfile_json["crypto"]["kdfparams"]["dklen"] = dklen
    else:
        keyfile_json["crypto"]["kdf"]["params"]["dklen"] = dklen
    with pytest.raises(EthKeyfileValueError, match="dklen"):
        decode_keyfile_json(keyfile_json, PASSWORD)


@pytest.mark.parametrize("make_keyfile", (_v3_keyfile, _v4_keyfile), ids=("v3", "v4"))
@pytest.mark.parametrize("kdf", ("pbkdf2", "scrypt"))
@pytest.mark.parametrize("dklen", (32, 64))
def test_dklen_of_at_least_32_still_decodes(make_keyfile, kdf, dklen):
    keyfile_json = make_keyfile(kdf, dklen)
    assert decode_keyfile_json(keyfile_json, PASSWORD) == PRIVATE_KEY
    with pytest.raises(EthKeyfileValueError, match="mismatch"):
        decode_keyfile_json(keyfile_json, b"wrong password")


@pytest.mark.parametrize("kdf", ("pbkdf2", "scrypt"))
def test_created_keyfile_round_trips(kdf):
    keyfile_json = create_keyfile_json(PRIVATE_KEY, PASSWORD, kdf=kdf, iterations=2)
    assert decode_keyfile_json(keyfile_json, PASSWORD) == PRIVATE_KEY
