import pytest
from eth_utils import (
    decode_hex,
    to_bytes,
)

from eth_keyfile.exceptions import (
    EthKeyfileValueError,
)
from eth_keyfile.keyfile import (
    MAX_V3_PRIVATE_KEY,
    MAX_V4_PRIVATE_KEY,
    create_keyfile_json,
    decode_keyfile_json,
)

PRIVATE_KEY = decode_hex(
    "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
)
PASSWORD = b"foo"

PRIVATE_KEYS_VALID_FOR_3_AND_4 = [
    decode_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
    decode_hex("21eac69b9a52f466bfe9047f0f21c9caf3a5cdaadf84e2750a9b3265d450d481"),
    to_bytes(MAX_V4_PRIVATE_KEY),
]
PRIVATE_KEYS_VALID_FOR_3_NOT_4 = [
    decode_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"),
    decode_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
]

PRIVATE_KEYS_INVALID_FOR_3_AND_4 = [
    decode_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    to_bytes(MAX_V3_PRIVATE_KEY + 1),
]

VALID_V3 = PRIVATE_KEYS_VALID_FOR_3_AND_4 + PRIVATE_KEYS_VALID_FOR_3_NOT_4
VALID_V4 = PRIVATE_KEYS_VALID_FOR_3_AND_4
INVALID_V3 = PRIVATE_KEYS_INVALID_FOR_3_AND_4
INVALID_V4 = PRIVATE_KEYS_VALID_FOR_3_NOT_4 + PRIVATE_KEYS_INVALID_FOR_3_AND_4


@pytest.mark.parametrize("private_key", VALID_V3)
@pytest.mark.parametrize("kdf", ["pbkdf2", "scrypt"])
@pytest.mark.parametrize("iterations", [1, 2, 4])
def test_keyfile_v3_creation(private_key, kdf, iterations):
    keyfile_json = create_keyfile_json(
        private_key,
        password=PASSWORD,
        version=3,
        kdf=kdf,
        iterations=iterations,
    )
    derived_private_key = decode_keyfile_json(keyfile_json, PASSWORD)
    assert derived_private_key == private_key


@pytest.mark.parametrize("private_key", VALID_V4)
@pytest.mark.parametrize("kdf", ["pbkdf2", "scrypt"])
@pytest.mark.parametrize("iterations", [1, 2, 4])
@pytest.mark.parametrize("salt_size", [1, 8, 9, 64, 128])
@pytest.mark.parametrize("description", ["", "foo", "bar"])
@pytest.mark.parametrize("path", ["a/b", "m/12381/60/3141592653/589793238"])
def test_keyfile_v4_creation(
    private_key, kdf, iterations, salt_size, description, path
):
    keyfile_json = create_keyfile_json(
        private_key,
        password=PASSWORD,
        version=4,
        kdf=kdf,
        iterations=iterations,
        salt_size=salt_size,
        description=description,
        path=path,
    )
    derived_private_key = decode_keyfile_json(keyfile_json, PASSWORD)
    assert derived_private_key == private_key


@pytest.mark.parametrize("private_key", INVALID_V3)
def test_invalid_v3_private_key_raises(private_key):
    with pytest.raises(EthKeyfileValueError):
        create_keyfile_json(
            private_key,
            password=PASSWORD,
            version=3,
        )


@pytest.mark.parametrize("private_key", INVALID_V4)
def test_invalid_v4_private_key_raises(private_key):
    with pytest.raises(EthKeyfileValueError):
        create_keyfile_json(
            private_key,
            password=PASSWORD,
            version=4,
        )


def test_pbkdf2_keyfile_salt32_creation():
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password=PASSWORD,
        kdf="pbkdf2",
        iterations=1,
        salt_size=32,
    )
    assert len(keyfile_json["crypto"]["kdfparams"]["salt"]) == 32 * 2
    derived_private_key = decode_keyfile_json(keyfile_json, PASSWORD)
    assert derived_private_key == PRIVATE_KEY


def test_scrypt_keyfile_address():
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password=PASSWORD,
        kdf="scrypt",
        iterations=2,
    )
    assert keyfile_json["address"] == "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b"


def recursive_check_dicts(dict1, dict2):
    for key in dict1:
        if isinstance(dict1[key], dict):
            recursive_check_dicts(dict1[key], dict2[key])
        else:
            assert type(dict1[key]) is type(dict2[key])


@pytest.mark.parametrize("kdf", ["pbkdf2", "scrypt"])
def test_v4_create_datatypes_match(kdf, v4_keyfile_data):
    test_pk = v4_keyfile_data[kdf]["priv"]
    test_pw = v4_keyfile_data[kdf]["password"]
    new_keyfile = create_keyfile_json(
        private_key=decode_hex(test_pk),
        password=test_pw.encode("utf-8"),
        version=4,
        kdf=kdf,
        description=v4_keyfile_data[kdf]["json"]["description"],
        path=v4_keyfile_data[kdf]["json"]["path"],
    )
    recursive_check_dicts(new_keyfile, v4_keyfile_data[kdf]["json"])
