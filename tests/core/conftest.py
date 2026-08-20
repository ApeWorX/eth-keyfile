import json
import os

import pytest

import eth_keyfile

FIXTURES_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(eth_keyfile.__file__)),
    "fixtures",
    "KeyStoreTests",
    "basic_tests.json",
)

MEW_KEYFILE = {
    "json": {
        "Crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "7e7b02d2b4ef45d6c98cb885e75f48d5",
            },
            "ciphertext": "a7a5743a6c7eb3fa52396bd3fd94043b79075aac3ccbae8e62d3af94db00397c",  # noqa: E501
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 8192,
                "p": 1,
                "r": 8,
                "salt": "247797c7a357b707a3bdbfaa55f4c553756bca09fec20ddc938e7636d21e4a20",  # noqa: E501
            },
            "mac": "5a3ba5bebfda2c384586eda5fcda9c8397d37c9b0cc347fea86525cf2ea3a468",
        },
        "address": "0b6f2de3dee015a95d3330dcb7baf8e08aa0112d",
        "id": "3c8efdd6-d538-47ec-b241-36783d3418b9",
        "version": 3,
    },
    "password": "moomoocow",
    "priv": "21eac69b9a52f466bfe9047f0f21c9caf3a5cdaadf84e2750a9b3265d450d481",
}

# https://eips.ethereum.org/EIPS/eip-2335#test-cases
SCRYPT_KEYFILE_V4 = {
    "json": {
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",  # noqa: E501
                },
                "message": "",
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484",  # noqa: E501
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f",  # noqa: E501
            },
        },
        "description": "This is a test keystore that uses scrypt to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",  # noqa: E501
        "path": "m/12381/60/3141592653/589793238",
        "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        "version": 4,
    },
    "password": "testpassword🔑",
    "priv": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
}

PBKDF2_KEYFILE_V4 = {
    "json": {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32,
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",  # noqa: E501
                },
                "message": "",
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1",  # noqa: E501
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad",  # noqa: E501
            },
        },
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",  # noqa: E501
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4,
    },
    "password": "testpassword🔑",
    "priv": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
}

with open(FIXTURES_FILE_PATH) as fixtures_file:
    BASE_KEYFILE_FIXTURES = json.load(fixtures_file)


KEYFILE_FIXTURES = BASE_KEYFILE_FIXTURES.copy()
KEYFILE_FIXTURES.update(
    {
        "MEW_generated_keyfile": MEW_KEYFILE,
        "scrypt_keyfile_v4": SCRYPT_KEYFILE_V4,
        "pbkdf2_keyfile_v4": PBKDF2_KEYFILE_V4,
    }
)


@pytest.fixture(params=KEYFILE_FIXTURES.keys())
def keyfile_data(request):
    return KEYFILE_FIXTURES[request.param]


@pytest.fixture
def v4_keyfile_data():
    return {"scrypt": SCRYPT_KEYFILE_V4, "pbkdf2": PBKDF2_KEYFILE_V4}
