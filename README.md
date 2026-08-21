# eth-keyfile

[![Build Status](https://github.com/ApeWorX/eth-keyfile/actions/workflows/test.yaml/badge.svg)](https://github.com/ApeWorX/eth-keyfile/actions/workflows/test.yaml)
[![PyPI version](https://badge.fury.io/py/eth-keyfile.svg)](https://badge.fury.io/py/eth-keyfile)
[![Python versions](https://img.shields.io/pypi/pyversions/eth-keyfile.svg)](https://pypi.python.org/pypi/eth-keyfile)

A library for handling the encrypted keyfiles used to store ethereum private keys

> This library and repository was previously located at https://github.com/pipermerriam/ethereum-keyfile. It was transferred to the Ethereum foundation github in November 2017 and renamed to `eth-keyfile`. The PyPi package was also renamed from `ethereum-keyfile` to `eth-keyfile`.

Read more in the documentation below.

View the [change log](https://github.com/ApeWorX/eth-keyfile/blob/main/CHANGELOG.rst).

## Installation

```sh
python -m pip install eth-keyfile
```

## Documentation

### `eth_keyfile.load_keyfile(path_or_file_obj) --> keyfile_json`

Takes either a filesystem path represented as a string or a file object and
returns the parsed keyfile json as a python dictionary.

```python
>>> from eth_keyfile import load_keyfile
>>> load_keyfile('path/to-my-keystore/keystore.json')
{
    "crypto" : {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {
            "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
        },
        "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf" : "pbkdf2",
        "kdfparams" : {
            "c" : 262144,
            "dklen" : 32,
            "prf" : "hmac-sha256",
            "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        },
        "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
    },
    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version" : 3
}
```

### `eth_keyfile.create_keyfile_json(private_key, password, kdf="pbkdf2", work_factor=None, salt_size=16) --> keyfile_json`

Takes the following parameters:

- `private_key`: A bytestring of length 32. [See note below.](#a-note-on-private-keys)
- `password`: A bytestring which will be the password that can be used to decrypt the resulting keyfile.
- `version`: An `int` to select the keyfile standard to use. Supported are `3` and `4`. Defaults to `3`.
- `kdf`: A `str` to select the key derivation function. Allowed values are `pbkdf2` and `scrypt`. By default, `pbkdf2` will be used.
- `iterations`: An `int` to set the work factor which will be used for the given key derivation function. By default `1000000` will be used for `pbkdf2` and `262144` for `scrypt`.
- `salt_size`: An `int` to define the size of the randomly-generated salt in bytes. Defaults to `16` for v3 and `32` for v4.
- `description`: (v4 only) An optional `str` for a user-defined message, generally to be able to tell one keyfile from another. Defaults to an empty string.
- `path`: (v4 only) An optional `str` to indicate where in the key-tree a key originates from. Defaults to an empty string. See [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334) for more detail.

Returns the keyfile json as a python dictionary.

```python
>>> private_key = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
>>> create_keyfile_json(private_key, b'foo')
{
    "address" : "1a642f0e3c3af545e7acbd38b07251b3990914f1",
    "crypto" : {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {
            "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
        },
        "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf" : "pbkdf2",
        "kdfparams" : {
            "c" : 262144,
            "dklen" : 32,
            "prf" : "hmac-sha256",
            "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        },
        "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
    },
    "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version" : 3
}

>>> create_keyfile_json(private_key, b'foo', version=4)
 {
    'crypto': {
        'checksum': {
            'function': 'sha256',
            'message': '66a4883a8017c9ef2854acc0c46af6cc8943de5bcf6bb501a2d6a932a91c5333',
            'params': {}
        },
        'cipher': {
            'function': 'aes-128-ctr',
            'message': '584fbbc86d65a92c1e0dfcaa3ba46c4790d31382c5dba25c94acfa2ae6e2687d',
            'params': {
                'iv': 'f948a84c4072cc3f38c82f6f672fa8a9'
            }
        },
        'kdf': {
            'function': 'pbkdf2',
            'message': '',
            'params': {
                'c': 1000000,
                'dklen': 32,
                'prf': 'hmac-sha256',
                'salt': 'd0a1d8a34e7b8bdffbe34e1152ee0bcf3dba64c6e1539cf2bce2ef6995061757'
            }
        }
    },
    'description': '',
    'path': '',
    'pubkey': 'aa1a1c26055a329817a5759d877a2795f9499b97d6056edde0eea39512f24e8bc874b4471f0501127abb1ea0d9f68ac1',
    'uuid': '92c3f383-e8ea-47a1-a1d7-55adccfae8fe',
    'version': 4}
```

#### A note on private keys

> Valid values for private keys are more limited with the keyfile v4 standard.
>
> In v3, a valid key must be less than
> '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
> a limit which most users are unlikely to run into.
>
> In v4, the key must be less than '0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'.
>
> These limits are due to the cryptographic functions used. `secp256k1` is used for v3,
> while `bls12-381` is used for v4.

### `eth_keyfile.decode_keyfile_json(keyfile_json, password) --> private_key`

Takes the keyfile json as a python dictionary and the password for the keyfile,
returning the decoded private key.

```python
>>> keyfile_json = {
...     "crypto" : {
...         "cipher" : "aes-128-ctr",
...         "cipherparams" : {
...             "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
...         },
...         "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
...         "kdf" : "pbkdf2",
...         "kdfparams" : {
...             "c" : 262144,
...             "dklen" : 32,
...             "prf" : "hmac-sha256",
...             "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
...         },
...         "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
...     },
...     "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
...     "version" : 3
... }
>>> decode_keyfile_json(keyfile_json, b'foo')
b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
```

### `eth_keyfile.extract_key_from_keyfile(path_or_file_obj, password) --> private_key`

Takes a filesystem path represented by a string or a file object and the
password for the keyfile. Returns the private key as a bytestring.

```python
>>> extract_key_from_keyfile('path/to-my-keystore/keyfile.json', b'foo')
b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
```

## Developer Setup

We use [prek](https://prek.j178.dev) to maintain consistent code style. Once
installed, it will run automatically with every commit. You can also run it manually
with `uv run prek run --all-files --show-diff-on-failure`. If you
need to make a commit that skips the `prek` checks, you can do so with
`git commit --no-verify`.

### Development Environment Setup

You can set up your dev environment with the `dev` dependency group, which is
installed by default when you run `uv sync`.

```sh
git clone --recurse-submodules git@github.com:ApeWorX/eth-keyfile.git
cd eth-keyfile
uv sync
uv run prek install
```

Common development commands:

```sh
uv run --group test pytest tests/core tests/test_exceptions.py
uv run --group lint ruff check .
uv run --group lint ruff format --check .
uv run --group lint --group test mypy .
uv build
```

### Release setup

Versions are derived from Git tags by `setuptools-scm`. To release a new version,
create a GitHub Release for the desired tag. The release workflow builds the package
and publishes to PyPI through trusted publishing.

The version format for this repo is `{major}.{minor}.{patch}` for stable, and
`{major}.{minor}.{patch}-{stage}.{devnum}` for unstable (`stage` can be alpha or beta).
