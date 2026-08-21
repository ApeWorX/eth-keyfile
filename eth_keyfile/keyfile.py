import hashlib
import hmac
import io
import json
from typing import (
    IO,
    Any,
    AnyStr,
    Literal,
    TypeVar,
    cast,
)
from unicodedata import (
    normalize,
)
from uuid import (
    uuid4,
)

from Crypto import (
    Random,
)
from Crypto.Cipher import (
    AES,
)
from Crypto.Hash import (
    SHA256,
)
from Crypto.Protocol.KDF import (
    scrypt,
)
from Crypto.Util import (
    Counter,
)
from eth_keys import (
    keys,
)
from eth_typing import (
    HexStr,
)
from eth_utils import (
    big_endian_to_int,
    decode_hex,
    encode_hex,
    is_dict,
    is_string,
    keccak,
    remove_0x_prefix,
    to_dict,
    to_int,
)
from py_ecc.bls import (
    G2ProofOfPossession as bls,
)
from py_ecc.bls12_381 import (
    curve_order,
)
from py_ecc.secp256k1 import (
    N,
)

from eth_keyfile.exceptions import (
    EthKeyfileNotImplementedError,
    EthKeyfileTypeError,
    EthKeyfileValueError,
)

UNICODE_CONTROL_CHARS = list(range(0x00, 0x20)) + list(range(0x7F, 0xA0))

# the maximum valid private key for secp256k1
MAX_V3_PRIVATE_KEY = N - 1

# the maximum valid private key for bls12-381
MAX_V4_PRIVATE_KEY = curve_order - 1

KDFType = Literal["pbkdf2", "scrypt"]
TKey = TypeVar("TKey")
TVal = TypeVar("TVal")


def encode_hex_no_prefix(value: AnyStr) -> HexStr:
    return remove_0x_prefix(encode_hex(value))


def load_keyfile(path_or_file_obj: str | IO[str]) -> Any:
    if is_string(path_or_file_obj):
        assert isinstance(path_or_file_obj, str)
        with open(path_or_file_obj) as keyfile_file:
            return json.load(keyfile_file)
    else:
        assert isinstance(path_or_file_obj, io.TextIOBase)
        return json.load(path_or_file_obj)


def create_keyfile_json(
    private_key: bytes | bytearray | memoryview,
    password: bytes,
    version: int = 3,
    kdf: KDFType = "pbkdf2",
    iterations: int | None = None,
    salt_size: int | None = None,
    description: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    if version == 3:
        return _create_v3_keyfile_json(
            private_key, password, kdf, iterations, salt_size
        )
    if version == 4:
        return _create_v4_keyfile_json(
            private_key, password, kdf, iterations, salt_size, description, path
        )
    else:
        raise EthKeyfileNotImplementedError("Not yet implemented")


def decode_keyfile_json(raw_keyfile_json: dict[Any, Any], password: bytes) -> bytes:
    keyfile_json = normalize_keys(raw_keyfile_json)
    version = keyfile_json["version"]

    if version == 3:
        return _decode_keyfile_json_v3(keyfile_json, password)
    if version == 4:
        return _decode_keyfile_json_v4(keyfile_json, password)
    else:
        raise EthKeyfileNotImplementedError("Not yet implemented")


def extract_key_from_keyfile(path_or_file_obj: str | IO[str], password: bytes) -> bytes:
    keyfile_json = load_keyfile(path_or_file_obj)
    private_key = decode_keyfile_json(keyfile_json, password)
    return private_key


@to_dict
def normalize_keys(keyfile_json: dict[Any, Any]) -> Any:
    for key, value in keyfile_json.items():
        if is_string(key):
            norm_key = key.lower()
        else:
            norm_key = key

        if is_dict(value):
            norm_value = normalize_keys(value)
        else:
            norm_value = value

        yield norm_key, norm_value


#
# Version 3 creator
#
DKLEN = 32
SCRYPT_R = 8
SCRYPT_P = 1


def _create_v3_keyfile_json(
    private_key: bytes | bytearray | memoryview,
    password: bytes,
    kdf: KDFType,
    work_factor: int | None = None,
    salt_size: int | None = None,
) -> dict[str, Any]:
    if work_factor is None:
        work_factor = get_default_work_factor_for_kdf(kdf)
    if salt_size is None:
        salt_size = 16

    if to_int(private_key) > MAX_V3_PRIVATE_KEY:
        raise EthKeyfileValueError(
            "Invalid `private_key`, exceeds maximum valid secp256k1 key "
            f"value of {MAX_V3_PRIVATE_KEY}"
        )

    salt = Random.get_random_bytes(salt_size)

    if kdf == "pbkdf2":
        derived_key = _pbkdf2_hash(
            password,
            hash_name="sha256",
            salt=salt,
            iterations=work_factor,
            dklen=DKLEN,
        )
        kdfparams = {
            "c": work_factor,
            "dklen": DKLEN,
            "prf": "hmac-sha256",
            "salt": encode_hex_no_prefix(salt),
        }
    elif kdf == "scrypt":
        derived_key = _scrypt_hash(
            password,
            salt=salt,
            buflen=DKLEN,
            r=SCRYPT_R,
            p=SCRYPT_P,
            n=work_factor,
        )
        kdfparams = {
            "dklen": DKLEN,
            "n": work_factor,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": encode_hex_no_prefix(salt),
        }
    else:
        raise EthKeyfileNotImplementedError(f"KDF not implemented: {kdf}")

    iv_bytes = Random.get_random_bytes(16)
    encrypt_key = derived_key[:16]
    ciphertext = encrypt_aes_ctr(private_key, encrypt_key, big_endian_to_int(iv_bytes))
    mac = keccak(derived_key[16:32] + ciphertext)

    address = keys.PrivateKey(private_key).public_key.to_checksum_address()

    return {
        "address": remove_0x_prefix(address),
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": iv_bytes.hex(),
            },
            "ciphertext": encode_hex_no_prefix(ciphertext),
            "kdf": kdf,
            "kdfparams": kdfparams,
            "mac": encode_hex_no_prefix(mac),
        },
        "id": str(uuid4()),
        "version": 3,
    }


#
# Verson 3 decoder
#
def _decode_keyfile_json_v3(keyfile_json: dict[str, Any], password: bytes) -> bytes:
    crypto = keyfile_json["crypto"]
    kdf = crypto["kdf"]

    # Derive the encryption key from the password using the key derivation
    # function.
    if kdf == "pbkdf2":
        derived_key = _derive_pbkdf_key(crypto["kdfparams"], password)
    elif kdf == "scrypt":
        derived_key = _derive_scrypt_key(crypto["kdfparams"], password)
    else:
        raise EthKeyfileTypeError(f"Unsupported key derivation function: {kdf}")

    # Validate that the derived key matchs the provided MAC
    ciphertext = decode_hex(crypto["ciphertext"])
    mac = keccak(derived_key[16:32] + ciphertext)

    expected_mac = decode_hex(crypto["mac"])

    if not hmac.compare_digest(mac, expected_mac):
        raise EthKeyfileValueError("MAC mismatch")

    # Decrypt the ciphertext using the derived encryption key to get the
    # private key.
    encrypt_key = derived_key[:16]
    cipherparams = crypto["cipherparams"]
    iv = big_endian_to_int(decode_hex(cipherparams["iv"]))

    private_key = decrypt_aes_ctr(ciphertext, encrypt_key, iv)

    return private_key


#
# Version 4 creator
#


def _create_v4_keyfile_json(
    private_key: bytes | bytearray | memoryview,
    password: bytes,
    kdf: KDFType,
    work_factor: int | None = None,
    salt_size: int | None = None,
    description: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    if work_factor is None:
        work_factor = get_default_work_factor_for_kdf(kdf)
    if salt_size is None:
        salt_size = 32
    if description is None:
        description = ""
    if path is None:
        path = ""

    aes_iv = Random.get_random_bytes(16)

    if to_int(private_key) > MAX_V4_PRIVATE_KEY:
        raise EthKeyfileValueError(
            "Invalid `private_key`, exceeds maximum valid bls12-381 key "
            f"value of {MAX_V4_PRIVATE_KEY}"
        )

    salt: bytes = Random.get_random_bytes(salt_size)
    uuid: str = str(uuid4())

    # clean password
    password_str = normalize("NFKD", password.decode())
    password_str = "".join(
        c for c in password_str if ord(c) not in UNICODE_CONTROL_CHARS
    )
    clean_password = password_str.encode("UTF-8")

    if kdf == "pbkdf2":
        derived_key = _pbkdf2_hash(
            password=clean_password,
            hash_name="sha256",
            salt=salt,
            iterations=work_factor,
            dklen=DKLEN,
        )
        kdfparams = {
            "c": work_factor,
            "dklen": DKLEN,
            "prf": "hmac-sha256",
            "salt": encode_hex_no_prefix(salt),
        }
    elif kdf == "scrypt":
        derived_key = _scrypt_hash(
            password=clean_password,
            salt=salt,
            buflen=DKLEN,
            r=SCRYPT_R,
            p=SCRYPT_P,
            n=work_factor,
        )
        kdfparams = {
            "dklen": DKLEN,
            "n": work_factor,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": encode_hex_no_prefix(salt),
        }
    else:
        raise EthKeyfileNotImplementedError(f"KDF not implemented: {kdf}")

    encrypt_key = derived_key[:16]
    encoded_pk = encrypt_aes_ctr(private_key, encrypt_key, big_endian_to_int(aes_iv))
    checksum_msg = SHA256.new(derived_key[16:32] + encoded_pk)

    kdf_key = {
        "function": kdf,
        "params": kdfparams,
        "message": "",
    }

    cipher_key = {
        "function": "aes-128-ctr",
        "params": {
            "iv": aes_iv.hex(),
        },
        "message": encoded_pk.hex(),
    }

    checksum_key = {
        "function": "sha256",
        "params": {},
        "message": checksum_msg.hexdigest(),
    }

    return {
        "crypto": {
            "kdf": kdf_key,
            "checksum": checksum_key,
            "cipher": cipher_key,
        },
        "description": description,
        "pubkey": bls.SkToPk(big_endian_to_int(private_key)).hex(),
        "path": path,
        "uuid": uuid,
        "version": 4,
    }


#
# Version 4 decoder
#
def _decode_keyfile_json_v4(keyfile_json: dict[str, Any], password: bytes) -> bytes:
    crypto = keyfile_json["crypto"]
    kdf = crypto["kdf"]["function"]

    # Derive the encryption key from the password using the key derivation
    # function.
    if kdf == "pbkdf2":
        derived_key = _derive_pbkdf_key(crypto["kdf"]["params"], password)
    elif kdf == "scrypt":
        derived_key = _derive_scrypt_key(crypto["kdf"]["params"], password)
    else:
        raise EthKeyfileTypeError(f"Unsupported key derivation function: {kdf}")

    cipher_message = decode_hex(crypto["cipher"]["message"])
    checksum_message = crypto["checksum"]["message"]

    if (
        hashlib.sha256(derived_key[16:32] + cipher_message).hexdigest()
        != checksum_message
    ):
        raise EthKeyfileValueError("Checksum mismatch")

    # Decrypt the cipher message using the derived encryption key to get the
    # private key.
    encrypt_key = derived_key[:16]
    cipherparams = crypto["cipher"]["params"]
    iv = big_endian_to_int(decode_hex(cipherparams["iv"]))

    private_key = decrypt_aes_ctr(cipher_message, encrypt_key, iv)

    return private_key


#
# Key derivation
#
def _derive_pbkdf_key(kdf_params: dict[str, Any], password: bytes) -> bytes:
    salt = decode_hex(kdf_params["salt"])
    dklen = kdf_params["dklen"]
    should_be_hmac, _, hash_name = kdf_params["prf"].partition("-")
    assert should_be_hmac == "hmac"
    iterations = kdf_params["c"]

    derive_pbkdf_key = _pbkdf2_hash(password, hash_name, salt, iterations, dklen)

    return derive_pbkdf_key


def _derive_scrypt_key(kdf_params: dict[str, Any], password: bytes) -> bytes:
    salt = decode_hex(kdf_params["salt"])
    p = kdf_params["p"]
    r = kdf_params["r"]
    n = kdf_params["n"]
    buflen = kdf_params["dklen"]

    derived_scrypt_key = _scrypt_hash(
        password,
        salt=salt,
        n=n,
        r=r,
        p=p,
        buflen=buflen,
    )
    return derived_scrypt_key


def _scrypt_hash(
    password: bytes, salt: bytes, n: int, r: int, p: int, buflen: int
) -> bytes:
    derived_key = scrypt(
        # scrypt uniquely accepts str, not bytes, for password and salt
        # latin-1 is used in pycryptodome for bytes encoding/decoding
        password.decode("latin-1"),
        salt.decode("latin-1"),
        key_len=buflen,
        N=n,
        r=r,
        p=p,
        num_keys=1,
    )
    # num_keys is set to 1, so rtype will always be bytes, not Tuple[bytes, ...]
    return cast(bytes, derived_key)


def _pbkdf2_hash(
    password: bytes, hash_name: str, salt: bytes, iterations: int, dklen: int
) -> bytes:
    derived_key = hashlib.pbkdf2_hmac(
        hash_name=hash_name,
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=dklen,
    )

    return derived_key


#
# Encryption and Decryption
#
def decrypt_aes_ctr(ciphertext: bytes, key: bytes, iv: int) -> bytes:
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    return encryptor.decrypt(ciphertext)


def encrypt_aes_ctr(
    value: bytes | bytearray | memoryview, key: bytes, iv: int
) -> bytes:
    ctr = Counter.new(128, initial_value=iv, allow_wraparound=True)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = encryptor.encrypt(value)
    return ciphertext


#
# Utility
#
def get_default_work_factor_for_kdf(kdf: KDFType) -> int:
    if kdf == "pbkdf2":
        return 1000000
    elif kdf == "scrypt":
        return 262144
    else:
        raise EthKeyfileValueError(f"Unsupported key derivation function: {kdf}")
