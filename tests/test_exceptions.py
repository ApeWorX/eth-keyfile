import os

import pytest

from eth_keyfile.exceptions import (
    EthKeyfileException,
)


def test_ethkeyfileexception_with_user_message():
    with pytest.raises(EthKeyfileException) as exception:
        raise EthKeyfileException(user_message="This failed!")
    assert exception.type is EthKeyfileException
    assert exception.value.user_message == "This failed!"


def test_ethkeyfileexception_with_kwargs():
    with pytest.raises(TypeError) as exception:
        raise EthKeyfileException(data={"message": "Unable to fulfill your request."})

    # For Python > 3.9, str exception includes 'EthKeyfileException.'
    expected = "__init__() got an unexpected keyword argument 'data'"
    actual = str(exception.value)
    assert exception.type is TypeError
    assert hasattr(exception.value, "data") is False
    assert expected in actual


def test_ethkeyfileexception_with_args():
    with pytest.raises(EthKeyfileException) as exception:
        raise EthKeyfileException("failed")
    assert exception.type is EthKeyfileException
    assert exception.value.user_message is None
    assert exception.value.args[0] == "failed"


ETH_KEYFILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "eth_keyfile"
)
DEFAULT_EXCEPTIONS = (
    NotImplementedError,
    TypeError,
    ValueError,
)


def test_no_default_exceptions_are_raised_within_py_geth():
    for root, _dirs, files in os.walk(ETH_KEYFILE_PATH):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, encoding="utf-8") as f:
                    for idx, line in enumerate(f):
                        for exception in DEFAULT_EXCEPTIONS:
                            exception_name = exception.__name__
                            if f"raise {exception_name}" in line:
                                raise Exception(
                                    f"``{exception_name}`` raised in eth-keyfile file "
                                    f"``{file}``, line {idx + 1}. "
                                    f"Replace with ``EthKeyfile{exception_name}``:\n"
                                    f"    file_path:{file_path}\n"
                                    f"    line:{idx + 1}"
                                )
