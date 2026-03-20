""" implements a simple wildcard string matcher """

from typing import Union

VALID_INPUT_TYPES = (str, bytes)

__all__ = [
    "complexmatch",
    "has_stars",
    "leading_wildcard_match",
    "trailing_wildcard_match",
    "match",
]

class TestNotRelevant(Exception):
    """ raised when the pattern wasn't relevant

eg: you ran leading_wildcard_match('test string", '*asdf*sdf')
"""

def _validate_input(test_value: Union[str, bytes]) -> bool:
    """ checks the input """
    if not isinstance(test_value, (str, bytes)):
        raise TypeError(f"test_string is not a valid type: {type(test_value)}, expected one of {','.join(VALID_INPUT_TYPES)}")
    return True

def has_stars(pattern: Union[str, bytes]) -> bool:
    """ checks if the pattern has stars """
    if isinstance(pattern, bytes):
        return b'*' in pattern
    return '*' in pattern

def trailing_wildcard_match(test_string: str, pattern: str) -> bool:
    """ simple "only has a trailing *" match """
    if not has_stars(pattern) or not pattern.endswith("*"):
        raise TestNotRelevant

    if not has_stars(pattern.rstrip("*")):
        if test_string.startswith(pattern.rstrip("*")):
            return True
        return False
    raise TestNotRelevant

def leading_wildcard_match(test_string: str, pattern: str) -> bool:
    """ simple "only has a leading *" match """
    if not has_stars(pattern) or not pattern.startswith("*"):
        raise TestNotRelevant

    if not has_stars(pattern.lstrip("*")):
        if test_string.endswith(pattern.lstrip("*")):
            return True
        return False
    raise TestNotRelevant

def complexmatch(test_string: str, pattern: str) -> bool:
    """ implementation of more complex match things """
    # current_index = 0

    # print(f"test string: {test_string}")
    # print(f"pattern: {pattern}")
    current_test_string = f"{test_string}"

    # chunk_index = {}
    parts = pattern.split("*")
    # print(parts)
    # print(test_string)
    for index, chunk in enumerate(parts):
        if index == 0 and not chunk.strip():
            # print("Blank start, continuing")
            continue
        if chunk not in current_test_string:
            # print(f"Couldn't find '{chunk}' in {current_test_string}")
            return False
        found_chunk = current_test_string.find(chunk)
        if found_chunk < 0:
            # print(f"Couldn't find '{chunk}' in {current_test_string}")
            return False
        # print(f"Found '{chunk}' in {current_test_string}")
        # print(current_test_string)
        current_test_string = current_test_string[found_chunk:]
    return True

def match(test_string: Union[str, bytes], pattern: str) -> bool:
    """ tests a string with a pattern """

    if test_string == pattern:
        return True
    if pattern == "*":
        return True

    # if it's not a direct string match, or a total wildcard, and there's no stars, it's not a match
    if not has_stars(pattern):
        return False

    _validate_input(test_string)

    if isinstance(test_string, bytes):
        test_string = test_string.decode("utf-8")

    # simple "only has a leading *" match
    for testfunc in (
        leading_wildcard_match,
        trailing_wildcard_match,
        complexmatch,
    ):
        try:
            return testfunc(test_string, pattern)
        except TestNotRelevant:
            pass
    return False
