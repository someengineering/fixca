import time
from fixca.utils import memoize, str_to_bool


def test_memoize() -> None:
    foo1 = foo()
    time.sleep(0.1)
    assert foo() == foo1
    time.sleep(1.1)
    assert foo() != foo1


@memoize(ttl=1)
def foo() -> int:
    return time.time()


def test_str_to_bool() -> None:
    assert str_to_bool("true") is True
    assert str_to_bool("false") is False
    assert str_to_bool("1") is True
    assert str_to_bool("0") is False
    assert str_to_bool("yes") is True
    assert str_to_bool("no") is False
    assert str_to_bool(True) is True
    assert str_to_bool(False) is False
    assert str_to_bool("qwerty") is False
