import time
from fixca.utils import memoize, str_to_bool


fake_time = time.time()


def test_memoize() -> None:
    global fake_time
    foo1 = foo()
    assert foo() == foo1
    fake_time += 2
    assert foo() != foo1


@memoize(ttl=1, time_fn=lambda: fake_time)
def foo() -> float:
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
