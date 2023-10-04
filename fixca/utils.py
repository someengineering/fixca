import time
from functools import wraps
from typing import Callable, Any, Tuple, Dict, Union, TypeVar, Type


def str_to_bool(s: Union[str, bool]) -> bool:
    return str(s).lower() in ("true", "1", "yes")


RT = TypeVar("RT")


def memoize(
    ttl: int = 60, cleanup_interval: int = 600, time_fn: Callable[[], float] = time.time
) -> Callable[[Callable[..., RT]], Callable[..., RT]]:
    last_cleanup: float = 0.0
    cache: Dict[Tuple[Callable[..., RT], Tuple[Any, ...], frozenset[Tuple[str, Any]]], Tuple[RT, float]] = {}

    def decorating_function(user_function: Callable[..., RT]) -> Callable[..., RT]:
        @wraps(user_function)
        def wrapper(*args: Any, **kwargs: Any) -> RT:
            now = time_fn()
            key = (user_function, args, frozenset(kwargs.items()))
            if key in cache:
                result, timestamp = cache[key]
                if now - timestamp < ttl:
                    return result

            result = user_function(*args, **kwargs)
            cache[key] = (result, now)

            nonlocal last_cleanup
            if now - last_cleanup > cleanup_interval:
                for k in [k for k, v in cache.items() if now - v[1] >= ttl]:
                    cache.pop(k)
                last_cleanup = now

            return result

        return wrapper

    return decorating_function
