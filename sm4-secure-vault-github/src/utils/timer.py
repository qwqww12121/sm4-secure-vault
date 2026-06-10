"""Small timing helper."""

from __future__ import annotations

from time import perf_counter
from typing import Any, Callable


def time_function(func: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """Run func and return its result plus elapsed seconds."""
    start = perf_counter()
    result = func(*args, **kwargs)
    return result, perf_counter() - start
