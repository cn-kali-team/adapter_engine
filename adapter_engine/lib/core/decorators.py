import hashlib


def cached_method(f, cache=None):
    """
    Method with a cached content
    Reference: http://code.activestate.com/recipes/325205-cache-decorator-in-python-24/
    """

    if cache is None:
        cache = {}

    def _(*args, **kwargs):
        key_string = "|".join(str(_) for _ in (f, args, kwargs)).encode()
        key = int(hashlib.md5(key_string).hexdigest(), 16) & 0x7fffffffffffffff
        if key not in cache:
            cache[key] = f(*args, **kwargs)

        return cache[key]

    return _
