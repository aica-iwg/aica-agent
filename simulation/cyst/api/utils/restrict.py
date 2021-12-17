import inspect

from pydoc import locate

type_list = {}


def parametrized(dec):
    def layer(*args, **kwargs):
        def repl(f):
            return dec(f, *args, **kwargs)
        return repl
    return layer


@parametrized
def restrict(fn, *types: str):
    def wrapper(*args, **kwargs):
        frame_info = inspect.stack(0)[1]
        caller = frame_info.frame.f_locals['self']
        for x in types:
            if isinstance(x, str):
                if x not in type_list:
                    t = locate(x)
                    if not t:
                        raise ValueError("Attempting to restrict access to an unknown type {}".format(x))
                    type_list[x] = t
                else:
                    t = type_list[x]
            else:
                t = x
            if issubclass(type(caller), t):
                raise AttributeError("Attempting to access a function/property restricted to {}".format(x))
        return fn(*args, **kwargs)
    return wrapper
