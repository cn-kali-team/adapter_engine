from http.client import HTTPException


class AdapterBaseException(Exception):
    pass


class AdapterValidationException(AdapterBaseException):
    pass


class AdapterIncompleteRead(HTTPException):
    def __init__(self, partial, expected=None):
        self.args = partial,
        self.partial = partial
        self.expected = expected

    def __repr__(self):
        if self.expected is not None:
            e = ', %i more expected' % self.expected
        else:
            e = ''
        return '%s(%i bytes read%s)' % (self.__class__.__name__,
                                        len(self.partial), e)

    def __str__(self):
        return repr(self)
