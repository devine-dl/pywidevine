class PyWidevineException(Exception):
    """Exceptions used by pywidevine."""


class TooManySessions(PyWidevineException):
    """Too many Sessions are open."""


class InvalidSession(PyWidevineException):
    """No Session is open with the specified identifier."""


class InvalidInitData(PyWidevineException):
    """The Widevine Cenc Header Data is invalid or empty."""


class InvalidLicenseType(PyWidevineException):
    """The License Type is an Invalid Value."""


class InvalidLicenseMessage(PyWidevineException):
    """The License Message is Invalid or Missing."""


class InvalidContext(PyWidevineException):
    """The Context is Invalid or Missing."""


class SignatureMismatch(PyWidevineException):
    """The Signature did not match."""


class NoKeysLoaded(PyWidevineException):
    """No License was parsed for this Session, No Keys available."""


class DeviceMismatch(PyWidevineException):
    """The Remote CDMs Device information and the APIs Device information did not match."""
