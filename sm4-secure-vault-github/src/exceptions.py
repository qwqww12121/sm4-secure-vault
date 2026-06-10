"""Custom exceptions used by the secure vault."""


class VaultError(Exception):
    """Base class for all vault-specific errors."""


class VaultNotInitializedError(VaultError):
    """Raised when an operation needs an initialized vault."""


class VaultAlreadyInitializedError(VaultError):
    """Raised when initializing an existing vault."""


class WrongPasswordError(VaultError):
    """Raised when the supplied password cannot unlock the vault."""


class FileAlreadyExistsError(VaultError):
    """Raised when importing a duplicate filename into the vault."""


class FileNotFoundInVaultError(VaultError):
    """Raised when a requested filename is not present in the vault."""


class InvalidCiphertextError(VaultError):
    """Raised when encrypted data is malformed or fails authentication."""
