"""Exceptions."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .utility import DominionSCTFAHandler


class CannotConnect(Exception):
    """Error to indicate we cannot connect. This is a retryable exception."""

    def __init__(
        self,
        message: str,
        url: str | None = None,
        status: int | None = None,
        response_text: str | None = None,
    ) -> None:
        """Initialize the exception."""
        super().__init__(message)
        self.url = url
        self.status = status
        self.response_text = response_text

    def __str__(self) -> str:
        """Return a string representation of the exception."""
        parts = [super().__str__()]
        if self.url is not None:
            parts.append(f"URL: {self.url}")
        if self.status is not None:
            parts.append(f"Status: {self.status}")
        if self.response_text is not None:
            parts.append(f"Response: {self.response_text}")
        return "\n".join(parts)


class InvalidAuth(Exception):
    """Error to indicate there is invalid auth."""


class MfaChallenge(Exception):
    """Raised when MFA is required and user interaction is needed."""

    def __init__(self, message: str, handler: "DominionSCTFAHandler") -> None:
        """Initialize the exception."""
        super().__init__(message)
        self.handler = handler


class ApiException(Exception):
    """Raised during problems talking to the API (response received but not as expected)."""

    def __init__(
        self,
        message: str,
        url: str,
        status: int | None = None,
        response_text: str | None = None,
    ) -> None:
        """Initialize the exception."""
        super().__init__(message)
        self.url = url
        self.status = status
        self.response_text = response_text

    def __str__(self) -> str:
        """Return a string representation of the exception."""
        parts = [super().__str__()]
        parts.append(f"URL: {self.url}")
        if self.status is not None:
            parts.append(f"Status: {self.status}")
        if self.response_text is not None:
            parts.append(f"Response: {self.response_text}")
        return "\n".join(parts)
