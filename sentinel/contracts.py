from datetime import date
from typing import Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator
from typing_extensions import Annotated

Package = Annotated[
    str,
    StringConstraints(
        max_length=255, pattern=r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"
    ),
]
Fingerprint = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


class Credentials(BaseModel):
    email: str = Field(
        min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    )
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        normalized = value.casefold()
        if len(normalized) > 254 or any(ord(char) < 32 for char in normalized):
            raise ValueError("Invalid email")
        return normalized


class TrustedRecord(BaseModel):
    package: Package
    publisher: str = Field(min_length=1, max_length=160)
    label: str = Field(min_length=1, max_length=160)
    source: str = Field(max_length=500, pattern=r"^https://[^\s]+$")
    evidence: str = Field(min_length=12, max_length=2000)
    verified_on: date
    status: Literal["active", "revoked"]
    signer_sets: list[list[Fingerprint]] = Field(min_length=1, max_length=20)
    icon_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")

    @field_validator("signer_sets")
    @classmethod
    def valid_sets(cls, sets):
        if any(
            not 1 <= len(signers) <= 8 or len(set(signers)) != len(signers)
            for signers in sets
        ):
            raise ValueError("Each signer set must include 1 to 8 unique fingerprints")
        return sets
