"""Esquemas das mensagens HTTP da loja."""

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegistrationIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("O nome não pode conter apenas espaços.")
        return value


class RegistrationOut(BaseModel):
    user_id: int
    name: str
    email: str
    totp_secret: str
    otpauth_uri: str


class PasswordLoginIn(BaseModel):
    email: EmailStr
    password: str


class PasswordLoginOut(BaseModel):
    challenge: str
    expires_in: int


class TotpLoginIn(BaseModel):
    challenge: str
    code: str = Field(pattern=r"^[0-9]{6}$")


class TotpLoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    user_id: int
    name: str
    email: str
