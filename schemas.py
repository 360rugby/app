from typing import Optional, List
from pydantic import BaseModel
from datetime import date



class UserBase(BaseModel):
    NombreUsuario: str
    CorreoElectronico: str
    Idioma: Optional[str] = "en"
    ZonaHoraria: Optional[str] = "UTC"
    

class UserCreate(UserBase):
    Contrasena: str


class UserUpdate(UserBase):
    Contrasena: Optional[str] = None


class UserRoleBase(BaseModel):
    RolID: int
    UsuarioID: int


class RoleBase(BaseModel):
    NombreRol: str
    DescripcionRol: str


class User(UserBase):
    UsuarioID: int
    FechaCreacion: Optional[date]
    FechaActualizacion: Optional[date]
    Token: Optional[str] = None
    roles: List[UserRoleBase] = [{"RolID": 2}]   # Asumiendo que un usuario puede tener múltiples roles.

    class Config:
        orm_mode = True


class Role(RoleBase):
    RolID: int

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
