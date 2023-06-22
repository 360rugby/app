from typing import Optional, List
from pydantic import BaseModel
from datetime import date

class UserBase(BaseModel):
    NombreUsuario: str
    CorreoElectronico: str
    Idioma: Optional[str] = "Español"
    ZonaHoraria: Optional[str] = "GMT+1"

class UserCreate(UserBase):
    Contrasena: str

class UserUpdate(UserBase):
    Contrasena: Optional[str] = None

class UserRoleBase(BaseModel):
    UsuariosRolesID: int
    UsuarioID: int
    RolID: int
    NombreRol: str  # Agrega el nombre del rol aquí

class RoleBase(BaseModel):
    NombreRol: str
    DescripcionRol: str

class User(UserBase):
    UsuarioID: int
    FechaCreacion: Optional[date]
    FechaActualizacion: Optional[date]
    Token: Optional[str] = None
    PuntosLealtad: Optional[int] = 0
    #user_roles: List[UserRoleBase]  # Cambiamos esto a UserRoleBase
    user_roles_names: List[str]  # Nuevo campo
    access_token: Optional[str] = None  # New field
    refresh_token: Optional[str] = None  # New field

    class Config:
        orm_mode = True

class Role(RoleBase):
    RolID: int
    role_users: List[UserRoleBase]

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    refresh_token: str  # Nuevo campo
    token_type: str
    roles: List[str] = []  # Nuevo campo

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

class RefreshToken(BaseModel):
    refresh_token: str

class Password(BaseModel):
    old_password: str
    new_password: str