from typing import Optional, List, Dict
from pydantic import BaseModel, constr
from datetime import date, datetime, time
import re

class UserBase(BaseModel):
    NombreUsuario: str
    CorreoElectronico: str
    Idioma: Optional[str] = "Español"
    ZonaHoraria: Optional[str] = "GMT+1"

class UserCreate(UserBase):
    Contrasena: str
    ConfirmarContrasena: str
    Movil: Optional[constr(regex="^[0-9]{9}$")] = None  # Sólo se permiten 9 dígitos

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
    Movil: Optional[str] = None
    PuntosLealtad: Optional[int] = 0
    user_roles: List[UserRoleBase]  # Cambiamos esto a UserRoleBase
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

class UserResponse(BaseModel):
    UsuarioID: int
    NombreUsuario: str
    CorreoElectronico: str
    Idioma: Optional[str] = "Español"
    ZonaHoraria: Optional[str] = "GMT+1"
    FechaCreacion: Optional[date]
    FechaActualizacion: Optional[date]
    Movil: Optional[str] = None
    PuntosLealtad: Optional[int] = 0
    user_roles: List[Dict]  # Esperamos una lista de diccionarios aquí
 

    class Config:
        orm_mode = True

#schemas para el correo
class ResetRequest(BaseModel):
    email: str

class PasswordReset(BaseModel):
    new_password: str

class UbicacionBase(BaseModel):
    NombreUbicacion: str
    DireccionUbicacion: str
    Ciudad: str
    Pais: str

class UbicacionCreate(UbicacionBase):
    pass

class Ubicacion(UbicacionBase):
    UbicacionID: int

    class Config:
        orm_mode = True

class EspacioCreate(BaseModel):
    NombreEspacio: str
    UbicacionID: int
    Capacidad: int
    TipoEspacio: str
    DescripcionEspacio: str
    PrecioPorHora: Optional[int] = None
    PrecioPorDia: Optional[int] = None
    PrecioPorMes: Optional[int] = None


class Espacio(EspacioCreate):
    EspacioID: int

    class Config:
        orm_mode = True


class ServicioAdicionalCreate(BaseModel):
    DescripcionServicio: str
    CostoServicio: int

class ServicioAdicional(ServicioAdicionalCreate):
    ServicioID: int

    class Config:
        orm_mode = True

class ReservaServicioCreate(BaseModel):
    ReservaID: int
    ServicioID: int

class ReservaServicio(BaseModel):
    ReservasServiciosID: int
    ReservaID: int
    ServicioID: int

    class Config:
        orm_mode = True

class ReservaBloqueadaCreate(BaseModel):
    UsuarioID: int
    EspacioID: int
    HoraInicioBloqueo: datetime
    HoraFinBloqueo: datetime

# Schema for response body
class ReservaBloqueada(ReservaBloqueadaCreate):
    ReservaBloqueadaID: int

    class Config:
        orm_mode = True

class MantenimientoCreate(BaseModel):
    EspacioID: int
    HoraInicio: datetime
    HoraFin: datetime

# Schema for response body
class Mantenimiento(MantenimientoCreate):
    MantenimientoID: int

    class Config:
        orm_mode = True

# New schema for individual reservation
class ReservaIndividualCreate(BaseModel):
    HoraInicio: time
    HoraFin: time
    FechaInicio: date
    FechaFin: date

class ReservaCreate(BaseModel):
    UsuarioID: int
    EspacioID: int
    Reservas: List[ReservaIndividualCreate]
    FrecuenciaReserva: Optional[str] = 'Una Vez'
    EstadoReserva: Optional[str] = 'Pendiente'

class Reserva(ReservaCreate):
    ReservaID: int


class Factura(BaseModel):
    FacturaID: int
    UsuarioID: int
    FechaFactura: date
    MontoFactura: int
    EstadoFactura: str

    class Config:
        orm_mode = True
