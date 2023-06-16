from sqlalchemy import Column, Integer, String, Enum, Date
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'usuarios'
    
    UsuarioID = Column(Integer, primary_key=True)
    NombreUsuario = Column(String(50), nullable=False)
    CorreoElectronico = Column(String(100), nullable=False)
    Contrasena = Column(String(25), nullable=False)
    FechaCreacion = Column(Date, nullable=False)
    FechaActualizacion = Column(Date)
    Idioma = Column(Enum('Español', 'English'), default='Español')
    ZonaHoraria = Column(String(8), default='GMT+1')
    Token = Column(String(50))
    PuntosLealtad = Column(Integer, default=0)
    # other columns...

class UserRole(Base):
    __tablename__ = 'rolesusuarios'
    
    RolID = Column(Integer, primary_key=True)
    NombreRol = Column(String(50), nullable=False)
    DescripcionRol = Column(String(200), nullable=False)
    # other columns...

class UserRoles(Base):
    __tablename__ = 'usuariosroles'
    
    UsuariosRolesID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, nullable=False)
    RolID = Column(Integer, nullable=False)
    # other columns...
