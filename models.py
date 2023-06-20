from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'usuarios'
    
    UsuarioID = Column(Integer, primary_key=True)
    NombreUsuario = Column(String(50), nullable=False)
    CorreoElectronico = Column(String(100), nullable=False)
    Contrasena = Column(String(60), nullable=False)
    FechaCreacion = Column(DateTime, default=func.now())
    FechaActualizacion = Column(DateTime)
    Idioma = Column(Enum('Español', 'English'), default='Español')
    ZonaHoraria = Column(String(8), default='GMT+1')
    Token = Column(String(50))
    PuntosLealtad = Column(Integer, default=0)
    RefreshToken = Column(String(255))
    RefreshTokenExpiry = Column(DateTime)

    user_roles = relationship("UserRoles", back_populates="user")
    user_roles_names = []  # Nuevo campo

    def to_dict(self):
        return {
            "UsuarioID": self.UsuarioID,
            "NombreUsuario": self.NombreUsuario,
            "CorreoElectronico": self.CorreoElectronico,
            "Contrasena": self.Contrasena,
            "FechaCreacion": self.FechaCreacion,
            "FechaActualizacion": self.FechaActualizacion,
            "Idioma": self.Idioma,
            "ZonaHoraria": self.ZonaHoraria,
            "Token": self.Token,
            "RefreshToken":self.RefreshToken,
            "RefreshTokenExpiry":self.RefreshTokenExpiry,
            "PuntosLealtad": self.PuntosLealtad,
            "user_roles": [role.to_dict() for role in self.user_roles],
            "user_roles_names": self.user_roles_names  # Incluimos el nuevo campo aquí
        }

class Role(Base):
    __tablename__ = 'rolesusuarios'
    
    RolID = Column(Integer, primary_key=True)
    NombreRol = Column(String(50), nullable=False)
    DescripcionRol = Column(String(200), nullable=False)

    role_users = relationship("UserRoles", back_populates="role")

class UserRoles(Base):
    __tablename__ = 'usuariosroles'
    
    UsuariosRolesID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    RolID = Column(Integer, ForeignKey('rolesusuarios.RolID'), nullable=False)

    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="role_users")

    def to_dict(self):
        return {
            "UsuariosRolesID": self.UsuariosRolesID,
            "UsuarioID": self.UsuarioID,
            "RolID": self.RolID,
            "NombreRol": self.role.NombreRol  # Agrega el nombre del rol aquí
        }
