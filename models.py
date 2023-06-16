# models.py
from sqlalchemy import Column, Integer, String, Enum, Date, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class UserRole(Base):
    __tablename__ = 'rolesusuarios'
    
    RolID = Column(Integer, primary_key=True)
    NombreRol = Column(String(50), nullable=False)
    DescripcionRol = Column(String(200), nullable=False)

    role_users = relationship("UserRoles", back_populates="role")

class UserRoles(Base):
    __tablename__ = 'usuariosroles'
    
    UsuariosRolesID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)  # ForeignKey añadida
    RolID = Column(Integer, ForeignKey('rolesusuarios.RolID'), nullable=False)  # ForeignKey añadida

    # Nueva relación
    user = relationship("User", back_populates="user_roles")
    role = relationship("UserRole", back_populates="role_users")

class User(Base):
    __tablename__ = 'usuarios'
    
    UsuarioID = Column(Integer, primary_key=True)
    NombreUsuario = Column(String(50), nullable=False)
    CorreoElectronico = Column(String(100), nullable=False)
    Contrasena = Column(String(25), nullable=False)
    FechaCreacion = Column(DateTime, default=func.now())  # Cambiado de Date a DateTime, y añadido valor por defecto
    FechaActualizacion = Column(DateTime)  # Cambiado de Date a DateTime
    Idioma = Column(Enum('Español', 'English'), default='Español')
    ZonaHoraria = Column(String(8), default='GMT+1')
    Token = Column(String(50))
    PuntosLealtad = Column(Integer, default=0)

    # Nueva relación
    user_roles = relationship("UserRoles", back_populates="user")
