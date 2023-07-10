from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey, Date, Time
from sqlalchemy.orm import relationship, class_mapper, ColumnProperty
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
    Movil = Column(String(50))
    PuntosLealtad = Column(Integer, default=0)
    RefreshToken = Column(String(255))
    RefreshTokenExpiry = Column(DateTime)
    ResetToken = Column(String(255))
    ResetTokenExpiry = Column(DateTime)
    DeviceToken = Column(String(255))
    user_roles_names = []  # Nuevo campo

    # Relationships
    descuentos = relationship("Descuentos", back_populates="usuario")
    facturas = relationship("Facturas", back_populates="usuario")
    notificaciones = relationship("Notificaciones", back_populates="usuario")
    opiniones = relationship("Opiniones", back_populates="usuario")
    reservas = relationship("Reservas", back_populates="usuario")
    reservas_bloqueadas = relationship("ReservasBloqueadas", back_populates="usuario")
    mantenimiento = relationship("Mantenimiento", back_populates="usuario")

    user_roles = relationship("UserRoles", back_populates="user")

    def to_dict(self, deep=True):
        data = {
            "UsuarioID": self.UsuarioID,
            "NombreUsuario": self.NombreUsuario,
            "CorreoElectronico": self.CorreoElectronico,
            "Contrasena": self.Contrasena,
            "FechaCreacion": self.FechaCreacion,
            "FechaActualizacion": self.FechaActualizacion,
            "Idioma": self.Idioma,
            "ZonaHoraria": self.ZonaHoraria,
            "Movil": self.Movil,
            "RefreshToken":self.RefreshToken,
            "RefreshTokenExpiry":self.RefreshTokenExpiry,
            "PuntosLealtad": self.PuntosLealtad,
            "user_roles": [role.to_dict() for role in self.user_roles],
            "user_roles_names": self.user_roles_names,
            "DeviceToken": self.DeviceToken  # Incluimos el nuevo campo aquí
        }
        if deep:
            data['reservas'] = [reserva.to_dict() for reserva in self.reservas]  # Changed this line
        return data
    
    def to_dict_deep(self):
        data = self.to_dict()
        data['reservas'] = [reserva.to_dict_deep() for reserva in self.reservas]
        return data


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

class ConfirmacionesReservas(Base):
    __tablename__ = 'confirmacionesreservas'
    
    ConfirmacionID = Column(Integer, primary_key=True)
    ReservaID = Column(Integer, ForeignKey('reservas.ReservaID'), nullable=False)
    FechaConfirmacion = Column(Date, nullable=False)
    DetallesConfirmacion = Column(String(50))

class Descuentos(Base):
    __tablename__ = 'descuentos'
    
    DescuentoID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    ValorDescuento = Column(Integer, nullable=False)
    FechaInicioDescuento = Column(Date, nullable=False)
    FechaFinDescuento = Column(Date)
    # Relaciones
    usuario = relationship("User", back_populates="descuentos")

class Ubicaciones(Base):
    __tablename__ = 'ubicaciones'
    
    UbicacionID = Column(Integer, primary_key=True)
    NombreUbicacion = Column(String(50), nullable=False)
    DireccionUbicacion = Column(String(50), nullable=False)
    Ciudad = Column(String(25), nullable=False)
    Pais = Column(String(25), nullable=False)
    espacios = relationship("Espacios", back_populates="ubicacion")  # new line

class Espacios(Base):
    __tablename__ = 'espacios'
    
    EspacioID = Column(Integer, primary_key=True)
    NombreEspacio = Column(String(50), nullable=False)
    UbicacionID = Column(Integer, ForeignKey('ubicaciones.UbicacionID'), nullable=False)
    Capacidad = Column(Integer, nullable=False)
    TipoEspacio = Column(String(50), nullable=False)
    DescripcionEspacio = Column(String(200), nullable=False)
    PrecioPorHora = Column(Integer)
    PrecioPorDia = Column(Integer)
    PrecioPorMes = Column(Integer)
    ubicacion = relationship("Ubicaciones", back_populates="espacios")  # new line
    reservas = relationship("Reservas", back_populates="espacio")  # new line
    opiniones = relationship("Opiniones", back_populates="espacio")  # new line


    def to_dict(self, deep=True):
        data = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        if deep:
            data['reservas'] = [reserva.to_dict() if hasattr(reserva, 'to_dict') else reserva for reserva in self.reservas]
        return data
    
    def to_dict_deep(self):
        data = self.to_dict()
        # Aquí puedes agregar cualquier relación adicional que necesites.
        return data


class Facturas(Base):
    __tablename__ = 'facturas'
    
    FacturaID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    FechaFactura = Column(Date, nullable=False)
    MontoFactura = Column(Integer, nullable=False)
    EstadoFactura = Column(String(50))
    PaymentIntentID = Column(String(255))

    # Relaciones
    usuario = relationship("User", back_populates="facturas")
    reservas = relationship("Reservas", back_populates="factura")

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        return result


    def to_dict_deep(self):
        data = self.to_dict()
        # Aquí puedes agregar cualquier relación adicional que necesites.
        # Por ejemplo:
        # data['reservas'] = [reserva.to_dict() for reserva in self.reservas]
        return data




class Mantenimiento(Base):
    __tablename__ = 'mantenimiento'
    
    MantenimientoID = Column(Integer, primary_key=True)
    EspacioID = Column(Integer, ForeignKey('espacios.EspacioID'), nullable=False)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    HoraInicio = Column(DateTime, nullable=False)
    HoraFin = Column(DateTime, nullable=False)
    espacio = relationship("Espacios")  # new line
    usuario = relationship("User", back_populates="mantenimiento")

class Notificaciones(Base):
    __tablename__ = 'notificaciones'
    
    NotificacionID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    TipoNotificacion = Column(String(50))
    ContenidoNotificacion = Column(String(50))
     # Relaciones
    usuario = relationship("User", back_populates="notificaciones")

class Opiniones(Base):
    __tablename__ = 'opiniones'
    
    OpinionesID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    EspacioID = Column(Integer, ForeignKey('espacios.EspacioID'), nullable=False)
    Puntuacion = Column(Enum('1','2','3','4','5'), nullable=False)
    Comentario = Column(String(200))
    # Relaciones
    usuario = relationship("User", back_populates="opiniones")
    espacio = relationship("Espacios", back_populates="opiniones")  # new line


class Reservas(Base):
    __tablename__ = 'reservas'
    
    ReservaID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    EspacioID = Column(Integer, ForeignKey('espacios.EspacioID'), nullable=False)
    HoraInicio = Column(Time, nullable=False)
    HoraFin = Column(Time, nullable=False)
    FechaInicio = Column(Date)
    FechaFin = Column(Date)
    FrecuenciaReserva = Column(Enum('Una Vez', 'Semanal', 'Mensual', 'Anual'))
    EstadoReserva = Column(Enum('Pendiente','Confirmada','Cancelada'), default='Pendiente')
    FacturaID = Column(Integer, ForeignKey('facturas.FacturaID'))
    
    # Relaciones
    usuario = relationship("User", back_populates="reservas")
    espacio = relationship("Espacios", back_populates="reservas")
    factura = relationship("Facturas", back_populates="reservas")  # Note the change here from 'factura' to 'reservas'

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        return result


    def to_dict_deep(self):
        data = self.to_dict()
        # Aquí puedes agregar cualquier relación adicional que necesites.
        # Por ejemplo:
        # data['facturas'] = [factura.to_dict() for factura in self.facturas]
        return data




class ReservasBloqueadas(Base):
    __tablename__ = 'reservasbloqueadas'
    
    ReservaBloqueadaID = Column(Integer, primary_key=True)
    UsuarioID = Column(Integer, ForeignKey('usuarios.UsuarioID'), nullable=False)
    EspacioID = Column(Integer, ForeignKey('espacios.EspacioID'), nullable=False)
    HoraInicioBloqueo = Column(DateTime, nullable=False)
    HoraFinBloqueo = Column(DateTime, nullable=False)

      # Relaciones
    usuario = relationship("User", back_populates="reservas_bloqueadas")

