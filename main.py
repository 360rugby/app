from datetime import datetime, timedelta, date, time
from fastapi import Body, FastAPI, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from schemas import Reserva, ReservaCreate,ReservaCualquiera
from schemas import ResetRequest,PasswordReset
from dependencies import get_current_user
from models import User
from schemas import RefreshToken
from security import ALGORITHM, SECRET_KEY
from database import get_db  
import schemas, crud , security
from typing import List
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from security import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, create_refresh_token, verify_refresh_token, generate_unique_token
from dependencies import get_current_role, admin_role_required, user_role_required, admin_or_user_role_required  # new import line
from schemas import Password, DeviceToken
from fastapi.middleware.cors import CORSMiddleware
import models
from sqlalchemy.exc import IntegrityError
from fastapi.responses import JSONResponse
from stripe.error import StripeError
import stripe
from dotenv import load_dotenv
import os
from crud import send_fcm_notification
from sqlalchemy import or_, and_
from dateutil import relativedelta
from dateutil.relativedelta import relativedelta




stripe_webhook_secret = stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

app = FastAPI()

# Replace 'your-app-domain.com' with the domain of your Flutter web application,
# or use '*' to allow all origins (not recommended in production)
origins = [
    'http://localhost:54165',  # This seems to be your Flutter web app's origin
    '*',  
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

#endpoint que muestra todos los usuarios de la tabla usuario y la relacion que hay con la tabla de rolesusuarios y usuariosroles
@app.get("/test_db", response_model=List[schemas.User])
def test_db(role: List[str] = Depends(admin_or_user_role_required), db: Session = Depends(get_db)):
    try:
        users = crud.get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/allusers", response_model=List[schemas.User])
def test_db(current_user: schemas.User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        users = crud.get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
 
#endponit que sirve para crear usuarios con el rol por defecto de User y devuelve datos de la tabla usuario y el token y el token de refresco
@app.post("/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if user.Contrasena != user.ConfirmarContrasena:
        raise HTTPException(
            status_code=400, detail="Passwords do not match"
        )

    db_user_by_name = crud.get_user_by_username(db, user.NombreUsuario)
    db_user_by_email = crud.get_user_by_email(db, user.CorreoElectronico)
    db_user_by_mobile = crud.get_user_by_mobile(db, "+34" + user.Movil) if user.Movil else None
    if db_user_by_name or db_user_by_email or db_user_by_mobile:
        raise HTTPException(
            status_code=400, detail="Username, email or mobile already registered"
        )

    db_user = crud.create_user(db=db, user=user)
    user_roles = [role.to_dict()["NombreRol"] for role in db_user.user_roles]
    data = {"sub": db_user.NombreUsuario, "user_id": db_user.UsuarioID}
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data=data, expires_delta=refresh_token_expires
    )

    db_user = db_user.to_dict()
    db_user["user_roles_names"] = user_roles
    db_user["access_token"] = access_token
    db_user["refresh_token"] = refresh_token
    return db_user


@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data=data, expires_delta=refresh_token_expires
    )

    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer", 
        "roles": user_roles
    }

@app.post("/refresh_token", response_model=schemas.Token)
def refresh_token(token: schemas.RefreshToken, db: Session = Depends(get_db)):
    refresh_token_str = token.refresh_token
    user_id = verify_refresh_token(refresh_token_str, db)
    
    user = crud.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)
    new_refresh_token = create_refresh_token(
        data=data, expires_delta=refresh_token_expires
    )

    return {
        "access_token": access_token, 
        "refresh_token": new_refresh_token, 
        "token_type": "bearer", 
        "roles": user_roles
    }

# Endpoint que devuelve los datos del usuario autenticado
@app.get("/me", response_model=schemas.UserResponse)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    try:
        user_roles_dict = [user_role.to_dict() for user_role in current_user.user_roles]  # Convertimos los roles a una lista de diccionarios
        user_response = schemas.UserResponse(
            UsuarioID = current_user.UsuarioID,
            NombreUsuario = current_user.NombreUsuario,
            CorreoElectronico = current_user.CorreoElectronico,
            Idioma = current_user.Idioma,
            ZonaHoraria = current_user.ZonaHoraria,
            FechaCreacion = current_user.FechaCreacion,
            FechaActualizacion = current_user.FechaActualizacion,
            Movil = current_user.Movil,
            PuntosLealtad = current_user.PuntosLealtad,
            user_roles = user_roles_dict,  # Usamos la lista de diccionarios de roles que acabamos de crear
            user_roles_names = current_user.user_roles_names
        )
        return user_response
    except Exception as e:
        print(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail=str(e))


#endpoint que sirve para cambiar la contrseña introduciendo la contraseña antigua
@app.post("/change_password")
def change_password(
    password: Password, 
    current_user: schemas.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not crud.verify_password(password.old_password, current_user.Contrasena):
        raise HTTPException(status_code=400, detail="Incorrect old password")

    try:
        crud.change_password(db=db, user=current_user, new_password=password.new_password)
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
#endpoint para cerrar sesion y desloguearse
@app.post("/logout")
def logout(current_user: schemas.User = Depends(get_current_user)):
    """
    This endpoint is used to logout user, even though it doesn't invalidate the token,
    it gives a chance to user interfaces to trigger this endpoint when user wants to logout,
    then UI can delete the token from the local storage.
    """
    return {"detail": "Successfully logged out"}

#endpoint para enviar la url de restablecimiento de contraseña por correo
@app.post("/password_reset_request")
def password_reset_request(request: ResetRequest, db: Session = Depends(get_db)):
    email = request.email
    user = crud.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = generate_unique_token() 
    user.ResetToken = reset_token
    user.ResetTokenExpiry = datetime.now() + timedelta(hours=24) 
    db.commit()

    crud.send_reset_email(email, reset_token)

    return {"detail": "Password reset email sent"}
#endpoint para cambiar la contraseña atraves de la url que se envio por correo
@app.post("/password_reset/{reset_token}")
def reset_password(reset_token: str, password_reset: PasswordReset, db: Session = Depends(get_db)):
    user = crud.get_user_by_reset_token(db, reset_token)
    if not user or user.ResetTokenExpiry < datetime.now():
        raise HTTPException(status_code=404, detail="Invalid or expired token")

    user.Contrasena = crud.get_password_hash(password_reset.new_password)
    user.ResetToken = None
    user.ResetTokenExpiry = None
    db.commit()

    return {"detail": "Password reset successful"}

#endpoint ubicaciones...
#crear una ubicacion
@app.post("/ubicaciones", response_model=schemas.Ubicacion)
def create_ubicacion(ubicacion: schemas.UbicacionCreate, db: Session = Depends(get_db)):
    db_ubicacion = models.Ubicaciones(**ubicacion.dict())
    db.add(db_ubicacion)
    db.commit()
    db.refresh(db_ubicacion)
    return db_ubicacion

#devolver una ubicacion atraves del id
@app.get("/ubicaciones/{ubicacion_id}", response_model=schemas.Ubicacion)
def read_ubicacion(ubicacion_id: int, db: Session = Depends(get_db)):
    db_ubicacion = db.query(models.Ubicaciones).filter(models.Ubicaciones.UbicacionID == ubicacion_id).first()
    if db_ubicacion is None:
        raise HTTPException(status_code=404, detail="Ubicación no encontrada")
    return db_ubicacion

#editar una ubicacion atraves del id
@app.put("/ubicaciones/{ubicacion_id}", response_model=schemas.Ubicacion)
def update_ubicacion(ubicacion_id: int, ubicacion: schemas.UbicacionCreate, db: Session = Depends(get_db)):
    db_ubicacion = db.query(models.Ubicaciones).filter(models.Ubicaciones.UbicacionID == ubicacion_id).first()
    if db_ubicacion is None:
        raise HTTPException(status_code=404, detail="Ubicación no encontrada")
    
    for key, value in ubicacion.dict().items():
        setattr(db_ubicacion, key, value)
    
    db.add(db_ubicacion)
    db.commit()
    db.refresh(db_ubicacion)
    return db_ubicacion

#eliminar una ubicacion atraves del id
@app.delete("/ubicaciones/{ubicacion_id}", response_model=str)
def delete_ubicacion(ubicacion_id: int, db: Session = Depends(get_db)):
    db_ubicacion = db.query(models.Ubicaciones).filter(models.Ubicaciones.UbicacionID == ubicacion_id).first()
    if db_ubicacion is None:
        raise HTTPException(status_code=404, detail="Ubicación no encontrada")
    
    db.delete(db_ubicacion)
    db.commit()
    return "Borrado correctamente"

#mostar todas las ubicaciones de la tabla ubicaciones
@app.get("/ubicaciones", response_model=List[schemas.Ubicacion])
def read_ubicaciones(role: List[str] = Depends(admin_or_user_role_required), skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    ubicaciones = db.query(models.Ubicaciones).offset(skip).limit(limit).all()
    return ubicaciones



@app.post("/espacios", response_model=schemas.Espacio)
def create_espacio(espacio: schemas.EspacioCreate, db: Session = Depends(get_db)):
    db_espacio = models.Espacios(**espacio.dict())
    db.add(db_espacio)
    db.commit()
    db.refresh(db_espacio)
    return db_espacio


@app.get("/espacios/{espacio_id}", response_model=schemas.Espacio)
def read_espacio(espacio_id: int, db: Session = Depends(get_db)):
    db_espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == espacio_id).first()
    if db_espacio is None:
        raise HTTPException(status_code=404, detail="Espacio no encontrado")
    return db_espacio


@app.put("/espacios/{espacio_id}", response_model=schemas.Espacio)
def update_espacio(espacio_id: int, espacio: schemas.EspacioCreate, db: Session = Depends(get_db)):
    db_espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == espacio_id).first()
    if db_espacio is None:
        raise HTTPException(status_code=404, detail="Espacio no encontrado")
    
    for key, value in espacio.dict().items():
        setattr(db_espacio, key, value)
    
    db.add(db_espacio)
    db.commit()
    db.refresh(db_espacio)
    return db_espacio


@app.delete("/espacios/{espacio_id}", response_model=str)
def delete_espacio(espacio_id: int, db: Session = Depends(get_db)):
    db_espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == espacio_id).first()
    if db_espacio is None:
        raise HTTPException(status_code=404, detail="Espacio no encontrado")
    
    db.delete(db_espacio)
    db.commit()
    return "Borrado correctamente"


@app.get("/espacios", response_model=List[schemas.Espacio])
def read_espacios(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    espacios = db.query(models.Espacios).offset(skip).limit(limit).all()
    return espacios




@app.post("/reservasbloqueadas", response_model=schemas.ReservaBloqueada)
def create_reserva_bloqueada(reserva: schemas.ReservaBloqueadaCreate, db: Session = Depends(get_db)):
    now = datetime.now()

    # Comprueba si HoraInicioBloqueo es posterior a la hora actual y anterior a HoraFinBloqueo
    if reserva.HoraInicioBloqueo <= now or reserva.HoraInicioBloqueo >= reserva.HoraFinBloqueo:
        raise HTTPException(status_code=400, detail="HoraInicioBloqueo debe ser posterior a la hora actual y anterior a HoraFinBloqueo")

    # Comprueba si HoraFinBloqueo es posterior a la hora actual y posterior a HoraInicioBloqueo
    if reserva.HoraFinBloqueo <= now or reserva.HoraFinBloqueo <= reserva.HoraInicioBloqueo:
        raise HTTPException(status_code=400, detail="HoraFinBloqueo debe ser posterior a la hora actual y posterior a HoraInicioBloqueo")

    # Comprueba si hay alguna reserva existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas = db.query(models.ReservasBloqueadas).filter(
        models.ReservasBloqueadas.EspacioID == reserva.EspacioID,
        models.ReservasBloqueadas.HoraInicioBloqueo < reserva.HoraFinBloqueo,
        models.ReservasBloqueadas.HoraFinBloqueo > reserva.HoraInicioBloqueo
    ).first()

    if overlapping_reservas is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva para este espacio durante el intervalo de tiempo solicitado")

    # Comprueba si hay algún mantenimiento programado para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
        models.Mantenimiento.EspacioID == reserva.EspacioID,
        models.Mantenimiento.HoraInicio < reserva.HoraFinBloqueo,
        models.Mantenimiento.HoraFin > reserva.HoraInicioBloqueo
    ).first()

    if overlapping_mantenimientos is not None:
        raise HTTPException(status_code=400, detail="Existe un mantenimiento programado para este espacio durante el intervalo de tiempo solicitado para la reserva")

    # Comprueba si hay alguna reserva regular que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas_regulares = db.query(models.Reservas).filter(
        models.Reservas.EspacioID == reserva.EspacioID,
        models.Reservas.HoraInicio < reserva.HoraFinBloqueo,
        models.Reservas.HoraFin > reserva.HoraInicioBloqueo
    ).first()

    if overlapping_reservas_regulares is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva regular para este espacio durante el intervalo de tiempo solicitado")

    db_reserva = models.ReservasBloqueadas(**reserva.dict())
    db.add(db_reserva)
    db.commit()
    db.refresh(db_reserva)
    return db_reserva




@app.get("/reservasbloqueadas/{reserva_id}", response_model=schemas.ReservaBloqueada)
def read_reserva_bloqueada(reserva_id: int, db: Session = Depends(get_db)):
    db_reserva = db.query(models.ReservasBloqueadas).get(reserva_id)
    if db_reserva is None:
        raise HTTPException(status_code=404, detail="Reserva bloqueada no encontrada")
    return db_reserva


@app.put("/reservasbloqueadas/{reserva_id}", response_model=schemas.ReservaBloqueada)
def update_reserva_bloqueada(reserva_id: int, reserva: schemas.ReservaBloqueadaCreate, db: Session = Depends(get_db)):
    db_reserva = db.query(models.ReservasBloqueadas).get(reserva_id)
    if db_reserva is None:
        raise HTTPException(status_code=404, detail="Reserva bloqueada no encontrada")

    now = datetime.now()

    # Comprueba si HoraInicioBloqueo es posterior a la hora actual y anterior a HoraFinBloqueo
    if reserva.HoraInicioBloqueo <= now or reserva.HoraInicioBloqueo >= reserva.HoraFinBloqueo:
        raise HTTPException(status_code=400, detail="HoraInicioBloqueo debe ser posterior a la hora actual y anterior a HoraFinBloqueo")

    # Comprueba si HoraFinBloqueo es posterior a la hora actual y posterior a HoraInicioBloqueo
    if reserva.HoraFinBloqueo <= now or reserva.HoraFinBloqueo <= reserva.HoraInicioBloqueo:
        raise HTTPException(status_code=400, detail="HoraFinBloqueo debe ser posterior a la hora actual y posterior a HoraInicioBloqueo")

    # Comprueba si hay alguna reserva existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas = db.query(models.Reservas).filter(
        models.Reservas.ReservaID != reserva_id,  # Note that it's ReservaID, not ReservaBloqueadaID
        models.Reservas.EspacioID == reserva.EspacioID,
        models.Reservas.HoraInicio < reserva.HoraFinBloqueo,  # Note that it's HoraInicio, not HoraInicioBloqueo
        models.Reservas.HoraFin > reserva.HoraInicioBloqueo,  # Note that it's HoraFin, not HoraFinBloqueo
    ).first()

    if overlapping_reservas is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva para este espacio durante el intervalo de tiempo solicitado")

    # Comprueba si hay alguna reserva bloqueada existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas_bloqueadas = db.query(models.ReservasBloqueadas).filter(
        models.ReservasBloqueadas.EspacioID == reserva.EspacioID,
        models.ReservasBloqueadas.HoraInicioBloqueo < reserva.HoraFinBloqueo,
        models.ReservasBloqueadas.HoraFinBloqueo > reserva.HoraInicioBloqueo,
        models.ReservasBloqueadas.ReservaBloqueadaID != reserva_id  # Exclude the current reservation being updated
    ).first()

    if overlapping_reservas_bloqueadas is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva bloqueada para este espacio durante el intervalo de tiempo solicitado")

    # Comprueba si hay algún mantenimiento programado para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
        models.Mantenimiento.EspacioID == reserva.EspacioID,
        models.Mantenimiento.HoraInicio < reserva.HoraFinBloqueo,
        models.Mantenimiento.HoraFin > reserva.HoraInicioBloqueo
    ).first()

    if overlapping_mantenimientos is not None:
        raise HTTPException(status_code=400, detail="Existe un mantenimiento programado para este espacio durante el intervalo de tiempo solicitado para la reserva")

    for key, value in reserva.dict().items():
        setattr(db_reserva, key, value)

    db.commit()
    return db_reserva




@app.delete("/reservasbloqueadas/{reserva_id}")
def delete_reserva_bloqueada(reserva_id: int, db: Session = Depends(get_db)):
    db_reserva = db.query(models.ReservasBloqueadas).get(reserva_id)
    if db_reserva is None:
        raise HTTPException(status_code=404, detail="Reserva bloqueada no encontrada")
    
    db.delete(db_reserva)
    db.commit()
    return JSONResponse(status_code=200, content={"message": "Reserva bloqueada borrada correctamente"})


@app.get("/reservasbloqueadas", response_model=List[schemas.ReservaBloqueada])
def read_reservas_bloqueadas(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    reservas = db.query(models.ReservasBloqueadas).offset(skip).limit(limit).all()
    return reservas


@app.post("/mantenimientos", response_model=schemas.Mantenimiento)
def create_mantenimiento(mantenimiento: schemas.MantenimientoCreate, db: Session = Depends(get_db)):
    now = datetime.now()

    # Comprueba si HoraInicio es posterior a la hora actual y anterior a HoraFin
    if mantenimiento.HoraInicio <= now or mantenimiento.HoraInicio >= mantenimiento.HoraFin:
        raise HTTPException(status_code=400, detail="HoraInicio debe ser posterior a la hora actual y anterior a HoraFin")

    # Comprueba si HoraFin es posterior a la hora actual y posterior a HoraInicio
    if mantenimiento.HoraFin <= now or mantenimiento.HoraFin <= mantenimiento.HoraInicio:
        raise HTTPException(status_code=400, detail="HoraFin debe ser posterior a la hora actual y posterior a HoraInicio")

    # Comprueba si hay alguna reserva existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas_bloqueadas = db.query(models.ReservasBloqueadas).filter(
        models.ReservasBloqueadas.EspacioID == mantenimiento.EspacioID,
        models.ReservasBloqueadas.HoraInicioBloqueo < mantenimiento.HoraFin,
        models.ReservasBloqueadas.HoraFinBloqueo > mantenimiento.HoraInicio
    ).first()

    overlapping_reservas = db.query(models.Reservas).filter(
        models.Reservas.EspacioID == mantenimiento.EspacioID,
        models.Reservas.HoraInicio < mantenimiento.HoraFin,
        models.Reservas.HoraFin > mantenimiento.HoraInicio
    ).first()

    if overlapping_reservas_bloqueadas is not None or overlapping_reservas is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva para este espacio durante el intervalo de tiempo solicitado para el mantenimiento")

    # Comprueba si hay algún mantenimiento existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
        models.Mantenimiento.EspacioID == mantenimiento.EspacioID,
        models.Mantenimiento.HoraInicio < mantenimiento.HoraFin,
        models.Mantenimiento.HoraFin > mantenimiento.HoraInicio
    ).first()

    if overlapping_mantenimientos is not None:
        raise HTTPException(status_code=400, detail="Ya existe un mantenimiento para este espacio durante el intervalo de tiempo solicitado")

    db_mantenimiento = models.Mantenimiento(**mantenimiento.dict())
    db.add(db_mantenimiento)
    db.commit()
    db.refresh(db_mantenimiento)

    # Aquí, busca el usuario y el espacio en la base de datos
    usuario = db.query(models.User).get(mantenimiento.UsuarioID)
    espacio = db.query(models.Espacios).get(mantenimiento.EspacioID)

    # Crea la notificación en la base de datos
    notificacion = models.Notificaciones(
        UsuarioID=mantenimiento.UsuarioID, 
        TipoNotificacion="Mantenimiento Creado", 
        ContenidoNotificacion=f"Acabas de crear un mantenimiento en la sala {espacio.NombreEspacio}"
    )
    db.add(notificacion)
    db.commit()

    if usuario and espacio:
        device_token = usuario.DeviceToken
        # Enviar la notificación a través de FCM
        try:
            response = send_fcm_notification(device_token, "Mantenimiento creado", f"Acabas de crear un mantenimiento en la sala {espacio.NombreEspacio}")
        except Exception as e:
            print(f"Error al enviar la notificación: {e}")

    return db_mantenimiento


@app.get("/mantenimientos/{mantenimiento_id}", response_model=schemas.Mantenimiento)
def get_mantenimiento(mantenimiento_id: int, db: Session = Depends(get_db)):
    db_mantenimiento = db.query(models.Mantenimiento).get(mantenimiento_id)
    if db_mantenimiento is None:
        raise HTTPException(status_code=404, detail="Mantenimiento no encontrado")
    return db_mantenimiento

@app.put("/mantenimientos/{mantenimiento_id}", response_model=schemas.Mantenimiento)
def update_mantenimiento(mantenimiento_id: int, mantenimiento: schemas.MantenimientoCreate, db: Session = Depends(get_db)):
    db_mantenimiento = db.query(models.Mantenimiento).get(mantenimiento_id)
    if db_mantenimiento is None:
        raise HTTPException(status_code=404, detail="Mantenimiento no encontrado")

    now = datetime.now()

    # Comprueba si HoraInicio es posterior a la hora actual y anterior a HoraFin
    if mantenimiento.HoraInicio <= now or mantenimiento.HoraInicio >= mantenimiento.HoraFin:
        raise HTTPException(status_code=400, detail="HoraInicio debe ser posterior a la hora actual y anterior a HoraFin")

    # Comprueba si HoraFin es posterior a la hora actual y posterior a HoraInicio
    if mantenimiento.HoraFin <= now or mantenimiento.HoraFin <= mantenimiento.HoraInicio:
        raise HTTPException(status_code=400, detail="HoraFin debe ser posterior a la hora actual y posterior a HoraInicio")

    # Comprueba si hay alguna reserva existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas = db.query(models.Reservas).filter(
        models.Reservas.EspacioID == mantenimiento.EspacioID,
        models.Reservas.HoraInicio < mantenimiento.HoraFin,
        models.Reservas.HoraFin > mantenimiento.HoraInicio,
    ).first()

    if overlapping_reservas is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva para este espacio durante el intervalo de tiempo solicitado para el mantenimiento")

    # Comprueba si hay alguna reserva bloqueada que se superponga con el nuevo intervalo de tiempo
    overlapping_reservas_bloqueadas = db.query(models.ReservasBloqueadas).filter(
        models.ReservasBloqueadas.EspacioID == mantenimiento.EspacioID,
        models.ReservasBloqueadas.HoraInicioBloqueo < mantenimiento.HoraFin,
        models.ReservasBloqueadas.HoraFinBloqueo > mantenimiento.HoraInicio,
    ).first()

    if overlapping_reservas_bloqueadas is not None:
        raise HTTPException(status_code=400, detail="Ya existe una reserva bloqueada para este espacio durante el intervalo de tiempo solicitado para el mantenimiento")

    # Comprueba si hay algún mantenimiento existente para el mismo espacio que se superponga con el nuevo intervalo de tiempo
    overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
        models.Mantenimiento.MantenimientoID != mantenimiento_id,  # Exclude the current maintenance being updated
        models.Mantenimiento.EspacioID == mantenimiento.EspacioID,
        models.Mantenimiento.HoraInicio < mantenimiento.HoraFin,
        models.Mantenimiento.HoraFin > mantenimiento.HoraInicio
    ).first()

    if overlapping_mantenimientos is not None:
        raise HTTPException(status_code=400, detail="Ya existe un mantenimiento para este espacio durante el intervalo de tiempo solicitado")

    for key, value in mantenimiento.dict().items():
        setattr(db_mantenimiento, key, value)

    db.commit()

    # Aquí, busca el usuario y el espacio en la base de datos
    usuario = db.query(models.User).get(mantenimiento.UsuarioID)
    espacio = db.query(models.Espacios).get(mantenimiento.EspacioID)

    # Crea la notificación en la base de datos
    notificacion = models.Notificaciones(
        UsuarioID=mantenimiento.UsuarioID, 
        TipoNotificacion="Mantenimiento Actualizado", 
        ContenidoNotificacion=f"Has actualizado un mantenimiento en la sala {espacio.NombreEspacio}"
    )
    db.add(notificacion)
    db.commit()

    if usuario and espacio:
        device_token = usuario.DeviceToken
        # Enviar la notificación a través de FCM
        try:
            response = send_fcm_notification(device_token, "Mantenimiento actualizado", f"Has actualizado un mantenimiento en la sala {espacio.NombreEspacio}")
        except Exception as e:
            print(f"Error al enviar la notificación: {e}")

    return db_mantenimiento


@app.delete("/mantenimientos/{mantenimiento_id}", response_model=dict)
def delete_mantenimiento(mantenimiento_id: int, db: Session = Depends(get_db)):
    db_mantenimiento = db.query(models.Mantenimiento).get(mantenimiento_id)
    if db_mantenimiento is None:
        raise HTTPException(status_code=404, detail="Mantenimiento no encontrado")
    
    db.delete(db_mantenimiento)
    db.commit()
    return {"message": "Mantenimiento borrado correctamente"}

#reserva si o si, es decir ai ya hay una reserva en una sala de las que el usuario quiere reservar , busca un espacio que sea igiual par reservar en sistitucion de ese espacio
@app.post("/reservaCualquiera", response_model=List[ReservaCualquiera])
async def create_reserva(reserva: ReservaCreate, db: Session = Depends(get_db)):
    now = datetime.utcnow()  # DateTime object for current time
    db_reservas = []
    db_reservas_to_add = []  # Use this list to store reservations before adding to database
    bloqueadas_to_add = []  # List to store instances of ReservasBloqueadas
    overlapping_reservas_list = []  # Use this list to store overlapping reservation dates
    overlapping_mantenimientos_list = []  # Use this list to store overlapping maintenance dates
    overlapping_customer_reservas_list = []  # Use this list to store overlapping reservation dates among the customer's reservations
    customer_reservas_times = []  # Use this list to store all reservation intervals
    espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == reserva.EspacioID).first()
    error_messages = {}
    total_cost = 0

    for reserva_individual in reserva.Reservas:
        # Create DateTime objects for reservation's start and end time
        HoraInicioBloqueo = datetime.combine(reserva_individual.FechaInicio, reserva_individual.HoraInicio)
        HoraFinBloqueo = datetime.combine(reserva_individual.FechaFin, reserva_individual.HoraFin)

        # Check if reservation start time is after current time
        if HoraInicioBloqueo <= now:
            raise HTTPException(status_code=400, detail="HoraInicioBloqueo debe ser posterior a la hora actual")

        # Check if reservation end time is after current time
        if HoraFinBloqueo <= now:
            raise HTTPException(status_code=400, detail="HoraFinBloqueo debe ser posterior a la hora actual")

        # Check if reservation end time is after start time (considering the case of crossing midnight)
        if HoraFinBloqueo < HoraInicioBloqueo:
            raise HTTPException(status_code=400, detail="HoraFinBloqueo debe ser posterior a HoraInicioBloqueo")

        # Check if reservation times overlap with other reservations in the same request
        for other_HoraInicio, other_HoraFin in customer_reservas_times:
            if max(HoraInicioBloqueo, other_HoraInicio) < min(HoraFinBloqueo, other_HoraFin):  # This condition checks for overlap
                overlapping_customer_reservas_list.append({"FechaInicio": str(reserva_individual.FechaInicio), "HoraInicio": str(reserva_individual.HoraInicio), "FechaFin": str(reserva_individual.FechaFin), "HoraFin": str(reserva_individual.HoraFin)})

        customer_reservas_times.append((HoraInicioBloqueo, HoraFinBloqueo))

        # Calculate total duration in years, months, days and hours
        diff = relativedelta(HoraFinBloqueo, HoraInicioBloqueo)

        total_years = diff.years
        total_months = diff.months
        total_days = diff.days
        total_hours = (HoraFinBloqueo - HoraInicioBloqueo).seconds // 3600

        # Determine frequency of reservation
        FrecuenciaReserva = 'Una Vez'
        if total_days < 7 and total_months == 0 and total_years == 0:
            FrecuenciaReserva = 'Una Vez'
        elif total_days >= 7 and total_days < 28 and total_months == 0 and total_years == 0:
            FrecuenciaReserva = 'Semanal'
        elif total_days >= 28 and total_days < 365 and total_years == 0:
            FrecuenciaReserva = 'Mensual'
        elif total_years >= 1:
            FrecuenciaReserva = 'Anual'

        # Calculate cost
        cost = 0
        if total_years > 0 and espacio.PrecioPorMes is not None:
            cost += total_years * 12 * espacio.PrecioPorMes
        if total_months > 0 and espacio.PrecioPorMes is not None:
            cost += total_months * espacio.PrecioPorMes
        # For 28 days or more but less than a month, consider it as a month
        if total_days >= 28 and espacio.PrecioPorMes is not None:
            cost += espacio.PrecioPorMes
        # For less than 28 days, calculate cost per day
        elif total_days < 28 and espacio.PrecioPorDia is not None:
            cost += total_days * espacio.PrecioPorDia
        if total_hours > 0 and espacio.PrecioPorHora is not None:
            cost += total_hours * espacio.PrecioPorHora
        total_cost += cost

        # Check if there is any existing reservation for the same space that overlaps with the new time slot
        overlapping_reservas = db.query(models.ReservasBloqueadas).filter(
            models.ReservasBloqueadas.EspacioID == reserva.EspacioID,
            models.ReservasBloqueadas.HoraInicioBloqueo < HoraFinBloqueo,
            models.ReservasBloqueadas.HoraFinBloqueo > HoraInicioBloqueo
        ).first()

        if overlapping_reservas is not None:
            overlapping_reservas_list.append({"FechaInicio": str(reserva_individual.FechaInicio), "HoraInicio": str(reserva_individual.HoraInicio), "FechaFin": str(reserva_individual.FechaFin), "HoraFin": str(reserva_individual.HoraFin)})

        overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
            models.Mantenimiento.EspacioID == reserva.EspacioID,
            models.Mantenimiento.HoraInicio < HoraFinBloqueo,
            models.Mantenimiento.HoraFin > HoraInicioBloqueo
        ).first()

        if overlapping_mantenimientos is not None:
            overlapping_mantenimientos_list.append({"FechaInicio": str(reserva_individual.FechaInicio), "HoraInicio": str(reserva_individual.HoraInicio), "FechaFin": str(reserva_individual.FechaFin), "HoraFin": str(reserva_individual.HoraFin)})

        if not overlapping_reservas and not overlapping_mantenimientos:
            reserva_individual_dict = reserva_individual.dict()
            reserva_individual_dict.update({
                'UsuarioID': reserva.UsuarioID,
                'EspacioID': reserva.EspacioID,
                'FrecuenciaReserva': FrecuenciaReserva,
                'EstadoReserva': reserva.EstadoReserva
            })

            db_reserva_individual = models.Reservas(**reserva_individual_dict)
            db_reservas_to_add.append(db_reserva_individual)

            # Create instance in ReservasBloqueadas table
            reserva_bloqueada = models.ReservasBloqueadas(
                UsuarioID=reserva.UsuarioID,
                EspacioID=reserva.EspacioID,
                HoraInicioBloqueo=HoraInicioBloqueo,
                HoraFinBloqueo=HoraFinBloqueo
            )
            bloqueadas_to_add.append(reserva_bloqueada)

    # Check if there is any discount for the reservation period
    descuento = db.query(models.Descuentos).filter(
        models.Descuentos.EspacioID == reserva.EspacioID,
        models.Descuentos.FechaInicioDescuento <= now,
        models.Descuentos.FechaFinDescuento >= now
    ).first()

    if descuento is not None:
        total_cost = total_cost - (total_cost * descuento.ValorDescuento / 100)

    # Add error messages for overlapping reservations and maintenances
    if overlapping_reservas_list:
        error_messages[f"Ya existe una reserva para el espacio {espacio.NombreEspacio} en las fechas y horas seleccionadas"] = overlapping_reservas_list

    if overlapping_mantenimientos_list:
        error_messages[f"Existe un mantenimiento para el espacio {espacio.NombreEspacio} en las fechas y horas seleccionadas"] = overlapping_mantenimientos_list

    if overlapping_customer_reservas_list:
        error_messages[f"Las fechas que estás introduciendo se superponen entre sí"] = overlapping_customer_reservas_list

    # If there were any error messages, find alternative spaces
    if error_messages:
        # Get the conflicting dates
        conflicting_dates = []
        for message, details in error_messages.items():
            for detail in details:
                conflicting_dates.append((detail["FechaInicio"], detail["HoraInicio"], detail["FechaFin"], detail["HoraFin"]))

        # Find alternative spaces
        for FechaInicio, HoraInicio, FechaFin, HoraFin in conflicting_dates:
            # Convert strings to datetime objects
            HoraInicioBloqueo = datetime.combine(datetime.strptime(FechaInicio, "%Y-%m-%d"), datetime.strptime(HoraInicio, "%H:%M:%S").time())
            HoraFinBloqueo = datetime.combine(datetime.strptime(FechaFin, "%Y-%m-%d"), datetime.strptime(HoraFin, "%H:%M:%S").time())

            # Find alternative spaces that are available at the same time, match the type of space and have a similar price
            alternative_space = db.query(models.Espacios).filter(
                models.Espacios.TipoEspacio == espacio.TipoEspacio,
                models.Espacios.PrecioPorHora.between(espacio.PrecioPorHora * 0.9, espacio.PrecioPorHora * 1.1),
                models.Espacios.PrecioPorDia.between(espacio.PrecioPorDia * 0.9, espacio.PrecioPorDia * 1.1),
                models.Espacios.PrecioPorMes.between(espacio.PrecioPorMes * 0.9, espacio.PrecioPorMes * 1.1),
                ~models.Espacios.EspacioID.in_(
                    db.query(models.ReservasBloqueadas.EspacioID).filter(
                        or_(
                            and_(models.ReservasBloqueadas.HoraInicioBloqueo <= HoraInicioBloqueo, models.ReservasBloqueadas.HoraFinBloqueo > HoraInicioBloqueo),
                            and_(models.ReservasBloqueadas.HoraInicioBloqueo < HoraFinBloqueo, models.ReservasBloqueadas.HoraFinBloqueo >= HoraFinBloqueo)
                        )
                    )
                ),
                ~models.Espacios.EspacioID.in_(
                    db.query(models.Mantenimiento.EspacioID).filter(
                        or_(
                            and_(models.Mantenimiento.HoraInicio <= HoraInicioBloqueo, models.Mantenimiento.HoraFin > HoraInicioBloqueo),
                            and_(models.Mantenimiento.HoraInicio < HoraFinBloqueo, models.Mantenimiento.HoraFin >= HoraFinBloqueo)
                        )
                    )
                )
            ).first()

            # Loop until we find an alternative space that is not booked
            while alternative_space is not None:
                # Replace the original space with the alternative space
                espacio = alternative_space

                # Check if the alternative space is booked
                overlapping_reservas = db.query(models.ReservasBloqueadas).filter(
                    models.ReservasBloqueadas.EspacioID == espacio.EspacioID,
                    models.ReservasBloqueadas.HoraInicioBloqueo < HoraFinBloqueo,
                    models.ReservasBloqueadas.HoraFinBloqueo > HoraInicioBloqueo
                ).first()

                overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
                    models.Mantenimiento.EspacioID == espacio.EspacioID,
                    models.Mantenimiento.HoraInicio < HoraFinBloqueo,
                    models.Mantenimiento.HoraFin > HoraInicioBloqueo
                ).first()

                if overlapping_reservas is None and overlapping_mantenimientos is None:
                    # The alternative space is not booked, so break the loop
                    break

                # The alternative space is booked, so get the next one
                alternative_space = db.query(models.Espacios).filter(
                    models.Espacios.TipoEspacio == espacio.TipoEspacio,
                    models.Espacios.PrecioPorHora.between(espacio.PrecioPorHora * 0.9, espacio.PrecioPorHora * 1.1),
                    models.Espacios.PrecioPorDia.between(espacio.PrecioPorDia * 0.9, espacio.PrecioPorDia * 1.1),
                    models.Espacios.PrecioPorMes.between(espacio.PrecioPorMes * 0.9, espacio.PrecioPorMes * 1.1),
                    models.Espacios.EspacioID > espacio.EspacioID,  # Add this condition to get the next space
                    ~models.Espacios.EspacioID.in_(
                        db.query(models.ReservasBloqueadas.EspacioID).filter(
                            or_(
                                and_(models.ReservasBloqueadas.HoraInicioBloqueo <= HoraInicioBloqueo, models.ReservasBloqueadas.HoraFinBloqueo > HoraInicioBloqueo),
                                and_(models.ReservasBloqueadas.HoraInicioBloqueo < HoraFinBloqueo, models.ReservasBloqueadas.HoraFinBloqueo >= HoraFinBloqueo)
                            )
                        )
                    ),
                    ~models.Espacios.EspacioID.in_(
                        db.query(models.Mantenimiento.EspacioID).filter(
                            or_(
                                and_(models.Mantenimiento.HoraInicio <= HoraInicioBloqueo, models.Mantenimiento.HoraFin > HoraInicioBloqueo),
                                and_(models.Mantenimiento.HoraInicio < HoraFinBloqueo, models.Mantenimiento.HoraFin >= HoraFinBloqueo)
                            )
                        )
                    )
                ).first()

            # If we didn't find any available alternative space, raise an error
            if alternative_space is None:
                raise HTTPException(status_code=400, detail="No se pudo encontrar un espacio alternativo disponible")

            # Now proceed with the reservation as usual
            reserva_individual_dict = reserva_individual.dict()
            reserva_individual_dict.update({
                'UsuarioID': reserva.UsuarioID,
                'EspacioID': alternative_space.EspacioID,
                'FrecuenciaReserva': FrecuenciaReserva,
                'EstadoReserva': reserva.EstadoReserva
            })

            db_reserva_individual = models.Reservas(**reserva_individual_dict)
            db_reservas_to_add.append(db_reserva_individual)

            # Create instance in ReservasBloqueadas table
            reserva_bloqueada = models.ReservasBloqueadas(
                UsuarioID=reserva.UsuarioID,
                EspacioID=alternative_space.EspacioID,
                HoraInicioBloqueo=HoraInicioBloqueo,
                HoraFinBloqueo=HoraFinBloqueo
            )
            bloqueadas_to_add.append(reserva_bloqueada)
    # Now that all dates have been verified, create the factura
    factura = models.Facturas(UsuarioID=reserva.UsuarioID, FechaFactura=now.date(), MontoFactura=total_cost, EstadoFactura="Pendiente")
    db.add(factura)
    db.commit()
    db.refresh(factura)

    # Add reservations to the database
    for reserva_to_add, bloqueada_to_add in zip(db_reservas_to_add, bloqueadas_to_add):
        # Update reserva_to_add with the invoice ID
        reserva_to_add.FacturaID = factura.FacturaID
        db.add(reserva_to_add)
        db.commit()
        db.refresh(reserva_to_add)

        # Include additional details in the response
        espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == reserva_to_add.EspacioID).first()
        reserva_dict = reserva_to_add.to_dict_deep()
        reserva_dict.update({
            'NombreEspacio': espacio.NombreEspacio,
            'EspacioID': espacio.EspacioID,
            'ReservaID': reserva_to_add.ReservaID,
            'Reservas': reserva.Reservas
        })

        db_reservas.append(Reserva(**reserva_dict))
        db.add(bloqueada_to_add)
        db.commit()

    # Create the notification in the database
    notificacion = models.Notificaciones(
        UsuarioID=reserva.UsuarioID, 
        TipoNotificacion="Reserva Creada", 
        ContenidoNotificacion="Tienes una reserva pendiente de pago"
    )
    db.add(notificacion)
    db.commit()

    # Get the user's device token
    usuario = db.query(models.User).get(reserva.UsuarioID)
    device_token = usuario.DeviceToken

    # Send the notification through FCM
    response = send_fcm_notification(device_token, "Reserva Creada", "Tienes una reserva pendiente de pago")

    # Return the list of reservations
    return db_reservas




#para hacer reservas para horas dias y semanas


@app.post("/reservas", response_model=List[Reserva])
async def create_reserva(reserva: ReservaCreate, db: Session = Depends(get_db)):
    now = datetime.utcnow()  # DateTime object for current time
    db_reservas = []
    db_reservas_to_add = []  # Use this list to store reservations before adding to database
    bloqueadas_to_add = []  # List to store instances of ReservasBloqueadas
    overlapping_reservas_list = []  # Use this list to store overlapping reservation dates
    overlapping_mantenimientos_list = []  # Use this list to store overlapping maintenance dates
    overlapping_customer_reservas_list = []  # Use this list to store overlapping reservation dates among the customer's reservations
    customer_reservas_times = []  # Use this list to store all reservation intervals
    espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == reserva.EspacioID).first()
    error_messages = {}
    total_cost = 0

    for reserva_individual in reserva.Reservas:
        # Create DateTime objects for reservation's start and end time
        HoraInicioBloqueo = datetime.combine(reserva_individual.FechaInicio, reserva_individual.HoraInicio)
        HoraFinBloqueo = datetime.combine(reserva_individual.FechaFin, reserva_individual.HoraFin)

        # Check if reservation start time is after current time
        if HoraInicioBloqueo <= now:
            raise HTTPException(status_code=400, detail="HoraInicioBloqueo debe ser posterior a la hora actual")

        # Check if reservation end time is after current time
        if HoraFinBloqueo <= now:
            raise HTTPException(status_code=400, detail="HoraFinBloqueo debe ser posterior a la hora actual")

        # Check if reservation end time is after start time (considering the case of crossing midnight)
        if HoraFinBloqueo < HoraInicioBloqueo:
            raise HTTPException(status_code=400, detail="HoraFinBloqueo debe ser posterior a HoraInicioBloqueo")

        # Check if reservation times overlap with other reservations in the same request
        for other_HoraInicio, other_HoraFin in customer_reservas_times:
            if max(HoraInicioBloqueo, other_HoraInicio) < min(HoraFinBloqueo, other_HoraFin):  # This condition checks for overlap
                overlapping_customer_reservas_list.append({"FechaInicio": str(reserva_individual.FechaInicio), "HoraInicio": str(reserva_individual.HoraInicio), "FechaFin": str(reserva_individual.FechaFin), "HoraFin": str(reserva_individual.HoraFin)})

        customer_reservas_times.append((HoraInicioBloqueo, HoraFinBloqueo))

        # Calculate total duration in years, months, days and hours
        diff = relativedelta(HoraFinBloqueo, HoraInicioBloqueo)

        total_years = diff.years
        total_months = diff.months
        total_days = diff.days
        total_hours = (HoraFinBloqueo - HoraInicioBloqueo).seconds // 3600

        # Determine frequency of reservation
        FrecuenciaReserva = 'Una Vez'
        if total_days < 7 and total_months == 0 and total_years == 0:
            FrecuenciaReserva = 'Una Vez'
        elif total_days >= 7 and total_days < 28 and total_months == 0 and total_years == 0:
            FrecuenciaReserva = 'Semanal'
        elif total_days >= 28 and total_days < 365 and total_years == 0:
            FrecuenciaReserva = 'Mensual'
        elif total_years >= 1:
            FrecuenciaReserva = 'Anual'

        # Calculate cost
        cost = 0
        if total_years > 0 and espacio.PrecioPorMes is not None:
            cost += total_years * 12 * espacio.PrecioPorMes
        if total_months > 0 and espacio.PrecioPorMes is not None:
            cost += total_months * espacio.PrecioPorMes
        # For 28 days or more but less than a month, consider it as a month
        if total_days >= 28 and espacio.PrecioPorMes is not None:
            cost += espacio.PrecioPorMes
        # For less than 28 days, calculate cost per day
        elif total_days < 28 and espacio.PrecioPorDia is not None:
            cost += total_days * espacio.PrecioPorDia
        if total_hours > 0 and espacio.PrecioPorHora is not None:
            cost += total_hours * espacio.PrecioPorHora
        total_cost += cost

        # Check if there is any existing reservation for the same space that overlaps with the new time slot
        overlapping_reservas = db.query(models.ReservasBloqueadas).filter(
            models.ReservasBloqueadas.EspacioID == reserva.EspacioID,
            models.ReservasBloqueadas.HoraInicioBloqueo < HoraFinBloqueo,
            models.ReservasBloqueadas.HoraFinBloqueo > HoraInicioBloqueo
        ).first()

        if overlapping_reservas is not None:
            overlapping_reservas_list.append({"FechaInicio": str(reserva_individual.FechaInicio), "HoraInicio": str(reserva_individual.HoraInicio), "FechaFin": str(reserva_individual.FechaFin), "HoraFin": str(reserva_individual.HoraFin)})

        overlapping_mantenimientos = db.query(models.Mantenimiento).filter(
            models.Mantenimiento.EspacioID == reserva.EspacioID,
            models.Mantenimiento.HoraInicio < HoraFinBloqueo,
            models.Mantenimiento.HoraFin > HoraInicioBloqueo
        ).first()

        if overlapping_mantenimientos is not None:
            overlapping_mantenimientos_list.append({"FechaInicio": str(reserva_individual.FechaInicio), "HoraInicio": str(reserva_individual.HoraInicio), "FechaFin": str(reserva_individual.FechaFin), "HoraFin": str(reserva_individual.HoraFin)})

        if not overlapping_reservas and not overlapping_mantenimientos:
            reserva_individual_dict = reserva_individual.dict()
            reserva_individual_dict.update({
                'UsuarioID': reserva.UsuarioID,
                'EspacioID': reserva.EspacioID,
                'FrecuenciaReserva': FrecuenciaReserva,
                'EstadoReserva': reserva.EstadoReserva
            })

            db_reserva_individual = models.Reservas(**reserva_individual_dict)
            db_reservas_to_add.append(db_reserva_individual)

            # Create instance in ReservasBloqueadas table
            reserva_bloqueada = models.ReservasBloqueadas(
                UsuarioID=reserva.UsuarioID,
                EspacioID=reserva.EspacioID,
                HoraInicioBloqueo=HoraInicioBloqueo,
                HoraFinBloqueo=HoraFinBloqueo
            )
            bloqueadas_to_add.append(reserva_bloqueada)

    # Check if there is any discount for the reservation period
    descuento = db.query(models.Descuentos).filter(
        models.Descuentos.EspacioID == reserva.EspacioID,
        models.Descuentos.FechaInicioDescuento <= now,
        models.Descuentos.FechaFinDescuento >= now
    ).first()

    if descuento is not None:
        total_cost = total_cost - (total_cost * descuento.ValorDescuento / 100)

    # Add error messages for overlapping reservations and maintenances
    if overlapping_reservas_list:
        error_messages[f"Ya existe una reserva para el espacio {espacio.NombreEspacio} en las fechas y horas seleccionadas"] = overlapping_reservas_list

    if overlapping_mantenimientos_list:
        error_messages[f"Existe un mantenimiento para el espacio {espacio.NombreEspacio} en las fechas y horas seleccionadas"] = overlapping_mantenimientos_list

    if overlapping_customer_reservas_list:
        error_messages[f"Las fechas que estás introduciendo se superponen entre sí"] = overlapping_customer_reservas_list

    # If there were any error messages, raise an exception with all the details
    if error_messages:
        raise HTTPException(status_code=400, detail=error_messages)

    # Now that all dates have been verified, create the factura
    factura = models.Facturas(UsuarioID=reserva.UsuarioID, FechaFactura=now.date(), MontoFactura=total_cost, EstadoFactura="Pendiente")
    db.add(factura)
    db.commit()
    db.refresh(factura)

    # Add reservations to the database
    for reserva_to_add, bloqueada_to_add in zip(db_reservas_to_add, bloqueadas_to_add):
        # Update reserva_to_add with the invoice ID
        reserva_to_add.FacturaID = factura.FacturaID
        db.add(reserva_to_add)
        db.commit()
        db.refresh(reserva_to_add)

        # Include additional details in the response
        espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == reserva_to_add.EspacioID).first()
        reserva_dict = reserva_to_add.to_dict_deep()
        reserva_dict.update({
            'NombreEspacio': espacio.NombreEspacio,
            'EspacioID': espacio.EspacioID,
            'ReservaID': reserva_to_add.ReservaID,
            'Reservas': reserva.Reservas
        })

        db_reservas.append(Reserva(**reserva_dict))
        db.add(bloqueada_to_add)
        db.commit()

    # Create the notification in the database
    notificacion = models.Notificaciones(
        UsuarioID=reserva.UsuarioID, 
        TipoNotificacion="Reserva Creada", 
        ContenidoNotificacion="Tienes una reserva pendiente de pago"
    )
    db.add(notificacion)
    db.commit()

    # Get the user's device token
    usuario = db.query(models.User).get(reserva.UsuarioID)
    device_token = usuario.DeviceToken

    # Send the notification through FCM
    response = send_fcm_notification(device_token, "Reserva Creada", "Tienes una reserva pendiente de pago")

    # Return the list of reservations
    return db_reservas




@app.get("/reservas", response_model=List[schemas.Reserva])
def read_reservas(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    reservas = db.query(models.Reservas).offset(skip).limit(limit).all()
    return reservas


@app.get("/reservas/{reserva_id}", response_model=schemas.Reserva)
def read_reserva(reserva_id: int, db: Session = Depends(get_db)):
    db_reserva = db.query(models.Reservas).get(reserva_id)
    if db_reserva is None:
        raise HTTPException(status_code=404, detail="Reserva no encontrada")
    return db_reserva

@app.delete("/reservas/{reserva_id}", response_model=schemas.Reserva)
def delete_reserva(reserva_id: int, db: Session = Depends(get_db)):
    db_reserva = db.query(models.Reservas).get(reserva_id)
    if db_reserva is None:
        raise HTTPException(status_code=404, detail="Reserva no encontrada")
    
    db.delete(db_reserva)
    db.commit()
    return {"message": f"Reserva con ID {reserva_id} eliminada correctamente"}



@app.get("/facturas/{factura_id}", response_model=schemas.Factura)
def read_factura(factura_id: int, db: Session = Depends(get_db)):
    db_factura = db.query(models.Facturas).filter(models.Facturas.FacturaID == factura_id).first()
    if db_factura is None:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    return db_factura


@app.post("/crear_pago/{factura_id}")
async def create_payment(factura_id: int, db: Session = Depends(get_db)):
    stripe.api_key = os.getenv('STRIPE_API_KEY')  # Usa tu propia clave secreta de Stripe

    # Busca la factura en la base de datos
    factura = db.query(models.Facturas).get(factura_id)
    if not factura:
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    # Convierte el monto de la factura a la menor unidad de moneda (centavos, en el caso de USD)
    amount = int(factura.MontoFactura * 100)

    try:
        # Crea un PaymentIntent en Stripe
        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency="usd",  # Asume que todas las facturas están en USD
        )
    except stripe.error.StripeError as e:
        # Maneja los errores de la API de Stripe
        return {"error": str(e)}

    # Almacena el PaymentIntentID en la factura
    factura.PaymentIntentID = payment_intent.id

    # Actualiza el estado de la factura a "En proceso"
    factura.EstadoFactura = "En proceso"

    # Actualiza el estado de las reservas asociadas a "Confirmada"
    for reserva in factura.reservas:
        reserva.EstadoReserva = "Confirmada"

    db.commit()

    # Devuelve el client_secret al cliente
    # Devuelve el client_secret y el PaymentIntentID al cliente
    return {"client_secret": payment_intent.client_secret, "payment_intent_id": payment_intent.id}



@app.post("/stripe_webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the payment_intent.succeeded event
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        factura_id = payment_intent['metadata']['factura_id']

        # Aquí, busca la factura en tu base de datos y actualízala a "Pagada"
        factura = db.query(models.Facturas).get(factura_id)
        if not factura:
            raise HTTPException(status_code=404, detail="Factura no encontrada")

        if factura.EstadoFactura == "Pagada":
            raise HTTPException(status_code=400, detail="La factura ya ha sido pagada")

        factura.EstadoFactura = "Pagada"
        db.commit()

        # Obtén la reserva asociada a esta factura
        reserva = db.query(models.Reservas).filter(models.Reservas.FacturaID == factura_id).first()
        if not reserva:
            raise HTTPException(status_code=404, detail="Reserva no encontrada")

        # Obtén el espacio asociado a esta reserva
        espacio = db.query(models.Espacios).filter(models.Espacios.EspacioID == reserva.EspacioID).first()
        if not espacio:
            raise HTTPException(status_code=404, detail="Espacio no encontrado")

        # Envía la notificación de que la factura ha sido pagada
        usuario = db.query(User).get(factura.UsuarioID)
        device_token = usuario.DeviceToken
        response = send_fcm_notification(device_token, "Reserva Pagada", f"Acabas de pagar por una reserva en la sala {espacio.NombreEspacio}")

    return {"status": "success"}


@app.post("/devoluciones/{factura_id}")
async def create_refund(factura_id: int, db: Session = Depends(get_db)):
    stripe.api_key = os.getenv('STRIPE_API_KEY')  # Usa tu propia clave secreta de Stripe

    # Busca la factura en la base de datos
    factura = db.query(models.Facturas).get(factura_id)
    if not factura:
        
        raise HTTPException(status_code=404, detail="Factura no encontrada")

    # Verifica si la factura ha sido pagada
    if factura.EstadoFactura != "Pagada":
        
        raise HTTPException(status_code=400, detail="La factura no ha sido pagada")

    # Busca el PaymentIntent en Stripe
    try:
        payment_intent = stripe.PaymentIntent.retrieve(factura.PaymentIntentID)
    except stripe.error.InvalidRequestError as e:
       
        raise HTTPException(status_code=400, detail="PaymentIntent no encontrado")

    # Crea un Refund en Stripe
    try:
        refund = stripe.Refund.create(
            payment_intent=payment_intent.id,
        )
    except stripe.error.InvalidRequestError as e:
      
        raise HTTPException(status_code=500, detail="Fallo al crear el reembolso")

    # Actualiza el estado de la factura a "Reembolsada"
    factura.EstadoFactura = "Reembolsada"
    db.commit()

    # Devuelve el ID del reembolso
    return {"refund_id": refund.id}


#endpoint que recibe el token de dispositivo atraves del id del usuario
@app.post("/save-device-token")
async def save_device_token(device_token: DeviceToken, db: Session = Depends(get_db)):
    usuario = db.query(User).get(device_token.usuario_id)
    
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    usuario.DeviceToken = device_token.device_token
    db.commit()
    return {"message": "Token de dispositivo guardado correctamente."}



@app.post("/descuentos", response_model=schemas.Descuento)
def create_descuento(descuento: schemas.DescuentoCreate, db: Session = Depends(get_db)):
    db_usuario = crud.get_usuario(db, descuento.UsuarioID)
    if not db_usuario:
        raise HTTPException(status_code=400, detail="UsuarioID does not exist.")

    db_espacio = crud.get_espacio(db, descuento.EspacioID)
    if not db_espacio:
        raise HTTPException(status_code=400, detail="EspacioID does not exist.")

    overlapping_discounts = db.query(models.Descuentos).filter(
        models.Descuentos.EspacioID == descuento.EspacioID,
        models.Descuentos.FechaInicioDescuento <= descuento.FechaFinDescuento,
        models.Descuentos.FechaFinDescuento >= descuento.FechaInicioDescuento
    ).first()

    if overlapping_discounts:
        raise HTTPException(status_code=400, detail="Ya existe un descuento para el espacio y el rango de fechas proporcionado.")

    if descuento.FechaInicioDescuento > descuento.FechaFinDescuento:
        raise HTTPException(status_code=400, detail="FechaInicioDescuento no puede ser mayor que FechaFinDescuento.")

    if descuento.FechaInicioDescuento < datetime.now():
        raise HTTPException(status_code=400, detail="FechaInicioDescuento no puede ser anterior a la fecha actual.")

    db_descuento = models.Descuentos(**descuento.dict())
    db.add(db_descuento)
    db.commit()
    db.refresh(db_descuento)
    
    return db_descuento
