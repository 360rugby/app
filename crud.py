from fastapi import HTTPException
from sqlalchemy.orm import Session, joinedload
from datetime import datetime
import models, schemas, security
from security import get_password_hash

def get_users(db: Session):
    users = db.query(models.User).options(joinedload(models.User.user_roles)).all()
    for user in users:
        user.user_roles_names = [role.to_dict()["NombreRol"] for role in user.user_roles]  
    return [user.to_dict() for user in users]

def create_user(db: Session, user: schemas.UserCreate):
    if user.Contrasena != user.ConfirmarContrasena:
        raise HTTPException(
            status_code=400, detail="Passwords do not match"
        )

    db_user_by_name = get_user_by_username(db, user.NombreUsuario)
    db_user_by_email = get_user_by_email(db, user.CorreoElectronico)
    if db_user_by_name or db_user_by_email:
        raise HTTPException(
            status_code=400, detail="Username or email already registered"
        )

    db_user = models.User(**user.dict(exclude={"ConfirmarContrasena"}))  # No queremos guardar ConfirmarContrasena
    db_user.Contrasena = get_password_hash(user.Contrasena)  # Aquí es donde se cambia la contraseña en texto plano por un hash
    if user.Movil:  # Sólo añadir prefijo si el usuario proporcionó un número de móvil
        db_user.Movil = "+34" + user.Movil
    db_user.FechaCreacion = datetime.now()

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    user_role = models.UserRoles(UsuarioID=db_user.UsuarioID, RolID=2)
    db.add(user_role)
    db.commit()

    return db_user


def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.NombreUsuario == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username) or get_user_by_email(db, username) 
    if not user:
        return False
    if not security.verify_password(password, user.Contrasena):
        return False
    return user

def verify_password(plain_password, hashed_password):
    return security.verify_password(plain_password, hashed_password)

def get_password_hash(password):
    return security.get_password_hash(password)

# La función get_user_by_token se ha renombrado a get_user_by_id y su implementación ha sido modificada.
def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.UsuarioID == user_id).first()

def change_password(db: Session, user: models.User, new_password: str):
    user.Contrasena = get_password_hash(new_password)
    db.commit()
    return user

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.NombreUsuario == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.CorreoElectronico == email).first()

def get_user_by_mobile(db: Session, mobile: str):
    return db.query(models.User).filter(models.User.Movil == mobile).first()


