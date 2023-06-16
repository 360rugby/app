from sqlalchemy.orm import Session
from datetime import datetime
from . import models, schemas, security

def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.NombreUsuario == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not security.verify_password(password, user.Contrasena):
        return False
    return user

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.UsuarioID == user_id).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(**user.dict())
    db_user.FechaCreacion = datetime.now() # asignar la fecha de creación antes de guardar
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user(db: Session, user: schemas.UserUpdate):
    db_user = get_user_by_id(db, user.UsuarioID)
    if db_user is None:
        return None
    for var, value in vars(user).items():
        if var == "Contrasena":
            value = security.get_password_hash(value)
        setattr(db_user, var, value) if value else None
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    db.delete(user)
    db.commit()
    return user

def verify_password(plain_password, hashed_password):
    return security.verify_password(plain_password, hashed_password)

def get_password_hash(password):
    return security.get_password_hash(password)
