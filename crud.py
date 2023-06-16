from sqlalchemy.orm import Session, joinedload
from datetime import datetime
import models, schemas, security

def get_users(db: Session):
    users = db.query(models.User).options(joinedload(models.User.user_roles)).all()
    for user in users:
        user.user_roles_names = [role.to_dict()["NombreRol"] for role in user.user_roles]  
    return [user.to_dict() for user in users]

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(**user.dict())
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
    user = get_user(db, username)
    if not user:
        return False
    if not security.verify_password(password, user.Contrasena):
        return False
    return user

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.UsuarioID == user_id).first()

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

# Nueva función para obtener un usuario por su token
def get_user_by_token(db: Session, token: str):
    return db.query(models.User).filter(models.User.Token == token).first()
