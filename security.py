from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import models
import secrets

# Configurar el contexto de Passlib
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Generar una clave segura
SECRET_KEY = secrets.token_hex(32)
#print(SECRET_KEY)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Asumiendo que tienes un modelo RevokedTokens
def revoke_token(token: str, db: Session):
    revoked_token = models.RevokedTokens(token=token)
    db.add(revoked_token)
    db.commit()

def is_token_revoked(token: str, db: Session):
    return db.query(models.RevokedTokens).filter(models.RevokedTokens.token == token).first() is not None

# Verificar tokens de refresco
def verify_refresh_token(refresh_token: str, db: Session):
    user = db.query(models.User).filter(models.User.Token == refresh_token).first()
    if not user:
        raise Exception("Invalid refresh token")
    return user.NombreUsuario
