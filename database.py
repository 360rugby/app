from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError
from fastapi import HTTPException

SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:@localhost/sion"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Define Base here
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    except OperationalError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database connection failed.")
    finally:
        db.close()
