
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
from passlib.context import CryptContext
import os

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def init_users():
    db = SessionLocal()
    try:
        username = os.getenv("UPTRIX_BOOTSTRAP_ADMIN_USERNAME")
        password = os.getenv("UPTRIX_BOOTSTRAP_ADMIN_PASSWORD")
        if bool(username) != bool(password):
            raise RuntimeError("Set both UPTRIX_BOOTSTRAP_ADMIN_USERNAME and UPTRIX_BOOTSTRAP_ADMIN_PASSWORD")
        if username:
            if len(password) < 12:
                raise RuntimeError("Bootstrap admin password must contain at least 12 characters")
            admin = db.query(models.User).filter(models.User.username == username).first()
            if not admin:
                db.add(models.User(username=username, hashed_password=get_password_hash(password), role="Admin",
                                   permissions="admin", is_active=True))
                db.commit()
                print("Bootstrap administrator created.")
            else:
                print("Bootstrap administrator already exists; credentials were not changed.")
        else:
            print("No default users created. Set bootstrap admin environment variables only when needed.")
    finally:
        db.close()

if __name__ == "__main__":
    models.Base.metadata.create_all(bind=engine)
    init_users()
