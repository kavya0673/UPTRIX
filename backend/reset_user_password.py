from database import SessionLocal
import models
from passlib.context import CryptContext
import os
import sys


def main():
    username = os.getenv('UPTRIX_RESET_USERNAME')
    password = os.getenv('UPTRIX_RESET_PASSWORD')
    if not username or not password or len(password) < 12:
        raise SystemExit('Set UPTRIX_RESET_USERNAME and a UPTRIX_RESET_PASSWORD of at least 12 characters.')
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            raise SystemExit('No account matches UPTRIX_RESET_USERNAME.')
        user.hashed_password = CryptContext(schemes=['pbkdf2_sha256'], deprecated='auto').hash(password)
        user.is_active = True
        db.commit()
        print('Password reset completed. The account role was left unchanged.')
    finally:
        db.close()


if __name__ == '__main__':
    main()
