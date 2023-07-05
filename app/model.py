from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from app.db_setup import Base, engine
import bcrypt
from jose import jwt
from datetime import datetime, timedelta
from decouple import config
"""
#SQLAlchemy models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
"""

from sqlalchemy import (
    LargeBinary, 
    Column, 
    String, 
    Integer,
    Boolean, 
    UniqueConstraint, 
    PrimaryKeyConstraint
)
JWT_SECRET =config("secret")
JWT_ALGORITHM = config("algorithm")



class User(Base):
    """Models a user table"""
    __tablename__ = "users"
    email = Column(String(225), nullable=False, unique=True)
    id = Column(Integer, nullable=False, primary_key=True)
    hashed_password = Column(LargeBinary, nullable=False)
    full_name = Column(String(225), nullable=False)
    is_active = Column(Boolean, default=False)

    UniqueConstraint("email", name="uq_user_email")
    PrimaryKeyConstraint("id", name="pk_user_id")

    def __repr__(self):
        """Returns string representation of model instance"""
        return "<User {full_name!r}>".format(full_name=self.full_name)
    @staticmethod
    def hash_password(password) -> str:
        """Transforms password from it's raw textual form to 
        cryptographic hashes
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def validate_password(self, password) -> bool:
        """Confirms password validity"""
        return {
            "access_token": jwt.encode(
                {"full_name": self.full_name, "email": self.email},
                "ApplicationSecretKey"
            )
        }

    def generate_token(self) -> dict:
        """Generate access token for user"""
        expiration = datetime.utcnow() + timedelta(minutes=15)

        payload = {
            "full_name": self.full_name,
            "email": self.email,
            "exp": expiration
        }
        return {
            "access_token": jwt.encode(payload, JWT_SECRET,algorithm=JWT_ALGORITHM)
        }
        """
        return {
            "access_token": jwt.encode(
                {"full_name": self.full_name, "email": self.email},
                JWT_SECRET
            )
        }
"""
Base.metadata.create_all(engine)
