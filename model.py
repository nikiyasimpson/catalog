from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask_login import UserMixin
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits)
                     for x in range(32))


class User(Base, UserMixin):
    """Registered user information stored in the database"""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))
    email = Column(String)
    picture = Column(String(250))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    """Category for Furniture Items Stored in the database"""
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String)

    items = relationship("Item", cascade="all, delete-orphan")


class Item(Base):
    """Furniture Item Information stored in the database"""
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    picture = Column(String)
    description = Column(String)
    price = Column(String)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", cascade="save-update")

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
                'id': self.id,
                'name': self.name,
                'picture': self.picture,
                'description': self.description,
                'price': self.price
        }


engine = create_engine('postgresql://catalog:catalog@localhost/itemCatalog')
Base.metadata.create_all(engine)
