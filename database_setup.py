
# Configuration Code

import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()


# User Model

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


# Class Code

class GroceryList(Base):
    __tablename__ = 'grocerylist'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }

class GroceryItem(Base):
    __tablename__ = 'grocery_item'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    catagory = Column(String(250))
    grocerylist_id = Column(Integer, ForeignKey('grocerylist.id'))
    grocerylist = relationship(GroceryList, backref=backref("groceryitem", cascade='all, delete-orphan'))
    """Delete cascade marks child objects for deletion"""
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'product': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
            'catagory': self.catagory,
        }


# Configuration Code

engine = create_engine('sqlite:///groceryitemswithusers.db')
Base.metadata.create_all(engine)
