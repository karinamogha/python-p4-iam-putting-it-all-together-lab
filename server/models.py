from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.ext.associationproxy import association_proxy

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    recipes = db.relationship('Recipe', backref='user')
    serialize_rules = ('-password_hash', '-recipes',)
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')
    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))
    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'
    @validates('username')
    def validate_username(self, key, value):
        if not value:
            raise ValueError("Username must be present")
        if User.query.filter_by(username=value).first():
            raise ValueError("Username must be unique")
        return value

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # serialize_rules = ('-user_id',)
    user_object = association_proxy('user', 'serialize', creator=lambda user: User(serialize=user))
    @validates('title')
    def validate_title(self, key, value):
        if not value:
            raise ValueError("Title must be present")
        return value
    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value:
            raise ValueError("Instructions must be present")
        if len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return value

