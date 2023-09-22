from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_jwt_extended import JWTManager
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

# Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://Tek:Tek778244*-+@localhost:3306/activeapp'
app.config['SECRET_KEY'] = 'V7S@+!C+*zrmHhST'
app.config['JWT_REQUIRED'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
app.config['CORS_HEADERs'] = 'Content-Type'


class User(db.Model):
    __tablename__ = 'user_t'  
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(45), unique=True, nullable=True)
    password = db.Column(db.String(200), unique=True, nullable=True)
    fname = db.Column(db.String(45), nullable=True)
    lname = db.Column(db.String(45), nullable=True)
    create_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    update_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)

    def __repr__(self):
        return f'<User {self.username}> <First name {self.fname}> <Last name {self.lname}> '
    
class Todo(db.Model):
    __tablename__ = 'todo_t'  
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer)
    topic = db.Column(db.String(45), nullable=True)
    content = db.Column(db.String(45), nullable=True)
    status = db.Column(db.String(45), nullable=True)
    type = db.Column(db.String(45), nullable=True)
    create_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    update_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)

    def __repr__(self):
        return f'<Topic {self.topic}> <Content {self.content}> <Status {self.status}>'


class TodoType(db.Model):
    __tablename__ = 'todo_type_t'  
    id = db.Column(db.Integer, primary_key=True)
    todo_type = db.Column(db.String(45), nullable=True)
    def __repr__(self):
        return f'<Todo Type {self.todo_type}> '