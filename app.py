from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from models import User, Todo, TodoType, app, db, jwt
from datetime import datetime
from flask_jwt_extended import jwt_required, get_jwt_identity,create_access_token, get_jwt_identity
import bcrypt

@app.route('/api/registor', methods=['POST'])
def registor():
    try:
        data = request.get_json()
        username = data['username']
        user = User.query.filter_by(username=username).first()
        if user is None:
            new_user = User(username=data['username'],
                            password=hash_password(data['password']),
                            fname=data['fname'],
                            lname=data['lname'])
            db.session.add(new_user)
            db.session.commit()
            return {'success':True,'message': 'success'}, 200
        else:return {'success':True,'message': 'There is already a user in the system.'}, 200
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username')
        password = request.json.get('password')
        user = User.query.filter_by(username=username).first()
        if user is not None:
            if check_password(password, user.password) == True:
                access_token = create_access_token(identity=username)
                return {'data':{"id":user.id,"username":user.username,
                                "fname":user.fname,
                                "lname":user.lname}
                                , 'success':True
                                ,'message': 'success'
                                ,'token':access_token}, 200
            else:return {'success':True,'message': 'Password incorrect'}, 200
        else:return {'success':True,'message': 'User not found'}, 200
    except Exception as e:
        return {'error': str(e)}, 400
    
@app.route('/api/gettodo', methods=['GET'])
def gettodo():
    try:
        todos = Todo.query.all()
        todo_list = [{"id": todo.id,
                    "owner_id": todo.owner_id,
                    "topic": todo.topic,
                    "content": todo.content,
                    "status":todo.status,
                    "type":todo.type} for todo in todos]
        return {'data':todo_list,'success':True,'message': 'success'}, 200
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/createtodo', methods=['POST'])
@jwt_required()
def createTodo():
    try:
        data = request.get_json()
        new_todo = Todo(
            owner_id =data["owner_id"],
            topic = data["topic"],
            content = data["content"],
            type = data["type"],
            status = "New",
        )
        db.session.add(new_todo)
        db.session.commit()
        return {'success':True,'message': 'success'}, 200
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/edittodo/<int:todo_id>', methods=['POST'])
@jwt_required()
def editTodo(todo_id):
    try:
        data = request.get_json()
        todo = Todo.query.get(todo_id)
        if todo is not None:
            todo.topic = data["topic"]
            todo.content = data["content"]
            todo.type = data["type"]
            db.session.commit()
            return {'success':True,'message': 'success'}, 200
        else: return {'success':True,'message': 'Todo not found'}, 200
    except Exception as e:
        return {'error': str(e)}, 400
    
@app.route('/api/inprogress/<int:todo_id>', methods=['PUT'])
@jwt_required()
def updateInprogress(todo_id):
    try:
        todo = Todo.query.get(todo_id)
        if todo is not None:
            if todo.status == "New" or todo.status == "Inprogress" :
                todo.status = "Inprogress"
                db.session.commit()
                return {'success':True,'message': 'success'}, 200
            else:return {'success':True,'message': 'This Todo is complete'}, 200
        else: return {'success':True,'message': 'Todo not found'}, 200
    except Exception as e:
        return {'error': str(e)}, 400
    
@app.route('/api/complete/<int:todo_id>', methods=['PUT'])
@jwt_required()
def completeToDo(todo_id):
    try:
        todo = Todo.query.get(todo_id)
        if todo is not None:
            todo.status = "Complete"
            db.session.commit()
            return {'success':True,'message': 'success'}, 200
        else: return {'success':True,'message': 'Todo not found'}, 200
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/gettodobyuser/<int:id>', methods=['GET'])
@jwt_required()
def gettodobyuser(id):
    try:
        todos = Todo.query.filter_by(owner_id=id).all()
        todo_list = [{"id": todo.id,
                    "owner_id": todo.owner_id,
                    "topic": todo.topic,
                    "content": todo.content,
                    "status":todo.status,
                    "type":todo.type} for todo in todos]
        return {'data':todo_list,'success':True,'message': 'success'}, 200
    except Exception as e:
        return {'error': str(e)}, 400
    
@app.route('/api/gettodotype', methods=['GET'])
@jwt_required()
def gettodotype():
    try:
        todos_types = TodoType.query.all()
        todo_list = [todos_type.todo_type for todos_type in todos_types]
        return {'data':todo_list,'success':True,'message': 'success'}, 200
    except Exception as e:
        return {'error': str(e)}, 400


def hash_password(password):
    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password.decode('utf-8')

def check_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
