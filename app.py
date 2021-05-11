from flask import Flask, jsonify, request, make_response, jsonify
import jwt
import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = 'blahblah'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///temp.db'
app.config["JWT_SECRET_KEY"] = "thisisthetimeofyourlife"  # Change this!
app.config["JWT_COOKIE_SECURE"] = False


jwt = JWTManager(app)


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50))
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401)

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401)

    if check_password_hash(user.password, auth.password):
        response = jsonify({"msg": "login successful"})
        access_token = create_access_token(identity=auth.username)
        set_access_cookies(response, access_token)
        return response

    return make_response('Could not verify', 401)


@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    
    return jsonify({'users': output})

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    return jsonify({'msg': 'success'})

# @app.route('/user/<public_id>', methods=['GET'])
# # @token_required
# def get_one_user(current_user, public_id):

#     user = User.query.filter_by(public_id=public_id).first()

#     if not user:
#         return jsonify({'message': 'No user found'})

#     user_data = {}
#     user_data['public_id'] = user.public_id
#     user_data['name'] = user.name
#     user_data['password'] = user.password
#     user_data['admin'] = user.admin

#     return jsonify({'user': user_data})
    

# @app.route('/user', methods=['POST'])
# def create_user():
#     data = request.get_json(force=True)

#     hashed_password = generate_password_hash(data['password'], method='sha256')

#     new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({'message': 'New user created'})

# @app.route('/user/<public_id>', methods=['PUT'])
# def promote_user(public_id):

#     user = User.query.filter_by(public_id=public_id).first()

#     if not user:
#         return jsonify({'message': 'No user found'})
    
#     user.admin = True
#     db.session.commit()

#     return jsonify({'message': 'User promoted'})

# @app.route('/user/<public_id>', methods=['DELETE'])
# def delete_user(public_id):

#     user = User.query.filter_by(public_id=public_id).first()

#     if not user:
#         return jsonify({'message': 'No user found'})

#     db.session.delete(user)
#     db.session.commit()

#     return jsonify({'message': 'User deleted'})


# @app.route('/login', methods=['POST'])
# def login():
#     auth = request.authorization

#     if not auth or not auth.username or not auth.password:
#         return make_response('Could not verify', 401)

#     user = User.query.filter_by(name=auth.username).first()

#     if not user:
#         return make_response('Could not verify', 401)

#     if check_password_hash(user.password, auth.password):
#         token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)}, app.config['SECRET_KEY'])

#         response = make_response("cookie fun")
#         response.set_cookie("x-access-token", token.decode('UTF-8'), httponly=True, samesite="Lax", max_age=30)
#         return response


#         # return jsonify({'token': token.decode('UTF-8')})

#     return make_response('Could not verify', 401)

# @app.route('/refresh', methods=['GET'])
# def refresh():
#     return ''

# @app.route('/todo/<todo_id>', methods=['GET'])
# @token_required
# def get_one_todo(current_user, todo_id):
#     return ''

# @app.route('/todo/<todo_id>', methods=['POST'])
# @token_required
# def create_todo(current_user, todo_id):
#     data = request.get_json()

#     new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
#     db.session.add(new_todo)
#     db.session.commit()
#     return jsonify({'message': 'Todo created'})

# @app.route('/todo/<todo_id>', methods=['PUT'])
# @token_required
# def complete_todo(current_user, todo_id):
#     return ''

# @app.route('/todo', methods=['GET'])
# @token_required
# def get_all_todos(current_user, todo_id):
#     return ''

# @app.route('/todo/<todo_id>', methods=['DELETE'])
# @token_required
# def delete_todo(current_user, todo_id):
#     return ''

if __name__ == '__main__':
    app.run(debug=True)
