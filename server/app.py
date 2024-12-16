#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        image_url = json.get('image_url')
        bio = json.get('bio')
        errors = {}
        if not username:
            errors['username'] = 'Username is required.'
        if not password:
            errors['password'] = 'Password is required.'
        
        if errors:
            return make_response(jsonify(errors), 422)
        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )
        try:
            user.password_hash = password
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return make_response(jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 201)
        except IntegrityError:
            db.session.rollback()
            return make_response(jsonify({'username': 'Username must be unique.'}), 422)

class CheckSession(Resource):
    def get(self):
        
        user_id = session['user_id']
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            return user.to_dict(), 200
        
        return {}, 401

class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        user = User.query.filter(User.username == username).first()
        password = request.get_json()['password']
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session['user_id']
        if user_id:
            session['user_id'] = None
            return {}, 204  # No Content
        else:
            return {"message": "User not logged in"}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            recipes = Recipe.query.all()
            return make_response(jsonify([recipe.to_dict() for recipe in recipes]), 200)
        return make_response(jsonify({'message': 'Unauthorized'}), 401)
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(jsonify({'message': 'Unauthorized'}), 401)
        
        json_data = request.get_json()
        title = json_data.get('title')
        instructions = json_data.get('instructions')
        minutes_to_complete = json_data.get('minutes_to_complete')
        errors = {}
        if not title:
            errors['title'] = 'Title is required.'
        if len(instructions) < 50:
            errors['instructions'] = 'Instructions must be at least 50 characters long'
        if not minutes_to_complete:
            errors['minutes_to_complete'] = 'Minutes to complete is required.'
        if errors:
            return make_response(jsonify(errors), 422)
        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
        )
        try:
            db.session.add(recipe)
            db.session.commit()
            return make_response(jsonify(recipe.to_dict()), 201)
        except IntegrityError:
            db.session.rollback()
            return jsonify({'message': 'Error saving the recipe.'}), 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run
