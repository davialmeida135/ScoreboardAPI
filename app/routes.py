import bcrypt
import re
import json
import time
from datetime import timedelta
from .database import db
from flask import Blueprint, jsonify, request
from app.models import User,Match,MatchMoment,MatchSet
from flask_jwt_extended import JWTManager,create_access_token, get_jwt_identity,create_refresh_token,jwt_required
app_bp = Blueprint('app', __name__)
def is_bcrypt_hash(string):
    bcrypt_regex = re.compile(r'^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$')
    return bool(bcrypt_regex.match(string))

#NEW USER
@app_bp.route('/users/new', methods=['POST'])
def create_user():
    data = request.get_json()
    #Password has to be bcrypt hashed
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409
    if not is_bcrypt_hash(data['password']):
        return jsonify({'error': 'Password must be hashed'}), 400
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

#DELETE USER
@app_bp.route('/users/delete', methods=['POST'])
@jwt_required()
def delete_user():
    data = request.get_json()
    user = User.query.filter(User.username == data['username']).first()
    try:
        if user and bcrypt.checkpw(data['password'].encode('utf-8'),user.password.encode('utf-8')):
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'}), 200
        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'message': {str(e)}}), 401

#AUTHENTICATE USER//SEND ACCESS TOKEN
@app_bp.route('/auth', methods=['POST'])
def authenticate_user():

    data = request.get_json()
    if 'username' in data and 'password' in data:
        user = User.query.filter(User.username == data['username']).first()
        if user and bcrypt.checkpw(data['password'].encode('utf-8'),user.password.encode('utf-8')):
            aexpires = timedelta(hours=1)
            rexpires = timedelta(days=360)
            access_token = create_access_token(identity=user.username,expires_delta=aexpires)
            refresh_token = create_refresh_token(identity=user.username,expires_delta=rexpires)
            return jsonify(access_token=access_token,refresh_token=refresh_token), 200       

    return jsonify({'message': 'Invalid credentials'}), 401

#REFRESH ACCESS TOKEN
@app_bp.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True)  # Protects the route, ensuring only valid refresh tokens can access it
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify({'access_token': new_token}), 200

#GET USER MATCHES
@app_bp.route('/user/matches', methods=['GET'])
@jwt_required()
def get_user_matches():
    current_user_username = get_jwt_identity()
    user_matches = Match.query.filter(Match.ownerUsername == current_user_username).all()
    return [match.to_json() for match in user_matches]

#CREATE MATCH
@app_bp.route('/matches/new', methods=['POST'])
@jwt_required()
def create_match():
    data = request.get_json()
    current_user = get_jwt_identity()
    match = Match.from_json(data,current_user)
    db.session.add(match)
    #db.session.add(match)
    db.session.commit()

    return jsonify({'message': 'Match created successfully'}), 201

#UPDATE MATCH
@app_bp.route('/matches/update', methods=['POST'])
@jwt_required()
def update_match():
    data = request.get_json()
    data = json.loads(data)
    # Retrieve the match by ID
    match = Match.query.get(data['idMatch'])
    print(match.to_json())
    if not match:
        return jsonify({"error": "Match not found"}), 404

    # Update match attributes
    match.title = data.get('title', match.title)
    match.player1 = data.get('player1', match.player1)
    match.player2 = data.get('player2', match.player2)
    match.ownerUsername = data.get('ownerUsername', match.ownerUsername)

    # Update moments and sets if provided
    if 'moments' in data:
        moment_data = data['moments'][0]
        #print('oi2')
        if match.moments:
            moment = match.moments[0]
            moment.current_game_p1 = moment_data.get('current_game_p1', moment.current_game_p1)
            moment.current_game_p2 = moment_data.get('current_game_p2', moment.current_game_p2)
            moment.current_set_p1 = moment_data.get('current_set_p1', moment.current_set_p1)
            moment.current_set_p2 = moment_data.get('current_set_p2', moment.current_set_p2)
            moment.match_score_p1 = moment_data.get('match_score_p1', moment.match_score_p1)
            moment.match_score_p2 = moment_data.get('match_score_p2', moment.match_score_p2)

            # Update sets if provided
            if 'sets' in moment_data:
                #print('oi3')
                for i, set_data in enumerate(moment_data['sets']):
                    if i < len(moment.sets):
                        match_set = moment.sets[i]
                        match_set.p1 = set_data.get('p1', match_set.p1)
                        match_set.p2 = set_data.get('p2', match_set.p2)
                    else:
                        new_set = MatchSet(p1=set_data['p1'], p2=set_data['p2'])
                        moment.sets.append(new_set)

    # Commit the changes
    db.session.commit()
    return jsonify({'message': 'Match updated successfully'}), 200

#GET SPECIFIC MATCH
@app_bp.route('/matches/<int:match_id>', methods=['GET'])
def get_match(match_id):
    match = Match.query.get(match_id)
    if not match:
        return jsonify({'message': 'Match not found'}), 404

    # Get the current match moment
    current_moment = MatchMoment.query.filter_by(idMatch=match_id).order_by(MatchMoment.idMatchMoment.desc()).first()
    if not current_moment:
        return jsonify({'message': 'No match moments found for this match'}), 404
    
    return match.to_json()
