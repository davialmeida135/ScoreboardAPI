from .database import db
from flask import Blueprint, jsonify, request
from app.models import User,Match,MatchMoment,MatchSet

match_bp = Blueprint('match', __name__)



@match_bp.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@match_bp.route('/users/<username>', methods=['GET'])
def get_user_matches(username):
    user_matches = Match.query.filter(Match.ownerUsername == username).all()
    return [match.to_json() for match in user_matches]

@match_bp.route('/matches/new', methods=['POST'])
def create_match():
    data = request.get_json()
    print(data)
    match = Match.from_dict(data)
    db.session.add(match)
    db.session.commit()
    return jsonify({'message': 'Match created successfully'}), 201

@match_bp.route('/matches/update', methods=['POST'])
def update_match():
    data = request.get_json()
    match = Match.query.get(data['idMatch'])
    if not match:
        return jsonify({'message': 'Match not found'}), 404
    
    match = Match.from_dict(data)
    db.session.commit()
    return jsonify({'message': 'Match updated successfully'}), 200

@match_bp.route('/matches', methods=['GET'])
def get_matches():
    print("matches")
    matches = Match.query.all()
    #print(matches)
    return [match.to_json() for match in matches]

@match_bp.route('/matches/<int:match_id>', methods=['GET'])
def get_match(match_id):
    match = Match.query.get(match_id)
    if not match:
        return jsonify({'message': 'Match not found'}), 404

    # Get the current match moment
    current_moment = MatchMoment.query.filter_by(idMatch=match_id).order_by(MatchMoment.idMatchMoment.desc()).first()
    if not current_moment:
        return jsonify({'message': 'No match moments found for this match'}), 404
    
    return match.to_json()
