from flask import json
from .database import db

class User(db.Model):
    __tablename__ = 'User'
    username = db.Column(db.String(25), primary_key=True, nullable=False)
    password = db.Column(db.String(400), nullable=False)
    matches = db.relationship('Match', backref='owner', cascade='all, delete-orphan')

class Match(db.Model):
    __tablename__ = 'Match'
    idMatch = db.Column(db.Integer, primary_key=True, nullable=False)
    title = db.Column(db.String(100))
    player1 = db.Column(db.String(45))
    player2 = db.Column(db.String(45))
    ownerUsername = db.Column(db.String(25), db.ForeignKey('User.username', ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    moments = db.relationship('MatchMoment', backref='match', cascade='all, delete-orphan')
    
    def to_json(self):
        return {
            'idMatch': self.idMatch,
            'title': self.title,
            'player1': self.player1,
            'player2': self.player2,
            'ownerUsername': self.ownerUsername,
            'moments': [moment.to_json() for moment in self.moments]
        }
    
    @classmethod
    def from_dict(cls,data):
        match = Match()
        
        match.title = data['title']
        match.player1 = data['player1']
        match.player2 = data['player2']
        match.ownerUsername = data['ownerUsername']
        if 'moments' in data:
            match.moments = [MatchMoment.from_dict(moment_data) for moment_data in data['moments']]
        return match

    @classmethod
    def from_json(cls,json_str):
        data = json.loads(json_str)
        return Match.from_dict(data)
    
class MatchMoment(db.Model):
    __tablename__ = 'MatchMoment'
    idMatchMoment = db.Column(db.Integer, primary_key=True, nullable=False)
    idMatch = db.Column(db.Integer, db.ForeignKey('Match.idMatch', ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    current_game_p1 = db.Column(db.String(10))
    current_game_p2 = db.Column(db.String(10))
    current_set_p1 = db.Column(db.Integer)
    current_set_p2 = db.Column(db.Integer)
    match_score_p1 = db.Column(db.Integer)
    match_score_p2 = db.Column(db.Integer)
    sets = db.relationship('MatchSet', backref='match_moment', cascade='all, delete-orphan')
    
    def to_json(self):
        return {
            'idMatchMoment': self.idMatchMoment,
            'idMatch': self.idMatch,
            'current_game_p1': self.current_game_p1,
            'current_game_p2': self.current_game_p2,
            'current_set_p1': self.current_set_p1,
            'current_set_p2': self.current_set_p2,
            'match_score_p1': self.match_score_p1,
            'match_score_p2': self.match_score_p2,
            'sets': [match_set.to_json() for match_set in self.sets]
        }
    
    @classmethod
    def from_dict(cls,data):
        moment = MatchMoment()
        if 'idMatchMoment' in data:
            moment.idMatchMoment = data['idMatchMoment']   
        if 'idMatch' in data:
            moment.idMatch = data['idMatch']

        moment.current_game_p1 = data['current_game_p1']
        moment.current_game_p2 = data['current_game_p2']
        moment.current_set_p1 = data['current_set_p1']
        moment.current_set_p2 = data['current_set_p2']
        moment.match_score_p1 = data['match_score_p1']
        moment.match_score_p2 = data['match_score_p2']

        moment.sets = MatchSet.from_dict(data['sets'])


class MatchSet(db.Model):
    __tablename__ = 'MatchSet'
    idMatchSet = db.Column(db.Integer, primary_key=True, nullable=False)
    idMatchMoment = db.Column(db.Integer, db.ForeignKey('MatchMoment.idMatchMoment', ondelete='CASCADE', onupdate='CASCADE'), nullable=False)
    p1 = db.Column(db.Integer)
    p2 = db.Column(db.Integer)
    def to_json(self):
        return {
            'idMatchSet': self.idMatchSet,
            'idMatchMoment': self.idMatchMoment,
            'p1': self.p1,
            'p2': self.p2
        }

    @classmethod
    def from_dict(cls,data):
        match_set = MatchSet()
        if 'idMatchSet' in data:
            match_set.idMatchSet = data['idMatchSet']
        if 'idMatchMoment' in data:
            match_set.idMatchMoment = data['idMatchMoment']
        match_set.p1 = data['p1']
        match_set.p2 = data['p2']
        return match_set