# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from sqlalchemy import UniqueConstraint
from apps import db
from apps.authentication.util import hash_pass
from sqlalchemy import DateTime


class Devices(db.Model):
    __tablename__ = 'Devices'

    id = db.Column(db.Integer, primary_key=True)
    devicename = db.Column(db.String(64), unique=True)
    password = db.Column(db.LargeBinary)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == 'password':
                value = hash_pass(value)  # we need bytes here (not plain str)

            setattr(self, property, value)

    def __repr__(self):
        return str(self.devicename)

    def to_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}


class TrackTrn(db.Model):
    __tablename__ = 'track_trn'

    id = db.Column(db.Integer, primary_key=True)
    devicename = db.Column(db.String(64))
    tag = db.Column(db.String(64))
    track_id = db.Column(db.Integer)
    tracked_seconds = db.Column(db.Integer)
    moved_distance = db.Column(db.Integer)
    age = db.Column(db.String(64))
    gender = db.Column(db.String(64))
    datetime = db.Column(DateTime())
    is_entry = db.Column(db.Integer)

    __table_args__ = (UniqueConstraint('devicename', 'tag', 'track_id', name='track_uc'),)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            setattr(self, property, value)

    def to_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}


class UserTrackMapper(db.Model):
    __tablename__ = 'user_track_mapper'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    devicename = db.Column(db.String(64), nullable=False)
    __table_args__ = (UniqueConstraint('devicename', 'username', name='usertrackmapper_uc'),)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            setattr(self, property, value)


class Dashboard():
    total = 0
    male_4 = 0
    male_16 = 0
    male_30 = 0
    male_50 = 0
    female_4 = 0
    female_16 = 0
    female_30 = 0
    female_50 = 0

    def to_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
