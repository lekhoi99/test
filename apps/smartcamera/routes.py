# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from functools import wraps
from flask import request, jsonify
from apps import db
from apps.authentication import blueprint
from apps.authentication.util import verify_pass, hash_pass
from apps.authentication.models import Users
from apps.smartcamera.models import Devices, TrackTrn, UserTrackMapper, Dashboard
import jwt
from datetime import date, datetime, timedelta
from flask import current_app
import numpy as np
import pandas as pd
from flask import abort
from apps.config import config_dict


def token_required(f):
    # TODO This currently needs to also validate with username tokens
    # token decode must validate with username and password in Users table
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        print(request.headers)

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
            print(token)

        if not token:
            return jsonify({'message': 'a valid token is missing'}), 401
        try:
            token = token.replace("Bearer ", "")
            data = jwt.decode(token, current_app.config["SECRET_KEY"])
            print(f'data: {data}')
            user = Users.query.filter_by(username=data['public_id']).first()
            print(user)

            if user is None:
                # not a user token or token is invalid, try device token
                device = Devices.query.filter_by(devicename=data['public_id']).first()

                if device is None:
                    # not a device token either, return invalid
                    return jsonify({'message': 'token is invalid'}), 401
                else:
                    return f(device, *args, **kwargs)
            else:
                return f(user, *args, **kwargs)
        except Exception:
            return jsonify({'message': 'token is invalid'}), 401

    return decorator


@blueprint.route('/logindevice', methods=['GET', 'POST'])
def logindevice():
    try:
        """login device"""
        args = request.get_json()

        devicename = args["devicename"]
        password = args["password"]

        # Locate device
        device = Devices.query.filter_by(devicename=devicename).first()

        # Check the password
        if device and verify_pass(password, device.password):
            token = jwt.encode({'public_id': device.devicename, 'exp': datetime.utcnow() + timedelta(minutes=300)},
                               current_app.config['SECRET_KEY'])
            print(token)
            return jsonify({'token': token.decode('UTF-8')})

        # Something (user or pass) is not ok
        abort(400, description="unsuccessfull device login")
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/add_device', methods=['GET', 'POST'])
def add_device():
    try:
        """add new device"""
        args = request.get_json()

        devicename = args["devicename"]
        # Check devicename exists
        device = Devices.query.filter_by(devicename=devicename).first()
        if device:
            abort(400, description="Device already registered")

        # else we can create the user
        device = Devices(**args)
        db.session.add(device)
        db.session.commit()
        return jsonify({'message': 'Device registered'})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/update_device_password', methods=['GET', 'POST'])
@token_required
def update_device_password(device):
    try:
        """update password"""
        args = request.get_json()

        devicename = args["devicename"]
        password = args["newpassword"]

        # Check the password
        if device.devicename == devicename:
            """add new device"""
            device.password = hash_pass(password)

            # db.session.update(device)
            db.session.commit()

            return jsonify({'device password changed': devicename})

        # Something (device name is not same as token)
        return {"ticket": f"unsuccessful device password change: "
                          f"old device: {devicename} "
                          f"token device:{device.devicename}"}, 401
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/delete_device', methods=['GET', 'POST'])
def delete_device():
    try:
        """delete device"""
        args = request.get_json()

        devicename = args["devicename"]
        password = args["password"]

        # Locate user
        device = Devices.query.filter_by(devicename=devicename).first()

        # Check the password
        if device and verify_pass(password, device.password):
            db.session.delete(device)

            # delete the user_track_mapper
            usm = UserTrackMapper.query.filter_by(devicename=devicename).first()
            if usm:
                db.session.delete(usm)
            db.session.commit()
            return jsonify({'device deleted': devicename})

        # Something (user or pass) is not ok
        return {"ticket": f"unsuccessfull delete device {devicename}"}, 401
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/track_upload', methods=['POST'])
@token_required
def track_upload(device):
    try:
        # devicename = Devices.query.filter_by(devicename=device).first()
        # """add new device"""
        print(f'testing{device}')

        data = request.get_json()["data"]

        print(data)
        for item in data:
            # print(item)
            try:
                # create the item
                exist = db.session.query(TrackTrn).filter(TrackTrn.devicename == item["devicename"]).filter(
                    TrackTrn.tag == item["tag"]).filter(TrackTrn.track_id == item["track_id"]).first()
                print(f'exist: {exist}')
                if exist is None:
                    track = TrackTrn(**item)
                    # populate datetime
                    track.datetime = datetime.fromisoformat(item['datetime'])

                    db.session.add(track)
                    db.session.commit()
                item['is_uploaded'] = 1
            except Exception as e:
                print(e)
                item['is_uploaded'] = 0

        return jsonify({'data': data})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/get_device_list', methods=['GET'])
@token_required
def get_device_list(user):
    try:
        """add new device relation to user"""
        username = str(user.username)

        # Check devicename exists
        usertrackmapper = UserTrackMapper.query.filter_by(username=username)

        if usertrackmapper:
            devices = []
            for item in usertrackmapper:
                device = Devices.query.filter_by(devicename=item.devicename)[0]
                devices.append(device.to_dict())
            for i in range(len(devices)):
                del devices[i]['password']
            print(devices)
            return jsonify({"devices": devices})
        else:
            return jsonify({})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/add_device_relation', methods=['GET', 'POST'])
@token_required
def add_device_relation(user):
    try:
        """add new device relation to user"""
        args = request.get_json()

        devicename = args["devicename"]
        devicepassword = args["devicepassword"]
        print('here')
        print(args)
        # Locate device
        device = Devices.query.filter_by(devicename=devicename).first()

        # Check the password and if the device exists
        if device and verify_pass(devicepassword, device.password):
            print('here2')
            print('here22')

            usertrackmapper = UserTrackMapper.query.filter_by(username=user.username).filter_by(
                devicename=devicename).first()

            if usertrackmapper:
                print('here2.2')
                return jsonify({'error': 'Device Relation is already mapped'})
            print('here3')

            # check username exists
            user = Users.query.filter_by(username=user.username).first()
            print('here4')

            if user:
                # we can create the usm
                utm = {'username': user.username, 'devicename': devicename}
                usm = UserTrackMapper(**utm)
                db.session.add(usm)
                db.session.commit()
                return jsonify({'success': 'Device Relation Registered'})
            else:
                return jsonify({'error': 'Username does not exist'})

        else:
            return jsonify(
                {'error': 'Cannot add relation because the Device Password is incorrect or the Device does not exist'})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/delete_device_relation', methods=['GET', 'POST'])
@token_required
def delete_device_relation(user):
    try:
        """add new device relation to user"""
        args = request.get_json()

        devicename = args["devicename"]
        devicepassword = args["devicepassword"]

        # Locate device
        device = Devices.query.filter_by(devicename=devicename).first()
        if (str(devicepassword) == str(device.password)):
            print("password is corect")
        else:
            print(f'devicepassword {devicepassword}')
            print(f'device.password {device.password}')

        # Check the password and if the device exists
        if device and str(devicepassword) == str(device.password):

            usertrackmapper = UserTrackMapper.query.filter_by(username=user.username).filter_by(
                devicename=devicename).one()
            if usertrackmapper:
                db.session.delete(usertrackmapper)
                db.session.commit()
                return jsonify({'success': 'Device Relation is deleted'})
            else:
                return jsonify({'error': 'Device Relation does not exist'})

        return jsonify(
            {'error': 'Cannot remove relation because the Device Password is incorrect or the Device does not exist'})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/get_tracklist', methods=['GET'])
@token_required
def get_tracklist(user):
    try:
        params = request.args
        username = str(user.username)
        fromdate = datetime.strptime(request.args['fromdate'], '%Y-%m-%d').date()
        todate = datetime.strptime(request.args['todate'], '%Y-%m-%d').date()

        usertrackmapper = UserTrackMapper.query.filter_by(username=username)
        devices = []

        if usertrackmapper:
            devices = []
            for item in usertrackmapper:
                devices.append(item.devicename)
            print(devices)
        tracklist = []
        if params['device'] == '':
            if len(devices) > 0:
                for item in devices:
                    tracks = TrackTrn.query.filter_by(devicename=item).filter(
                        TrackTrn.datetime.between(fromdate, todate))
                    for track in tracks:
                        tracklist.append(track.to_dict())
        if params['device'] != '':
            if params['tag'] == '':
                if len(devices) > 0:
                    for item in devices:
                        if item == params['device']:
                            tracks = TrackTrn.query.filter_by(devicename=item).filter(
                                TrackTrn.datetime.between(fromdate, todate))
                            for track in tracks:
                                tracklist.append(track.to_dict())
            if params['tag'] != '':
                if len(devices) > 0:
                    for item in devices:
                        if item == params['device']:
                            tracks = TrackTrn.query.filter_by(devicename=item, tag=params['tag']).filter(
                                TrackTrn.datetime.between(fromdate, todate))
                            for track in tracks:
                                tracklist.append(track.to_dict())
        dashboard = get_dashboard_by_date(username, fromdate, todate)
        linechart = get_linechart(tracklist, fromdate, todate)
        return jsonify({'tracklist': tracklist,
                        'dashboard': dashboard,
                        'linechart': linechart})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


def get_dashboard_by_date(username, fromdate, todate):
    usertrackmapper = UserTrackMapper.query.filter_by(username=username)
    devices = []

    if usertrackmapper:
        devices = []
        for item in usertrackmapper:
            devices.append(item.devicename)
        print(devices)

    ret_dashboard = Dashboard()

    if len(devices) > 0:
        for item in devices:
            # totals
            ret_dashboard = get_dashboardbydate(item, ret_dashboard, fromdate, todate)
    print(ret_dashboard.__dict__)

    return ret_dashboard.__dict__


def get_linechart(tracklist, fromdate, todate):
    # interval
    interval = (todate - fromdate).days

    # create data grid

    columnnames = list(AGE_GENDERMAP.keys())

    indexarr = np.arange(0, interval, step=1)
    df = pd.DataFrame(columns=columnnames, index=indexarr)

    df = df.fillna(0)

    for item in tracklist:
        trackdate = datetime.fromisoformat(item['datetime']).date()
        # get the date row index
        indexn = (trackdate - fromdate).days
        columnindex = f'{item["gender"]}{item["age"]}'

        print(f'[{indexn}][{columnindex}]')
        df.loc[indexn][columnindex] += 1

    linechart = {}
    linechart['labels'] = [(fromdate + timedelta(days=i)).isoformat() for i in range(0, interval)]
    print(linechart['labels'])

    datasetarr = []
    for item in AGE_GENDERMAP:
        data = {}
        data['label'] = AGE_GENDERMAP[item]
        data['backgroundColor'] = BG_MAP[item]
        data['borderColor'] = BG_MAP[item]
        data['pointBackgroundColor'] = BG_MAP[item]
        data['data'] = df[item].to_list()
        datasetarr.append(data)
        print(data)

    linechart['datasets'] = datasetarr
    return linechart


@blueprint.route('/get_dashboard', methods=['GET'])
@token_required
def get_dashboard(user):
    try:
        username = str(user.username)

        usertrackmapper = UserTrackMapper.query.filter_by(username=username)
        devices = []

        if usertrackmapper:
            devices = []
            for item in usertrackmapper:
                devices.append(item.devicename)
            print(devices)

        yesterday = date.today() - timedelta(days=1)
        lastweekday = date.today() - timedelta(days=7)
        lastmonthday = date.today() - timedelta(days=30)

        print(yesterday)
        print(lastweekday)
        print(lastmonthday)
        yeserdaydashboard = Dashboard()
        lastweek = Dashboard()
        lastmonth = Dashboard()

        if len(devices) > 0:
            for item in devices:
                # total yeserdaydashboard
                yeserdaydashboard = get_dashboardbydate(item, yeserdaydashboard, yesterday, date.today())
                lastweek = get_dashboardbydate(item, lastweek, lastweekday, date.today())
                lastmonth = get_dashboardbydate(item, lastmonth, lastmonthday, date.today())

        return jsonify({'yesterday': yeserdaydashboard.__dict__,
                        'lastweek': lastweek.__dict__,
                        'lastmonth': lastmonth.__dict__})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/register_user', methods=['GET', 'POST'])
def register_user():
    try:
        args = request.get_json()

        username = args['username']
        email = args['email']

        # Check usename exists
        user = Users.query.filter_by(username=username).first()
        if user:
            return jsonify({'message': 'Username already registered'})

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return jsonify({'message': 'Email already registered'})

        # else we can create the user
        user = Users(**args)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/login_user', methods=['GET', 'POST'])
def login_user():
    try:
        args = request.get_json()

        username = args['username']
        password = args['password']

        # Locate user
        user = Users.query.filter_by(username=username).first()

        # Check the password
        if user and verify_pass(password, user.password):
            # TODO token decode must validate with username and password in Users table
            token = jwt.encode({'public_id': username, 'exp': datetime.utcnow() + timedelta(minutes=300)},
                               current_app.config['SECRET_KEY'])
            print(token)
            return jsonify({'token': token.decode('UTF-8')})

        # Something (user or pass) is not ok
        return jsonify({'message': 'User login unsuccessful'})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


@blueprint.route('/get_client_version', methods=['GET'])
def get_client_version():
    try:
        clientversion = config_dict['Production'].CLIENT_VERSION
        print(clientversion)
        return jsonify({"current_client_version": clientversion})
    except Exception as e:
        print(e)
        return jsonify({'error': e}), 400


def get_dashboardbydate(devicename, dashboard, from_date, to_date):
    dashboard.total += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).count()
    dashboard.male_4 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 0).filter(TrackTrn.gender == 0).count()
    dashboard.male_16 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 1).filter(TrackTrn.gender == 0).count()
    dashboard.male_30 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 2).filter(TrackTrn.gender == 0).count()
    dashboard.male_50 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 3).filter(TrackTrn.gender == 0).count()

    dashboard.female_4 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 0).filter(TrackTrn.gender == 1).count()
    dashboard.female_16 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 1).filter(TrackTrn.gender == 1).count()
    dashboard.female_30 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 2).filter(TrackTrn.gender == 1).count()
    dashboard.female_50 += TrackTrn.query.filter_by(devicename=devicename).filter(
        TrackTrn.datetime.between(from_date, to_date)).filter(TrackTrn.age == 3).filter(TrackTrn.gender == 1).count()

    return dashboard


AGE_GENDERMAP = {}
AGE_GENDERMAP['00'] = "Male 4-16"
AGE_GENDERMAP['01'] = "Male 16-30"
AGE_GENDERMAP['02'] = "Male 30-50"
AGE_GENDERMAP['03'] = "Male 50+"
AGE_GENDERMAP['10'] = "Female 4-16"
AGE_GENDERMAP['11'] = "Female 16-30"
AGE_GENDERMAP['12'] = "Female 30-50"
AGE_GENDERMAP['13'] = "Female 50+"

BG_MAP = {}
BG_MAP['00'] = "rgb(228,102,81,0.9)"
BG_MAP['01'] = "rgb(222,216,255,0.9)"
BG_MAP['02'] = "rgb(90,102,81,0.9)"
BG_MAP['03'] = "rgb(180,216,255,0.9)"
BG_MAP['10'] = "rgb(159,102,81,0.9)"
BG_MAP['11'] = "rgb(0,216,255,0.9)"
BG_MAP['12'] = "rgb(213,102,81,0.9)"
BG_MAP['13'] = "rgb(123,111,255,0.9)"
