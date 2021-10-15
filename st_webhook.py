#!/usr/bin/env python
 
#eventlet WSGI server
import eventlet
eventlet.monkey_patch()
 
#Flask Libs
from flask import Flask, abort, request, jsonify, render_template, send_from_directory, session, redirect, url_for, flash
 
#Flask Login Libs
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
 
#Web Sockets
from flask_socketio import SocketIO, send, emit, join_room, leave_room, disconnect, rooms
 
#HTTP Libs
import requests
 
#JSON Libs
import json
 
#datetime
from datetime import datetime, timedelta
 
#My Libs
from smartthings import SmartThings, SmartThingsController
from my_secrets.secrets import SECRET_KEY, ST_WEBHOOK, CORS_ALLOWED_ORIGINS #, LOCAL_NETWORK_IP
 
def isLocalIP(ipVal, ipList):
    status = False
    for item in ipList:
        if item in ipVal:
            status = True
    return status
    
def isGuestIP(user, ip):
    status = False
    ipLocations = stc.getLocationsByNetwork(ip)
    userLocations = [location.location_id for location in user.locations]
    print(f'isGuestIP: {ip} / user: {user.id} / ipLocations: {ipLocations} / userLocations: {userLocations}')
    
    for location in ipLocations:
        if location in userLocations:
            status = True
    return status
 
  
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins=CORS_ALLOWED_ORIGINS)
app.config['SECRET_KEY'] = SECRET_KEY
 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # Defines our flask-login user database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Mute flask-sqlalchemy warning message
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30) # Flask session expiration
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30) # Remember Me cookie expiration (Not sure this works???)
app.config['REMEMBER_COOKIE_SECURE'] = None # Change to True if you want to force using HTTPS to store cookies.
app.config['REMEMBER_COOKIE_HTTPONLY'] = True # Prevents cookies from being accessed on the client-side.
 
db = SQLAlchemy(app) # This gives us our database/datamodel object
 
login_manager = LoginManager(app) # This creates our login manager object
login_manager.login_view = 'login' # Defines our login view (basically calls url_for('login'))
 
class User(UserMixin, db.Model): # This is our User class/model.  It will store our valid users.
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    active = db.Column(db.Boolean) # This value must be True (1) before the user can login.
    email = db.Column(db.String(100), unique=True) # This is our username.  Must be unique.
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    role = db.Column(db.String(25))
    # db.relationship defines the one-to-many relationship with the UserLogin class/table and can be accessible here (but we won't use it that way)
    #   backref tells sqlalchemy that we can also go from UserLogin to User
    #   lazy='dynamic' tells sqlalchemy not to automatically load the related data into the logins attribute.  It could get large.
    logins = db.relationship('UserLogin', backref='users', lazy='dynamic')
    locations = db.relationship('UserLocations', backref='users')
 
class UserLogin(db.Model): # This is our UserLogin class/model.  It will store login related data for our users
    __tablename__ = 'user_login'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    event = db.Column(db.String(50))
    date = db.Column(db.String(100))
    ip = db.Column(db.String(50))
 
class FailedLogin(db.Model): # This is our FailedLogin class/model.  It will store failed login attempts.
    __tablename__ = 'failed_login'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    date = db.Column(db.String(100))
    ip = db.Column(db.String(50))
 
class UserLogging(db.Model): # This is our UserLogging class/model.  It will allow us to turn logging on/off by login-type.
    __tablename__ = 'user_logging'
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(50), unique=True)
    log_event = db.Column(db.Boolean, server_default='True')
 
class UserLocations(db.Model):
    __tablename__ = 'user_locations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    location_id = db.Column(db.String(50))
    current = db.Column(db.Boolean)
    def getName(self):
        return stc.getByLocation(self.location_id).display_name
        
db.create_all() # Creates our database and tables as defined in the above classes.
 
if not UserLogging.query.filter(UserLogging.event == 'login').first():
    log = UserLogging(event = 'login', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'logout').first():
    log = UserLogging(event = 'logout', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'connect').first():
    log = UserLogging(event = 'connect', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'disconnect').first():
    log = UserLogging(event = 'disconnect', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'config-view').first():
    log = UserLogging(event = 'config-view', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'config-update').first():
    log = UserLogging(event = 'config-update', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'presence-update').first():
    log = UserLogging(event = 'presence-update', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'scene-update').first():
    log = UserLogging(event = 'scene-update', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'user-update').first():
    log = UserLogging(event = 'user-update', log_event = True)
    db.session.add(log)
    db.session.commit()
if not UserLogging.query.filter(UserLogging.event == 'log-delete').first():
    log = UserLogging(event = 'log-delete', log_event = True)
    db.session.add(log)
    db.session.commit()
 
# Create first user if it doesn't already exist.  Notice it doesn't have to be a valid email.  It basically serves as our username.
if not User.query.filter(User.email == 'jeff@example.com').first():
    user = User(
        active=True,
        email='jeff@example.com',
        password=generate_password_hash('Password', method='sha256'), # We don't store the actual password, just the hash.
        name='Jeff',
        role='Admin'
    )
    db.session.add(user)
    db.session.commit()
    
@login_manager.user_loader # This is the login manager user loader.  Used to load current_user.
def load_user(user_id):
    # since the user_id is the primary key of our user table, use it in the query for the user
    user = User.query.get(int(user_id))
    if user and user.active and len(user.password) > 0: # Only return the user if they are active
        return user
    return None

user_sessions = []
 
@socketio.on('connect')
def socket_connect():
    # Make sure the current_user is still authenticated.
    if current_user.is_authenticated:
        data = json.dumps({'status': 'connected'}) ###
        emit('conn', data, broadcast=False) ###
    else: ###
        print('Current user no longer authenticated!') ###
        emit('location_data', '', broadcast=False) ### # Send an empty event to notify browser user is no longer authorized
         
# This let's a disconnected socket attempt to reset session context when the connection is reestablished.
@socketio.on('set-session')
def socket_set_session(msg):
    print(f'set-session: {msg}')
    # Make sure the current_user is still authenticated.
    if current_user.is_authenticated:
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr

        session_info = msg.get('sessions', [])
        if current_user.role == 'Admin':
            user_locations = [location.location_id for location in stc.locations]
        elif current_user.role == 'Guest':
            user_locations = stc.getLocationsByNetwork(ip)
            if len(user_locations) > 0 and len(session_info) == 0:
                session_info.append(user_locations[0])
        else:
            user_locations = [location.location_id for location in current_user.locations]
        if len(session_info) == 0:
            for loc in current_user.locations:
                if len(session_info) == 0:
                    session_info.append(loc.location_id)
                if loc.current:
                    session_info[0] = loc.location_id
        if len(session_info) == 0:
            if current_user.role == 'Admin':
                session_info.append(stc.locations[0].location_id)

        #print(f'session_info: {session_info}')
        current_sessions = []
        for info in session_info:
            if info in user_locations:
                current_sessions.append(info)
                join_room(info)
        if len(current_sessions) > 0:
            idx = getUserSessionIndex(session)
            if idx == -1:
                user_sessions.append({'user_id': session['_user_id'], 'session_id': session['_id'], 'ip': ip,
                    'date': datetime.now().strftime('%m/%d/%y %H:%M:%S'), 'rooms': current_sessions})
            else:
                user_sessions[idx]['rooms'] = current_sessions
                user_sessions[idx]['ip'] = ip
            location_data = json.dumps(stc.getLocationData(current_sessions))
            print(f'User: {current_user.id} Joining Rooms: {current_sessions}')
            emit('location_data', location_data, broadcast=False) #We only need to send this to the user currently connecting, not all.

            if UserLogging.query.filter(UserLogging.event == 'connect').filter(UserLogging.log_event == True).first():
                current_user.logins.append(UserLogin(event='connect', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
                db.session.commit()
        else:
            print('Current user not associated with requested locations!')
            emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
    else:
        print('Current user no longer authenticated!')
        emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
         
@socketio.on('disconnect')
def socket_disconnect():
    print(f'Disconnecting user: {session["_user_id"]}')
    if current_user.is_authenticated:
        idx = getUserSessionIndex(session)
        if idx >= 0:
            user_sessions.pop(idx)
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        if UserLogging.query.filter(UserLogging.event == 'disconnect').filter(UserLogging.log_event == True).first():
            current_user.logins.append(UserLogin(event='disconnect', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
            db.session.commit()
 
@socketio.on('location-change')
def socket_location_change(msg):
    print(f'location-change: {msg}')
    location_data = ''
    location_list = []
    current_locations = []
    if current_user.is_authenticated:
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        if current_user.role != 'Admin':
            if msg['location_id'] == 'combined':
                locationList = [location.location_id for location in current_user.locations]
                idx = getUserSessionIndex(session)
                if idx >= 0:
                    current_locations = user_sessions[idx]['rooms']
                for location_id in locationList:
                    if not location_id in current_locations:
                        join_room(location_id)
                user_sessions[idx]['rooms'] = locationList
                user_sessions[idx]['ip'] = ip
                location_data = json.dumps(stc.getLocationData(locationList))
            else:
                if current_user.role == 'Guest':
                    user_locations = stc.getLocationsByNetwork(ip)
                    if not msg['location_id'] in user_locations:
                        location_data = json.dumps({'error': 'You are not connected to the local network for this location!'})
                else:
                    user_locations = [location.location_id for location in current_user.locations]
                if msg['location_id'] in user_locations:
                    for location in current_user.locations:
                        if location.location_id == msg['location_id']:
                            idx = getUserSessionIndex(session)
                            if idx >= 0:
                                for room in user_sessions[idx]['rooms']:
                                    leave_room(room)
                                join_room(location.location_id)
                                user_sessions[idx]['rooms'] = [location.location_id]
                                user_sessions[idx]['ip'] = ip
                                st = stc.getByLocation(location.location_id)
                                location_data = json.dumps(stc.getLocationData([st.location_id]))
                                location.current = True
                        else:
                            location.current = False    
                    db.session.commit()
        else:
            if msg['location_id'] == 'combined':
                locationList = [location.location_id for location in stc.locations]
                idx = getUserSessionIndex(session)
                if idx >= 0:
                    current_locations = user_sessions[idx]['rooms']
                for location_id in locationList:
                    if not location_id in current_locations:
                        join_room(location_id)
                user_sessions[idx]['rooms'] = locationList
                user_sessions[idx]['ip'] = ip 
                location_data = json.dumps(stc.getLocationData(locationList))
            else:
                st = stc.getByLocation(msg['location_id'])
                if st:
                    idx = getUserSessionIndex(session)
                    if idx >= 0:
                        for room in user_sessions[idx]['rooms']:
                            leave_room(room)
                        join_room(st.location_id)
                        user_sessions[idx]['rooms'] = [st.location_id]
                        user_sessions[idx]['ip'] = ip
                        location_data = json.dumps(stc.getLocationData([st.location_id]))
                        for location in current_user.locations:
                            if location.location_id == st.location_id:
                                location.current = True
                            else:
                                location.current = False
                            db.session.commit()
                else:
                    print('Invalid location: %s' % msg['location_id'])
            
    print('emitting data...')
    emit('location_data', location_data, broadcast=False)
 
@socketio.on('pingBack')
def socket_pingback():
    if current_user.is_authenticated:
        emit('pingRcv');
    else:
        print('Current user no longer authenticated!')
        emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
 
@socketio.on('disconn')
def socket_disconn():
    user = User.query.get(int(session['_user_id']))
    if user:
        print('Disconnecting unauthorized user! [user: %s]' % user.email)
    else:
        print('Disconnect unkown user!')
    idx = getUserSessionIndex(session)
    if idx >= 0:
        user_sessions.pop(idx)
    if user: # Record the web socket disconnect.  Remove if desired.
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        if UserLogging.query.filter(UserLogging.event == 'disconnect').filter(UserLogging.log_event == True).first():
            user.logins.append(UserLogin(event='disconnect', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
            db.session.commit()
    disconnect()
 
@socketio.on('refresh')
def socket_refresh():
    print('refresh')
    # Make sure the current_user is still authenticated.
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            refresh_locations = [location.location_id for location in stc.locations]
        else:
            refresh_locations = [location.location_id for location in current_user.locations]
        for room in refresh_locations:
            print(f'refreshing" {room}')
            stc.getByLocation(room).readData(refresh=False)
            location_data = json.dumps(stc.getLocationData([room]))
            emit('location_data', location_data, to=room) #Broadcast any changes to all users.
    else:
        print('Current user no longer authenticated! [user_id: %s]' % session['_user_id'])
        emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
 
@socketio.on('update-device')
def socket_update_device(msg):
    print('update-device: %s' % msg)
    # Make sure the current_user is still authenticated.
    if current_user.is_authenticated:
        idx = getUserSessionIndex(session)
        st = None;
        if idx >= 0:
            st = stc.getByLocation(msg['locationId'])
        if st:
            st.changeDevice(msg['deviceId'], msg['capability'], msg['state'], current_user)
        else:
            print('st object not defined!')
    else:
        print('Current user no longer authenticated! [user_id: %s]' % session['_user_id'])
        emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
 
@socketio.on('update-thermostat')
def socket_update_thermostat(msg):
    print('update-thermostat: %s' % msg)
    # Make sure the current_user is still authenticated.
    if current_user.is_authenticated:
        idx = getUserSessionIndex(session)
        st = None;
        if idx >= 0:
            st = stc.getByLocation(msg['locationId'])
        if st:
            st.changeThermostat(msg, current_user)
        else:
            print('st object not defined!')
    else:
        print('Current user no longer authenticated! [user_id: %s]' % session['_user_id'])
        emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
 
@socketio.on('run-scene')
def socket_run_scene(msg):
    print('run-scene: %s' % msg)
    if current_user.is_authenticated:
        idx = getUserSessionIndex(session)
        if idx >= 0:
            st = stc.getByLocation(msg['location_id'])
        if st:
            if not st.runScene(msg['scene_id'], current_user):
                print('Failed running scene!')
        else:
            print('st object not defined!')
    else:
        print('Current user no longer authenticated! [user_id: %s]' % session['_user_id'])
        emit('location_data', '', broadcast=False)  # Send an empty event to notify browser user is no longer authorized
 
# This is the login route.  If a users tries to go directly to any URL that requires a login (has the @login_required decorator)
#   before being authenticated, they will be redirected to this URL.  This is defined in the login_manager.login_view setting above.
@app.route('/login', methods=['GET'])
def login():
    if current_user.is_authenticated: # No need to have a logged in user login again.
        return redirect(url_for('index'))
    # The 'next' query parameter will be set automatically by the login_manager
    #   if the user tried to go directly to @login_required URL before authenticating.
    next_page = request.args.get('next')
    #print('next: %s' % next_page)
    if not next_page or url_parse(next_page).netloc != '':  # If there is no next query parameter, default to index.
        next_page = url_for('index')
    return render_template('login.html', next_page=next_page)
 
@app.route('/login', methods=['POST']) # The browser user click the Login button...
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
 
    user = User.query.filter_by(email=email).filter_by(active=True).first() # Let's see if this user exists...
 
    # Capture the IP address so we can check Guest users and log it...
    if request.headers.getlist('X-Forwarded-For'):
        ip = request.headers.getlist('X-Forwarded-For')[0]
    else:
        ip = request.remote_addr
    #print(f'******\nIP: {ip}\n{request.headers}\n*********')
 
    if user and user.role == 'Guest': # If this is a Guest user, make sure they are logging in from the local network only...
        if isGuestIP(user, ip): # Check to make sure current IP is in this location's IP list:
            print(f'Guest User [{user.name}] is connected to local network.  Allowed...')
        else:
            print(f'Guest User [{user.name}] is NOT connected to local network.  Aborting...')
            flash(f'Guest Users Must Be Connected to Local Network')
            return redirect(url_for('login')) # If not, send them back to the Login page.
 
    # If the user exists in the db, but the password is empty, then take the entered password, hash it, and update the db.
    #   This is how I add a new user to the db without setting the password for them.
    if user and user.password == '':
        print('Setup user!')
        user.password=generate_password_hash(password, method='sha256')
        db.session.commit()
 
    # Check if the user actually exists and is active
    # Take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not user.active or not check_password_hash(user.password, password) or (user.role != 'Admin' and not len(user.locations) > 0):
        # Maybe the user just doesn't have a location assigned yet.
        if user and user.role != 'Admin' and len(user.locations) == 0:
            flash("You must be associated with a location to login!")
        else:
            # If there's a problem, create a FailedLogin event.
            failed_user = FailedLogin(email=email, password=password, date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip)
            db.session.add(failed_user)
            db.session.commit()
            flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page
 
    try: # This just captures the last login for the user in case we decide to use it later.
         # We wrap it in a try in case there was no previous login.
        userLogin = UserLogin.query.filter_by(user_id=user.id).filter_by(event='login').order_by(UserLogin.date.desc()).first()
        print("Last Login: %s" % userLogin.date)
    except:
        pass
 
    # If the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    session.permanent = True # This is the flask session.  It's set to permanent, but the PERMANENT_SESSION_LIFETIME is applied for expiration.
 
    # Record the login event.  Remove if desired.
    if UserLogging.query.filter(UserLogging.event == 'login').filter(UserLogging.log_event == True).first():
        user.logins.append(UserLogin(event='login', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
 
    # This is the next query parameter that we passed through from the login GET request.
    #  If it was set, we want to now redirect the user to the URL they originally tried to go to.
    next_page = request.args.get('next')
    #print('next: %s' % next_page)
    if not next_page or url_parse(next_page).netloc != '':
        next_page = url_for('index')
    return redirect(next_page)
 
@app.route('/logout')
def logout():
    if current_user.is_authenticated:  # If the user is logged in, record the event and log them out.
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        if UserLogging.query.filter(UserLogging.event == 'logout').filter(UserLogging.log_event == True).first():
            current_user.logins.append(UserLogin(event='logout', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
            db.session.commit()
        logout_user()
    return redirect(url_for('login')) # Logged in or not, redirect to the login page.
 
# Admin Home Page
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    if UserLogging.query.filter(UserLogging.event == 'config-view').filter(UserLogging.log_event == True).first():
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        current_user.logins.append(UserLogin(event='config-view', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
    #print(f'admin session: {session}')
    
    locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_home.html', locationData=locationData, allLocationData=allLocationData)
 
def getSessionLocationData(sessionData):
    location_id = getSessionLocationId(sessionData)
    location_name = 'Unknown'
    if location_id:
        location_name = stc.getByLocation(location_id).display_name
    locationData = {'location_id': location_id, 'name': location_name}
    return locationData
    
def getSessionLocationId(sessionData):
    loc = getUserSessionIndex(sessionData)
    location_id = ''
    if loc >= 0:
        location_id = user_sessions[loc]['rooms'][0]
    else:
        #print(f'getting by session user_id: {sessionData["_user_id"]}')
        user = User.query.get(sessionData['_user_id'])
        if user and user.active:
            for location in user.locations:
                location_id = location.location_id
                if location.current:
                    break
    return location_id
    
def getUserSessionIndex(sessionData):
    session_id = sessionData['_id']
    loc = [i for i, item in enumerate(user_sessions) if item['session_id'] == session_id]
    if len(loc) > 0:
        return loc[0]
    return -1

# Admin Switch Location
@app.route('/admin-switch-location', methods=['POST'])
@login_required
def admin_switch_location():
    print('admin-switch-location')
    if current_user.role != 'Admin':
        return 'Fail', 403
    locationData = request.get_json()
    print(f'locationData: {locationData}')
    loc_idx = getUserSessionIndex(session)
    if loc_idx >= 0:
        user_sessions[loc_idx]['rooms'] = [locationData['location_id']]
    else:
        for location in current_user.locations:
            if location.location_id == locationData['location_id']:
                location.current = True
            else:
                location.current = False
        db.session.commit()
    return 'OK', 200

# Admin View User Sessions
@app.route('/admin-view-sessions')
@login_required
def admin_view_sessions():
    #print(user_sessions)
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    locationData = getSessionLocationData(session)
    userSessionData = {'sessions': []}
    for user_session in user_sessions:
        email = User.query.get(user_session['user_id']).email
        rooms = ''
        for room in user_session['rooms']:
            rooms += f'[{stc.getByLocation(room).display_name}] '
        userSessionData['sessions'].append({'user_id': user_session['user_id'], 'email': email, 'ip': user_session['ip'], 'room': rooms,
            'date': user_session['date']})
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_sessions.html', sessionData=userSessionData, locationData=locationData, allLocationData=allLocationData)

# Admin View User Logs
@app.route('/admin-view-logs')
@login_required
def admin_view_logs():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    results = UserLogin.query.all()
    logData = {'logs': []}
    for log in results:
        email = User.query.get(log.user_id).email
        logData['logs'].append({'id': log.id, 'user_id': log.user_id, 'email': email, 'event': log.event, 'date': log.date, 'ip': log.ip})
    locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_logs.html', logData=logData, locationData=locationData, allLocationData=allLocationData)
 
# Admin Delete User Logs
@app.route('/delete-user-logs', methods=['POST'])
@login_required
def admin_delete_logs():
    print('delete-user-logs')
    if current_user.role != 'Admin':
        return 'Fail', 403
    logData = request.get_json()
    #print('logData: %s' % logData)
    for log in logData['logs']:
        logRecord = UserLogin.query.get(log['id'])
        if logRecord:
            db.session.delete(logRecord)
            db.session.commit()
    if UserLogging.query.filter(UserLogging.event == 'log-delete').filter(UserLogging.log_event == True).first():
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        current_user.logins.append(UserLogin(event='log-delete', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
    return 'OK', 200
 
# Admin Failed Logins
@app.route('/admin-failed-logins')
@login_required
def admin_failed_logins():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    results = FailedLogin.query.all()
    logData = {'data': []}
    logData['data'] = [{'id': data.id, 'email': data.email, 'password': data.password, 'date': data.date, 'ip': data.ip} for data in results]
#    for data in results:
#        logData['data'].append({'id': data.id, 'email': data.email, 'password': data.password, 'date': data.date, 'ip': data.ip})
    locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_failed_login.html', logData=logData, locationData=locationData, allLocationData=allLocationData)
 
# Admin Delete Failed Login
@app.route('/delete-failed-login', methods=['POST'])
@login_required
def admin_delete_failed_login():
    print('delete-failed-login')
    if current_user.role != 'Admin':
        return 'Fail', 403
    logData = request.get_json()
    #print('logData: %s' % logData)
    for log in logData['logs']:
        logRecord = FailedLogin.query.get(log['id'])
        if logRecord:
            db.session.delete(logRecord)
            db.session.commit()
    if UserLogging.query.filter(UserLogging.event == 'log-delete').filter(UserLogging.log_event == True).first():
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        current_user.logins.append(UserLogin(event='log-delete', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
    return 'OK', 200
 
# Admin Configure Logging
@app.route('/admin-logging')
@login_required
def admin_logging():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    results = UserLogging.query.all()
    logData = {'logs': []}
    logData['logs'] = [{'id': log.id, 'event': log.event, 'log_event': '1' if log.log_event else '0'} for log in results]
#    for log in results:
#        logData['logs'].append({'id': log.id, 'event': log.event, 'log_event': '1' if log.log_event else '0'})
    locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_logging.html', logData=logData, locationData=locationData, allLocationData=allLocationData)
 
# Admin Updating Logging
@app.route('/update-logging', methods=['POST'])
@login_required
def update_logging():
    if current_user.role != 'Admin':
        return 'Fail', 403
    print('update-logging')
    logData = request.get_json()
    #print(logData)
    for log in logData['logs']:
        logRecord = UserLogging.query.get(int(log['id']))
        if logRecord:
            logRecord.log_event = True if log['log_event'] == '1' else False
            db.session.commit()
    if UserLogging.query.filter(UserLogging.event == 'config-update').filter(UserLogging.log_event == True).first():
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        current_user.logins.append(UserLogin(event='config-update', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
    return 'OK', 200
 
# Admin Maintain Users
@app.route('/admin-users')
@login_required
def admin_users():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    results = User.query.all()
    userData = {"users": []}
    for user in results:
        userLocations = [{"location_id": location.location_id, "name": location.getName()} for location in user.locations]
        userData['users'].append({"id": user.id, "name": user.name, "email": user.email, "role": user.role, 
        "active": 1 if user.active else 0, 'locations': userLocations})
    locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_users.html', userData=userData, locationData=locationData, allLocationData=allLocationData)
 
@app.route('/update-users', methods=['POST'])
@login_required
def update_users():
    if current_user.role != 'Admin':
        return 'Fail', 403
    print('update-users')
    userData = request.get_json()
    #print(userData)
    for user in userData['users']:
        #print('updating user: %s' % user['id'])
        userRecord = User.query.get(int(user['id']))
        if userRecord:
            userRecord.name = user['name']
            userRecord.role = user['role']
            userRecord.active = True if user['active'] == '1' else False
            if user['reset'] == '1':
                userRecord.password = ''
            userLocations = user.get('locations', None);
            if userLocations != None:
                for loc in userRecord.locations:
                    db.session.delete(loc)
                for loc in user['locations']:
                    userLoc = UserLocations(user_id=userRecord.id, location_id=loc)
                    db.session.add(userLoc)
            else:
                print('No userLocations found!')
            db.session.commit()
    if UserLogging.query.filter(UserLogging.event == 'user-update').filter(UserLogging.log_event == True).first():
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        current_user.logins.append(UserLogin(event='user-update', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
    return 'OK', 200
 
@app.route('/new-user', methods=['POST'])
@login_required
def new_user():
    if current_user.role != 'Admin':
        return 'Fail', 403
    print('new-user')
    userData = request.get_json()
    #print(userData)
    if not User.query.filter(User.email == userData['email']).first():
        user = User(
            active=True if userData['active'] == '1' else False,
            email=userData['email'],
            password='',
            name=userData['name'],
            role=userData['role']
        )
        db.session.add(user)
        db.session.commit()
    if UserLogging.query.filter(UserLogging.event == 'user-update').filter(UserLogging.log_event == True).first():
        if request.headers.getlist('X-Forwarded-For'):
            ip = request.headers.getlist('X-Forwarded-For')[0]
        else:
            ip = request.remote_addr
        current_user.logins.append(UserLogin(event='user-update', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
        db.session.commit()
    return 'OK', 200
 
# Admin Presence Sensor Config
@app.route('/config-presence')
@login_required
def config_presence():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    loc_id = getSessionLocationId(session)
    if loc_id:
        st = stc.getByLocation(loc_id)
        configData = st.getPresence()
        locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_presence.html', configData=configData, locationData=locationData, allLocationData=allLocationData)
 
@app.route('/update-presence-configs', methods=['POST'])
@login_required
def update_presence_configs():
    if current_user.role == 'Admin':
        print('update-presence-configs')
        configData = request.get_json()
        #print(configData)
        loc_id = configData.get('location_id', '')
        if loc_id:
            st = stc.getByLocation(loc_id)
            if st.updatePresenceConfigs(configData):
                st.readData(refresh=False)
                location_data = json.dumps(stc.getLocationData([st.location_id]))
                socketio.emit('location_data', location_data, to=st.location_id) #Broadcase any changes to all users.
                if UserLogging.query.filter(UserLogging.event == 'presence-update').filter(UserLogging.log_event == True).first():
                    if request.headers.getlist('X-Forwarded-For'):
                        ip = request.headers.getlist('X-Forwarded-For')[0]
                    else:
                        ip = request.remote_addr
                    current_user.logins.append(UserLogin(event='presence-update', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
                    db.session.commit()
                return 'OK', 200
        return 'Fail', 200
    return 'Fail', 403
 
# Admin Scenes Config
@app.route('/config-scenes')
@login_required
def config_scenes():
    if current_user.role != 'Admin':
        return redirect(url_for('index'))
    loc_id = getSessionLocationId(session)
    if loc_id:
        st = stc.getByLocation(loc_id)
        configData = st.getScenes()
    locationData = getSessionLocationData(session)
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}
    return render_template('admin_scenes.html', configData=configData, locationData=locationData, allLocationData=allLocationData)
 
@app.route('/update-scene-configs', methods=['POST'])
@login_required
def update_scene_configs():
    if current_user.role == 'Admin':
        print('update-scene-configs')
        configData = request.get_json()
        #print(configData)
        loc_id = configData.get('location_id', '')
        if loc_id:
            st = stc.getByLocation(loc_id)
            if st.updateSceneConfigs(configData):
                st.readData(refresh=False)
                location_data = json.dumps(stc.getLocationData([st.location_id]))
                print(f'Emitting data: {location_data}')
                socketio.emit('location_data', location_data, to=st.location_id) #Broadcast any changes to all users.
                if UserLogging.query.filter(UserLogging.event == 'scene-update').filter(UserLogging.log_event == True).first():
                    if request.headers.getlist('X-Forwarded-For'):
                        ip = request.headers.getlist('X-Forwarded-For')[0]
                    else:
                        ip = request.remote_addr
                    current_user.logins.append(UserLogin(event='scene-update', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
                    db.session.commit()
                return 'OK', 200
        return 'Fail', 200
    return 'Fail', 403
 
# To access this page, the user must be logged in and also have an Admin role.
@app.route('/config-rooms')
@login_required
def config_rooms():
    if current_user.role == 'Admin':
        loc_id = getSessionLocationId(session)
        if loc_id:
            st = stc.getByLocation(loc_id)
            configData = st.getConfig()
        locationData = getSessionLocationData(session)
        allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
        allLocationData = {'locations': allLocations}
        return render_template('admin_rooms.html', configData=configData, locationData=locationData, allLocationData=allLocationData)
    # If the user isn't an Admin, log them out, flash them a message, and send back to the login page.
    logout_user()
    flash("You must be an Administrator to access this page!")
    return redirect(url_for('login'))
 
# Obviously, we want to make sure the user is logged in here and is an admin.
@app.route('/update-room-configs', methods=['POST'])
@login_required
def update_room_configs():
    if current_user.role == 'Admin':
        print('update-room-configs')
        configData = request.get_json()
        #print(configData)
        loc_id = configData.get('location_id', '')
        if loc_id:
            st = stc.getByLocation(configData['location_id'])
            if st.updateConfigs(configData):
                st.readData(refresh=False)
                location_data = json.dumps(stc.getLocationData([st.location_id]))
                socketio.emit('location_data', location_data, to=st.location_id) #Broadcast any changes to all users.
                if UserLogging.query.filter(UserLogging.event == 'config-update').filter(UserLogging.log_event == True).first():
                    if request.headers.getlist('X-Forwarded-For'):
                        ip = request.headers.getlist('X-Forwarded-For')[0]
                    else:
                        ip = request.remote_addr
                    current_user.logins.append(UserLogin(event='config-update', date=datetime.now().strftime('%m/%d/%y %H:%M:%S'), ip=ip))
                    db.session.commit()
                return 'OK', 200
        return 'Fail', 200
    return 'Fail', 403
 
# Admin Refresh Scenes
@app.route('/admin-refresh-scenes', methods=['POST'])
@login_required
def admin_refresh_scenes():
    loc = request.get_json();
    loc_id = loc.get('location_id', '')
    print(f'admin-refresh-scenes: loc={loc_id}')
    if current_user.role != 'Admin':
        return 'Fail', 403
    if loc_id:
        st = stc.getByLocation(loc_id)
        if st.loadAllScenes():
            if st.readAllScenes():
                location_data = json.dumps(stc.getLocationData([st.location_id]))
                socketio.emit('location_data', location_data, to=st.location_id) #Broadcast any changes to all users.            
                return 'OK', 200
    return 'Fail', 200
 
# Admin Refresh All Devices Status
@app.route('/admin-refresh-device-status', methods=['POST'])
@login_required
def admin_refresh_device_status():
    loc = request.get_json()
    loc_id = loc.get('location_id', '')
    print(f'admin-refresh-device-status: loc={loc_id}')
    if current_user.role != 'Admin':
        return 'Fail', 403
    if loc_id:
        st = stc.getByLocation(loc_id)
        if st.loadAllDevicesStatus():
            location_data = json.dumps(stc.getLocationData([st.location_id]))
            socketio.emit('location_data', location_data, to=st.location_id) #Broadcast any changes to all users.            
            return 'OK', 200
    return 'Fail', 200
 
# Admin Refresh All Devices Health
@app.route('/admin-refresh-device-health', methods=['POST'])
@login_required
def admin_refresh_device_health():
    loc = request.get_json()
    loc_id = loc.get('location_id', '')
    print(f'admin-refresh-device-health: loc={loc_id}')
    if current_user.role != 'Admin':
        return 'Fail', 403
    if loc_id:
        st = stc.getByLocation(loc_id)
        if st.loadAllDevicesHealth():
            location_data = json.dumps(stc.getLocationData([st.location_id]))
            socketio.emit('location_data', location_data, to=st.location_id) #Broadcast any changes to all users.            
            return 'OK', 200
    return 'Fail', 200
 
# Admin Refresh Foundation Data (App, Location, Rooms, Devices)
@app.route('/admin-refresh-foundation', methods=['POST'])
@login_required
def admin_refresh_foundation():
    loc = request.get_json();
    loc_id = loc.get('location_id', '')
    print(f'admin-refresh-foundation: loc={loc_id}')
    if current_user.role != 'Admin':
        return 'Fail', 403
    if loc_id:
        st = stc.getByLocation(loc_id)
        if st.loadData():
            if st.readData(refresh=False):
                location_data = json.dumps(stc.getLocationData([st.location_id]))
                socketio.emit('location_data', location_data, to=st.location_id) #Broadcast any changes to all users.            
                return 'OK', 200       
    return 'Fail', 200
 
# Only logged in users can see the dashboard.
@app.route('/', methods=['GET'])
@login_required
def index():
    allLocations = [{'location_id': location.location_id, 'name': location.display_name} for location in stc.locations]
    allLocationData = {'locations': allLocations}    
    return render_template('dashboard.html', allLocationData=allLocationData)
 
@app.route('/', methods=['POST'])
def smarthings_requests():
    content = request.get_json()
    print('AppId: %s\nLifeCycle: %s' % (content['appId'], content['lifecycle']))
 
    if (content['lifecycle'] == 'PING'):
        print('PING: %s' % content)
        challenge = content['pingData']['challenge']
        data = {'pingData':{'challenge': challenge}}
        return jsonify(data)
 
    elif (content['lifecycle'] == 'CONFIRMATION'):
        confirmationURL = content['confirmationData']['confirmationUrl']
        r = requests.get(confirmationURL)
        print('CONFIRMATION\nContent: %s\nURL: %s\nStatus: %s' % (content,confirmationURL,r.status_code))
        if r.status_code == 200:
            return r.text
        else:
            abort(r.status_code)
 
    elif (content['lifecycle'] == 'CONFIGURATION' and content['configurationData']['phase'] == 'INITIALIZE'):
        print(content['configurationData']['phase'])
 
        if content['appId'] == ST_WEBHOOK:
            data = {
                      "configurationData": {
                        "initialize": {
                          "name": "ST Test Webhook App",
                          "description": "ST Test Webhook App",
                          "id": "st_webhook_app_page_1",
                          "permissions": [
                            "r:devices:*"
                          ],
                          "firstPageId": "1"
                        }
                      }
                    }
        else:
            data = {'appId':'Not Recognized'}
            print('Initialize Unknown appId: %s' % content['appId'])
 
        return jsonify(data)
 
    elif (content['lifecycle'] == 'CONFIGURATION' and content['configurationData']['phase'] == 'PAGE'):
        print(content['configurationData']['phase'])
        pageId = content['configurationData']['pageId']
 
        if content['appId'] == ST_WEBHOOK:
            data = {
                      "configurationData": {
                        "page": {
                          "pageId": "1",
                          "name": "Select Devices",
                          "nextPageId": "null",
                          "previousPageId": "null",
                          "complete": "true",
                          "sections": [
                            {
                              "name": "Allow full access to all rooms and devices?",
                              "settings": [
                                {
                                  "id": "allowFullAccess",
                                  "name": "Allow?",
                                  "description": "Select Yes to allow app to function",
                                  "type": "ENUM",
                                  "required": "true",
                                  "multiple": "false",
                                  "options": [
                                     {
                                       "id": "yes",
                                       "name": "Yes"
                                     },
                                     {
                                       "id": "no",
                                       "name": "No"
                                     }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                      }
                    }
        else:
            data = {'appId':'Not Recognized'}
            print('Page Unknown appId: %s' % content['appId'])
 
        return jsonify(data)
 
    elif (content['lifecycle'] == 'INSTALL'):
        print(content['lifecycle'])
        data = {'installData':{}}
        resp = content['installData']
 
        if content['appId'] == ST_WEBHOOK:
            print('Installing ST Webhook')
            st = stc.getByLocation(resp['installedApp']['locationId'])
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'switch', 'switch', 'capSwitchSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'lock', 'lock', 'capLockSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'temperatureMeasurement', 'temperature', 'capTempSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'relativeHumidityMeasurement', 'humidity', 'capHumiditySubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'doorControl', 'door', 'capDoorSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'contactSensor', 'contact', 'capContactSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'motionSensor', 'motion', 'capMotionSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'switchLevel', 'level', 'capSwitchLevelSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'battery', 'battery', 'capBatterySubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'presenceSensor', 'presence', 'capPresenceSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatOperatingState', 'thermostatOperatingState', 'capOperatingStateSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatMode', 'thermostatMode', 'capModeSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatCoolingSetpoint', 'coolingSetpoint', 'capCoolSetpointSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatHeatingSetpoint', 'heatingSetpoint', 'capHeatSetpointSubscription')
            st.deviceHealthSubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'])
        else:
            data = {'appId':'Not Recognized'}
            print('Install Unknown appId: %s' % content['appId'])
 
        return jsonify(data)
 
    elif (content['lifecycle'] == 'UPDATE'):
        print(content['lifecycle'])
        data = {'updateData':{}}
        resp = content['updateData']
        print('resp: %s' % resp)
 
        if content['appId'] == ST_WEBHOOK:
            print('Updating ST Webhook')
            st = stc.getByLocation(resp['installedApp']['locationId'])
            st.deleteSubscriptions(resp['authToken'], resp['installedApp']['installedAppId'])
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'switch', 'switch', 'capSwitchSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'lock', 'lock', 'capLockSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'temperatureMeasurement', 'temperature', 'capTempSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'relativeHumidityMeasurement', 'humidity', 'capHumiditySubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'doorControl', 'door', 'capDoorSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'contactSensor', 'contact', 'capContactSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'motionSensor', 'motion', 'capMotionSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'switchLevel', 'level', 'capSwitchLevelSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'battery', 'battery', 'capBatterySubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'presenceSensor', 'presence', 'capPresenceSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatOperatingState', 'thermostatOperatingState', 'capOperatingStateSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatMode', 'thermostatMode', 'capModeSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatCoolingSetpoint', 'coolingSetpoint', 'capCoolSetpointSubscription')
            st.capabilitySubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'], 'thermostatHeatingSetpoint', 'heatingSetpoint', 'capHeatSetpointSubscription')
            st.deviceHealthSubscriptions(resp['authToken'], resp['installedApp']['locationId'], resp['installedApp']['installedAppId'])
        else:
            data = {'appId':'Not Recognized'}
            print('Update Unknown appId: %s' % content['appId'])
 
        return jsonify(data)
 
    elif (content['lifecycle'] == 'OAUTH_CALLBACK'):
        print(content['lifecycle'])
        data = {'oAuthCallbackData':{}}
        return jsonify(data)
 
    elif (content['lifecycle'] == 'EVENT'):
        data = {'eventData':{}}
 
        event = content['eventData']['events'][0]
         
        if content['appId'] == ST_WEBHOOK:
            if event['eventType'] == 'DEVICE_EVENT':
                if not event.get('deviceEvent', None):
                    print('***********************************')
                    print(f'Event Error:\n{event}')
                    print('***********************************')
                st = stc.getByLocation(event['deviceEvent']['locationId'])
                device = event['deviceEvent']
                emit_val = st.updateDevice(device['deviceId'], device['capability'], device['attribute'], device['value'])
                if emit_val:
                    print('emit_val: ', emit_val)
                    print('Emitting: %s: %s to room: %s' % (emit_val[0], emit_val[1], device['locationId']))
                    socketio.emit(emit_val[0],emit_val[1], to=device['locationId'])
#room                    socketio.emit(emit_val[0],emit_val[1], room=device['locationId'])
            elif event['eventType'] == 'DEVICE_HEALTH_EVENT':
                if not event.get('deviceHealthEvent', None):
                    print('***********************************')
                    print(f'Health Event Error:\n{event}')
                    print('***********************************')
                data = event['deviceHealthEvent']
                st = stc.getByLocation(data['locationId'])
                if st.updateDeviceHealth(data['deviceId'], data['status']):
                    socketio.emit('location_data', json.dumps(stc.getLocationData([st.location_id])), to=data['locationId'])
#locations                    socketio.emit('location_data', json.dumps(st.location), to=data['locationId'])
#room                    socketio.emit('location_data', json.dumps(st.location), room=data['locationId'])
        else:
            data = {'appId':'Not Recognized'}
            print('Event Unknown appId: %s' % content['appId'])
 
        return jsonify(data)
 
    elif (content['lifecycle'] == 'UNINSTALL'):
        print(content['lifecycle'])
        data = {'uninstallData':{}}
        return jsonify(data)
 
    else:
        print('Unknown Lifecycle: %s' % content['lifecycle'])
        return '',404
 
@app.route('/apple-touch-icon-152x152.png')
@app.route('/apple-touch-icon-152x152-precomposed.png')
@app.route('/apple-touch-icon-120x120-precomposed.png')
@app.route('/apple-touch-icon-120x120.png')
@app.route('/apple-touch-icon-precomposed.png')
@app.route('/apple-touch-icon.png')
@app.route('/favicon.ico')
def favicon():
    print('favicon')
    return send_from_directory('./static', 'favicon.png')
 
if __name__ == '__main__':
    stc = SmartThingsController()
    stc.initialize(False)
    
    # Add all locations for Admin users if necessary
    admins = User.query.filter(User.role == 'Admin').all()
    for admin in admins:
        for location in stc.locations:
            if not UserLocations.query.filter(UserLocations.user_id == admin.id).filter(UserLocations.location_id == location.location_id).first():
                ul = UserLocations(user_id=admin.id, location_id=location.location_id)
                db.session.add(ul)
                db.session.commit()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 
#    socketio.run(app, debug=False, host='0.0.0.0', port=5000) #Change to debug=False before deployment.
