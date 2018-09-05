
import os
from hashlib import md5
from datetime import datetime
import uuid
import sendgrid
from sendgrid.helpers.mail import *

from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

import pdb


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", default=None)
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", default=None)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI", default='sqlite:////tmp/test.db')

jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
sg = sendgrid.SendGridAPIClient(apikey=os.environ.get('SENDGRID_API_KEY', default=None))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    cypher_password = db.Column(db.String(32), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(30), nullable=False)
    glucose_controls = db.relationship('GlucoseControl', backref=db.backref('user', lazy='joined'), lazy='select')
    glucose_unit = db.Column(db.Integer, nullable=False)
    confirm_account_token = db.Column(db.String(36), unique=True, default=str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<User %r>' % self.username

class GlucoseControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    value = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return "<GlucoseControl id: {} value: {}{}>".format(self.id, self.value, self.unit)

@app.route('/')
def hello():
    return "Hello World!"

@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    first_name = request.json.get('first_name', None)
    last_name = request.json.get('last_name', None)
    email = request.json.get('email', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if not first_name:
        return jsonify({"msg": "Missing first_name parameter"}), 400
    if not last_name:
        return jsonify({"msg": "Missing last_name parameter"}), 400
    if not email:
        return jsonify({"msg": "Missing email parameter"}), 400
    if User.query.filter((User.email == email) | (User.username == username)).first():
        return jsonify({"msg": "Username or email already in use!"}), 400
    cypher_password = md5(password.encode("utf-8")).hexdigest()
    user = User(username=username, email=email, cypher_password=cypher_password, first_name=first_name, last_name=last_name, role='dm1', glucose_unit='mg/dl')
    db.session.add(user)
    db.session.commit()


    ### VALIDATION EMAIL
    from_email = Email(email = "confirm@mellitt.us", name = "Mellitt.us")
    to_email = Email(user.email)
    subject = "Confirmar cuenta de Mellitt.us"
    body = render_template('activation_email.html', user=user)
    content = Content("text/html", body)

    mail = Mail(from_email, subject, to_email, content)
    response = sg.client.mail.send.post(request_body=mail.get())

    return jsonify(status="Éxito, ahora valida tu cuenta!"), 200

@app.route('/verify', methods=['GET'])
def verify():
    token = request.args.get('token')
    if not token:
        return "Error, no token!"
    user = User.query.filter_by(confirm_account_token=token).first_or_404()
    user.confirm_account_token = None
    db.session.commit()
    return render_template('verification_success.html', user=user), 200

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    cypher_password = md5(password.encode("utf-8")).hexdigest()
    if not User.query.filter_by(username=username, cypher_password=cypher_password).first():
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


### DIABETES USERS METHODS

#Register a new glucose control to the user based on the JWT
@app.route('/glucose_control', methods=['POST'])
@jwt_required
def glucose_control():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role in ['dm1', 'dm2']:
        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400
        value = request.json.get('value', None)
        if not value:
            return jsonify({"msg": "Missing value parameter"}), 400
        user = User.query.filter_by(username=current_user).first()
        gc = GlucoseControl(user_id=user.id, value=value, unit=user.glucose_unit)
        db.session.add(gc)
        db.session.commit()
        return jsonify(logged_in_as=current_user, glucose_id=gc.id), 200
    return jsonify({"error": "No a diabetes user"}), 403

### DOCTORS USERS METHODS

@app.route('/<string:patient>/glucose_controls', methods=['GET'])
@jwt_required
def glucose_control_list(patient):
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role in ['doctor']:
        patient = User.query.filter_by(username=patient).first()
        gcs = GlucoseControl.query.filter_by(user_id=patient.id).all()
        return jsonify({"controls": str(gcs).split(',')}), 200



        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400
        value = request.json.get('value', None)
        if not value:
            return jsonify({"msg": "Missing value parameter"}), 400
        user = User.query.filter_by(username=current_user).first()
        gc = GlucoseControl(user_id=user.id, value=value, unit=user.glucose_unit)
        db.session.add(gc)
        db.session.commit()
        return jsonify(logged_in_as=current_user, glucose_id=gc.id), 200
    return jsonify({"error": "No a doctor user"}), 403

if __name__ == '__main__':
    app.run()
