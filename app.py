# app.py
import datetime
import decimal
import hashlib
import random
import string


import pickle
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer

nltk.download('stopwords')

filename = 'GaussianNB_nlp_model.sav'

cv = pickle.load(open('bow_pickle.pickle', 'rb'))

classifier = pickle.load(open(filename, 'rb'))

nltk.download('stopwords')


import boto3
import flask.json
from flask import Flask, request, jsonify
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from marshmallow import fields


class MyJSONEncoder(flask.json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            # Convert decimal instances to strings.
            return str(obj)
        return super(MyJSONEncoder, self).default(obj)


app = Flask(__name__)
# Init app
app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'PSQLALCHEMY_DATABASE_URI_REMOVED_FOR_SECURITY'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json_encoder = MyJSONEncoder
# Config app
db = SQLAlchemy(app)
ma = Marshmallow(app)

aws_access_key_id = 'AWS_ACCESS_KEY_REMOVED_FOR_SECURITY'
aws_secret_access_key = 'AWS_SECRET_KEY_REMOVED_FOR_SECURITY'
endpoint_arn = 'AWS_COMPREHEND_ENDPOINT_ARN_REMOVED_FOR_SECURITY'


# AWS translator

def translate(text):
    translator = boto3.client(service_name='translate', region_name='eu-central-1', use_ssl=True,
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)

    result = translator.translate_text(Text=text,
                                       SourceLanguageCode="auto", TargetLanguageCode="en")

    return {'translated_from' : result.get('SourceLanguageCode'), 'translated_request_description': result.get('TranslatedText') }


# Measure severity


def measure_severity(text):



    try:
        new_review = text
        new_review = re.sub('[^a-zA-Z]', ' ', new_review)
        new_review = new_review.lower()
        new_review = new_review.split()
        ps = PorterStemmer()
        all_stopwords = stopwords.words('english')
        all_stopwords.remove('not')
        new_review = [ps.stem(word) for word in new_review if not word in set(all_stopwords)]
        new_review = ' '.join(new_review)
        new_corpus = [new_review]
        new_X_test = cv.transform(new_corpus).toarray()
        new_y_pred = classifier.predict(new_X_test)

        response = {'severity': str(new_y_pred[0]), 'score': str(0.16)}


        # comprehend = boto3.client(service_name='comprehend', region_name='eu-central-1', use_ssl=True,
        #                          aws_access_key_id=aws_access_key_id,
        #                          aws_secret_access_key=aws_secret_access_key)
        #
        # result = comprehend.classify_document(Text=text,
        #                                      EndpointArn=endpoint_arn)
        #
        # score = "{:.2f}".format(result['Classes'][0]['Score'])
        #
        # response = {'severity': result['Classes'][0]['Name'], 'score' : str(score)}
    except:
        response = {'severity': None, 'score': None}

    return response


@app.route('/test')
def test():
    return jsonify({'result': True, 'message': measure_severity('I have headache')})


# Models
class UserType(db.Model):
    __tablename__ = 'user_type'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(250))
    user = db.relationship('User', backref='UserType', uselist=True)

    def __init__(self, title, description):
        self.title = title
        self.description = description


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250))
    password = db.Column(db.String(40))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    user_type_id = db.Column(db.Integer, db.ForeignKey('user_type.id'),
                             nullable=False)

    def __repr__(self):
        return '<User %s>' % self.id


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "email", "first_name", "last_name", "user_type_id", "password")
        model = User


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class Driver(db.Model):
    __tablename__ = 'driver'
    id = db.Column(db.Integer, primary_key=True)
    driver_license_number = db.Column(db.String(250))
    ambulance_license_plate = db.Column(db.String(250))
    driver_phone = db.Column(db.String(100))
    type_of_ambulance = db.Column(db.Integer)
    latitude = db.Column(db.Numeric(10, 8))
    longitude = db.Column(db.Numeric(11, 8))
    credit_card_number = db.Column(db.String(50))
    credit_card_cvv = db.Column(db.String(5))
    credit_card_type = db.Column(db.String(100))
    credit_card_holder_name = db.Column(db.String(250))
    credit_card_expiry = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.Boolean, default=False)


class DriverSchema(ma.Schema):
    class Meta:
        fields = (
            "driver_license_number", "ambulance_license_plate", "driver_phone", "type_of_ambulance", "latitude",
            "longitude", "credit_card_number", "credit_card_cvv", "credit_card_type", "credit_card_holder_name",
            "credit_card_expiry")
        model = Driver


driver_schema = DriverSchema()
drivers_schema = DriverSchema(many=True)


class Customer(db.Model):
    __tablename__ = 'customer'
    id = db.Column(db.Integer, primary_key=True)
    customer_phone = db.Column(db.String(100))
    street_address = db.Column(db.String(250))
    postal_code = db.Column(db.String(10))
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    age = db.Column(db.Integer)
    credit_card_number = db.Column(db.String(50))
    credit_card_cvv = db.Column(db.String(5))
    credit_card_type = db.Column(db.String(100))
    credit_card_holder_name = db.Column(db.String(250))
    credit_card_expiry = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False)


class CustomerSchema(ma.Schema):
    class Meta:
        fields = (
            "customer_phone", "street_address", "postal_code", "city", "country", "age", "credit_card_number",
            "credit_card_cvv", "credit_card_type", "credit_card_holder_name", "credit_card_expiry")
        model = Customer


customer_schema = CustomerSchema()
customers_schema = CustomerSchema(many=True)


class CustomerUserSchema(ma.Schema):
    class Meta:
        user = fields.Nested(UserSchema)
        customer = fields.Nested(CustomerSchema)


customer_user_schema = CustomerUserSchema()
customer_users_schema = CustomerUserSchema(many=True)


class Admin(db.Model):
    __tablename__ = 'admin'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False)


class AdminSchema(ma.Schema):
    class Meta:
        fields = ("id", "user_id")
        model = Driver


admin_schema = AdminSchema()
admins_schema = AdminSchema(many=True)


class AmbulanceRequest(db.Model):
    __tablename__ = 'ambulance_request'

    id = db.Column(db.Integer, primary_key=True)
    customer_user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                                 nullable=False)
    driver_user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                               nullable=True)

    request_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    latitude = db.Column(db.Numeric(10, 8))
    longitude = db.Column(db.Numeric(11, 8))

    accept_time = db.Column(db.DateTime, nullable=True)
    finish_time = db.Column(db.DateTime, nullable=True)
    request_description = db.Column(db.String(250))


class AmbulanceRequestSchema(ma.Schema):
    class Meta:
        fields = ("id", "customer_user_id", "driver_user_id", "request_time", "latitude", "longitude", "accept_time",
                  "finish_time", "request_description")
        model = AmbulanceRequest


ambulance_request_schema = AmbulanceRequestSchema()
ambulance_requests_schema = AmbulanceRequestSchema(many=True)


####### Custom Queries #######

class AmbulanceRequestQuery(object):
    @staticmethod
    def get_active_requests_by_user_id(user_id=None):
        all_ambulance_requests = AmbulanceRequest.query.filter((AmbulanceRequest.customer_user_id == user_id)
                                                               | (AmbulanceRequest.driver_user_id == user_id)
                                                               & (AmbulanceRequest.finish_time == None))
        return all_ambulance_requests

    @staticmethod
    def get_all_active_requests():
        all_ambulance_requests = AmbulanceRequest.query.filter(AmbulanceRequest.finish_time == None)
        return all_ambulance_requests

    @staticmethod
    def get_customer_active_request(user_id=None):
        all_active_requests = AmbulanceRequest.query.filter((AmbulanceRequest.customer_user_id == user_id)
                                                            & (AmbulanceRequest.finish_time == None))
        return all_active_requests


########## Routes ############

# @app.before_request
# def before_request_callback():
#     path = request.path
#
#     if 'secure' in path:


@app.route('/')
def index():
    return "<h1>Welcome to CSDP-Aidline !!</h1>"


@app.route('/login', methods=['POST'])
def login():
    pwd = hashlib.md5(request.json['password'].encode()).hexdigest()
    user = db.session.query(User).filter_by(email=request.json['email'], password=pwd).first()

    if user:
        access_token_string = ''.join(random.choice(string.ascii_lowercase) for x in range(16))

        return jsonify({'result': True, 'message': 'User logged in successfully', 'user_id': user.id,
                        'access_token': access_token_string, 'user_type_id': user.user_type_id})

    return jsonify({'result': False, 'message': 'Username or password are invalid'})


@app.route('/logout', methods=['GET'])
def logout():
    return jsonify({'result': True, 'message': 'Logout successful'})


def create_user(req):
    user_exists = db.session.query(User.id).filter_by(email=request.json['email']).first() is not None

    if user_exists:
        return False

    pwd = hashlib.md5(request.json['password'].encode()).hexdigest()

    user = User(
        email=request.json['email'],
        password=pwd,
        first_name=request.json['first_name'],
        last_name=request.json['last_name'],
        user_type_id=request.json['user_type_id']
    )

    db.session.add(user)
    db.session.commit()

    return user


@app.route('/create_customer', methods=['POST'])
def create_customer():
    user = create_user(request)

    if not user:
        return jsonify({'result': False, 'message': 'User with the same email already exists'})

    customer = Customer(
        customer_phone=request.json['customer_phone'],
        street_address=request.json['street_address'],
        postal_code=request.json['postal_code'],
        city=request.json['city'],
        country=request.json['country'],
        age=request.json['age'],
        credit_card_number=request.json['credit_card_number'],
        credit_card_cvv=request.json['credit_card_cvv'],
        credit_card_type=request.json['credit_card_type'],
        credit_card_holder_name=request.json['credit_card_holder_name'],
        credit_card_expiry=request.json['credit_card_expiry'],
        user_id=user.id
    )

    db.session.add(customer)
    db.session.commit()

    return jsonify({'result': True, 'message': 'Customer created successfully', 'user_id': user.id})


@app.route('/create_driver', methods=['POST'])
def create_driver():
    user = create_user(request)

    if not user:
        return jsonify({'result': False, 'message': 'User with the same email already exists'})

    driver = Driver(
        driver_license_number=request.json['driver_license_number'],
        ambulance_license_plate=request.json['ambulance_license_plate'],
        driver_phone=request.json['driver_phone'],
        type_of_ambulance=request.json['type_of_ambulance'],
        latitude=request.json['latitude'],
        longitude=request.json['longitude'],
        credit_card_number=request.json['credit_card_number'],
        credit_card_cvv=request.json['credit_card_cvv'],
        credit_card_type=request.json['credit_card_type'],
        credit_card_holder_name=request.json['credit_card_holder_name'],
        credit_card_expiry=request.json['credit_card_expiry'],
        user_id=user.id
    )

    db.session.add(driver)
    db.session.commit()

    return jsonify({'result': True, 'message': 'Driver created successfully', 'user_id': user.id})


@app.route('/create_admin', methods=['POST'])
def create_admin():
    user = create_user(request)

    if not user:
        return jsonify({'result': False, 'message': 'User with the same email already exists'})

    admin = Admin(
        user_id=user.id
    )

    db.session.add(admin)
    db.session.commit()

    return jsonify({'result': True, 'message': 'Admin created successfully', 'user_id': user.id})


@app.route('/update_ambulance_location', methods=['POST'])
def update_ambulance_location():
    driver = db.session.query(Driver).filter_by(user_id=request.json['driver_user_id']).first()

    if not driver:
        return jsonify({'result': False, 'message': 'User does not exist'})

    driver.latitude = request.json['latitude']
    driver.longitude = request.json['longitude']

    db.session.commit()

    driver_is_busy = False
    ambulance_request = AmbulanceRequestQuery.get_active_requests_by_user_id(driver.user_id)
    if ambulance_request.count() > 0 or driver.status:
        driver_is_busy = True

    return jsonify(
        {'result': True, 'message': 'Ambulance location updated successfully: ', 'driver_is_busy': driver_is_busy})


@app.route('/update_customer', methods=['POST'])
def update_customer():
    customer = db.session.query(Customer).filter_by(user_id=request.json['customer_user_id']).first()
    user = db.session.query(User).filter_by(id=request.json['customer_user_id']).first()

    if not customer:
        return jsonify({'result': False, 'message': 'Customer does not exist'})

    user.first_name = request.json['first_name'] if 'first_name' in request.json else user.first_name
    user.last_name = request.json['last_name'] if 'last_name' in request.json else user.last_name
    user.email = request.json['email'] if 'email' in request.json else user.email

    if request.json['password']:
        pwd = hashlib.md5(request.json['password'].encode()).hexdigest()
    else:
        pwd = user.password

    user.password = pwd

    db.session.commit()

    customer.street_address = request.json[
        'street_address'] if 'street_address' in request.json else customer.street_address
    customer.postal_code = request.json['postal_code'] if 'postal_code' in request.json else customer.postal_code
    customer.city = request.json['city'] if 'city' in request.json else customer.city
    customer.country = request.json['country'] if 'country' in request.json else customer.country
    customer.customer_phone = request.json[
        'customer_phone'] if 'customer_phone' in request.json else customer.customer_phone

    customer.credit_card_number = request.json[
        'credit_card_number'] if 'credit_card_number' in request.json else customer.credit_card_number
    customer.credit_card_cvv = request.json[
        'credit_card_cvv'] if 'credit_card_cvv' in request.json else customer.credit_card_cvv
    customer.credit_card_type = request.json[
        'credit_card_type'] if 'credit_card_type' in request.json else customer.credit_card_type
    customer.credit_card_holder_name = request.json[
        'credit_card_holder_name'] if 'credit_card_holder_name' in request.json else customer.credit_card_holder_name
    customer.credit_card_expiry = request.json[
        'credit_card_expiry'] if 'credit_card_expiry' in request.json else customer.credit_card_expiry

    db.session.commit()

    return jsonify({'result': True, 'message': 'Customer profile updated successfully.'})


@app.route('/update_driver', methods=['POST'])
def update_driver():
    driver = db.session.query(Driver).filter_by(user_id=request.json['driver_user_id']).first()
    user = db.session.query(User).filter_by(id=request.json['driver_user_id']).first()

    if not driver:
        return jsonify({'result': False, 'message': 'Driver does not exist'})

    user.first_name = request.json['first_name'] if 'first_name' in request.json else user.first_name
    user.last_name = request.json['last_name'] if 'last_name' in request.json else user.last_name
    user.email = request.json['email'] if 'email' in request.json else user.email

    if request.json['password']:
        pwd = hashlib.md5(request.json['password'].encode()).hexdigest()
    else:
        pwd = user.password

    user.password = pwd
    db.session.commit()

    driver.driver_license_number = request.json[
        'driver_license_number'] if 'driver_license_number' in request.json else driver.driver_license_number
    driver.ambulance_license_plate = request.json[
        'ambulance_license_plate'] if 'ambulance_license_plate' in request.json else driver.ambulance_license_plate
    driver.driver_phone = request.json['driver_phone'] if 'driver_phone' in request.json else driver.driver_phone
    driver.type_of_ambulance = request.json[
        'type_of_ambulance'] if 'type_of_ambulance' in request.json else driver.type_of_ambulance
    driver.latitude = request.json['latitude'] if 'latitude' in request.json else driver.latitude
    driver.longitude = request.json['longitude'] if 'longitude' in request.json else driver.longitude
    driver.credit_card_number = request.json[
        'credit_card_number'] if 'credit_card_number' in request.json else driver.credit_card_number
    driver.credit_card_cvv = request.json[
        'credit_card_cvv'] if 'credit_card_cvv' in request.json else driver.credit_card_cvv
    driver.credit_card_type = request.json[
        'credit_card_type'] if 'credit_card_type' in request.json else driver.credit_card_type
    driver.credit_card_holder_name = request.json[
        'credit_card_holder_name'] if 'credit_card_holder_name' in request.json else driver.credit_card_holder_name
    driver.credit_card_expiry = request.json[
        'credit_card_expiry'] if 'credit_card_expiry' in request.json else driver.credit_card_expiry

    db.session.commit()

    return jsonify({'result': True, 'message': 'Driver profile updated successfully.'})


@app.route('/update_admin', methods=['POST'])
def update_admin():
    user = db.session.query(User).filter_by(id=request.json['admin_user_id'], user_type_id=3).first()

    if not user:
        return jsonify({'result': False, 'message': 'Admin does not exist'})

    user.first_name = request.json['first_name'] if 'first_name' in request.json else user.first_name
    user.last_name = request.json['last_name'] if 'last_name' in request.json else user.last_name
    user.email = request.json['email'] if 'email' in request.json else user.email

    if request.json['password']:
        pwd = hashlib.md5(request.json['password'].encode()).hexdigest()
    else:
        pwd = user.password

    user.password = pwd

    db.session.commit()

    return jsonify({'result': True, 'message': 'Admin profile updated successfully'})


@app.route('/get_requests')
def get_requests():
    all_requests = AmbulanceRequest.query.all()
    return jsonify(ambulance_requests_schema.dump(all_requests))


@app.route('/get_not_accepted_requests')
def get_not_accepted_requests():
    all_ambulance_requests = db.session.query(AmbulanceRequest).filter_by(accept_time=None)

    result = []

    for request in all_ambulance_requests:
        ambulance = {'request': ambulance_request_schema.dump(request)}
        ambulance['translation'] = translate(request.request_description)
        ambulance['emergency_level'] = measure_severity(ambulance['translation']['translated_request_description'])
        customer_schema_object = None
        driver_schema_object = None
        if request.customer_user_id:
            user = User.query.get(request.customer_user_id)
            user_schema_object = user_schema.dump(user)
            customer = Customer.query.get(request.customer_user_id)
            customer_schema_object = customer_schema.dump(customer)
            ambulance['customer'] = {**customer_schema_object, **user_schema_object}
        else:
            ambulance['customer'] = None

        if request.driver_user_id:
            user = User.query.get(request.driver_user_id)
            user_schema_object = user_schema.dump(user)
            driver = Driver.query.get(request.driver_user_id)
            driver.latitude = str(driver.latitude)
            driver.longitude = str(driver.longitude)
            driver_schema_object = driver_schema.dump(driver)
            ambulance['driver'] = {**driver_schema_object, **user_schema_object}
        else:
            ambulance['driver'] = None

        result.append(ambulance)

    return jsonify({'result': True, 'data': result})

    return jsonify(ambulance_requests_schema.dump(all_requests))


@app.route('/request_ambulance', methods=['POST'])
def request_ambulance():
    user = User.query.get(request.json['customer_user_id'])
    if user is None:
        return jsonify({'result': False, 'message': 'User not found'})
    if user.user_type_id != 1:
        return jsonify({'result': False, 'message': 'This user is not Customer'})

    ambulance_request = AmbulanceRequestQuery.get_customer_active_request(request.json['customer_user_id'])

    if ambulance_request.count() > 0:
        return jsonify({'result': False, 'message': 'Customer already has active request'})

    ambulance_request = AmbulanceRequest(
        customer_user_id=request.json['customer_user_id'],
        latitude=request.json['latitude'],
        longitude=request.json['longitude'],
        request_description=request.json['emergency_description']
    )

    db.session.add(ambulance_request)
    db.session.commit()

    return jsonify({'result': True, 'message': 'Request created'})


@app.route('/accept_request', methods=['POST'])
def accept_request():
    ambulance_request = db.session.query(AmbulanceRequest).filter_by(id=request.json['ambulance_request_id'],
                                                                     accept_time=None).first()
    if not ambulance_request:
        return jsonify({'result': False, 'message': 'Request not found'})

    driver = db.session.query(Driver).filter_by(user_id=request.json['driver_user_id']).first()

    if not driver:
        return jsonify({'result': False, 'message': 'Driver not found'})

    ambulance_request.driver_user_id = request.json['driver_user_id']
    ambulance_request.accept_time = datetime.datetime.utcnow()
    db.session.add(ambulance_request)
    db.session.commit()

    user = db.session.query(User).filter_by(id=ambulance_request.customer_user_id).first()
    customer = db.session.query(Customer).filter_by(user_id=ambulance_request.customer_user_id).first()

    if not customer:
        return jsonify({'result': False, 'message': 'Customer not found'})

    return jsonify({'result': True, 'message': 'Request accepted', 'latitude': ambulance_request.latitude,
                    'longitude': ambulance_request.longitude, 'customer_phone_number': customer.customer_phone,
                    'first_name': user.first_name, 'last_name': user.last_name})


@app.route('/users')
def users():
    all_users = User.query.all()
    return jsonify(users_schema.dump(all_users))


@app.route("/users_by_user_type/<int:user_type_id>")
def users_by_user_type(user_type_id):
    all_users = db.session.query(User).filter_by(user_type_id=user_type_id)
    return jsonify(users_schema.dump(all_users))


def get_specific_user_by_type(user_id, user_type_id):
    specific_user = None
    if user_type_id == 1:
        specific_user = db.session.query(Customer).filter_by(user_id=user_id).first()
    elif user_type_id == 2:
        specific_user = db.session.query(Driver).filter_by(user_id=user_id).first()
    elif user_type_id == 3:
        specific_user = db.session.query(Driver).filter_by(user_id=user_id).first()

    return specific_user


def marshal_specific_user_by_type(specific_user, user_type_id):
    specific_user_dump = None
    if user_type_id == 1:
        specific_user_dump = customer_schema.dump(specific_user)
    elif user_type_id == 2:
        specific_user_dump = driver_schema.dump(specific_user)
    elif user_type_id == 3:
        specific_user_dump = admin_schema.dump(specific_user)

    return specific_user_dump


@app.route("/users/<user_id>")
def user_detail(user_id):
    user = User.query.get(user_id)

    if user:
        specific_user = get_specific_user_by_type(user.id, user.user_type_id)

        user_dump = user_schema.dump(user)
        specific_user_dump = marshal_specific_user_by_type(specific_user, user.user_type_id)

        return jsonify({'result': True, 'user': user_dump, 'detail': specific_user_dump})

    else:
        return jsonify({'result': False, 'message': 'User not found'})


@app.route("/users/<user_id>", methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)

    if user:
        specific_user = get_specific_user_by_type(user.id, user.user_type_id)
        if specific_user:
            print('specific user found: ' + str(specific_user.id))
            db.session.delete(specific_user)
            db.session.commit()
            db.session.flush()

        db.session.delete(user)
        db.session.commit()
        db.session.flush()
        return jsonify({'result': True, 'message': 'User deleted successfully'})

    return jsonify({'result': False, 'message': 'User not found'})


## New api 28.11.2020

@app.route("/cancel_request/<request_id>", methods=['GET'])
def cancel_request(request_id):
    ambulance_request = AmbulanceRequest.query.get(request_id)

    if ambulance_request:
        if ambulance_request.finish_time is not None:
            return jsonify({'result': False, 'message': 'Ambulance request has already finished'})

        ambulance_request.driver_user_id = None
        ambulance_request.accept_time = None
        # db.session.add(ambulance_request)
        db.session.commit()
        return jsonify({'result': True, 'message': 'Ambulance request cancelled'})

    return jsonify({'result': False, 'message': 'Ambulance request not found'})


@app.route("/finish_request/<request_id>", methods=['GET'])
def finish_request(request_id):
    ambulance_request = AmbulanceRequest.query.get(request_id)

    if ambulance_request:
        ambulance_request.finish_time = datetime.datetime.utcnow()
        # db.session.add(ambulance_request)
        db.session.commit()
        return jsonify({'result': True, 'message': 'Ambulance request finished'})

    return jsonify({'result': False, 'message': 'Ambulance request not found'})


@app.route("/delete_request/<request_id>", methods=['DELETE'])
def delete_request(request_id):
    ambulance_request = AmbulanceRequest.query.get(request_id)

    if ambulance_request:
        db.session.delete(ambulance_request)
        db.session.commit()
        return jsonify({'result': True, 'message': 'Ambulance request deleted successfully'})

    return jsonify({'result': False, 'message': 'Ambulance request not found'})


@app.route("/get_active_requests", methods=['GET'])
def get_active_requests():
    all_ambulance_requests = AmbulanceRequestQuery.get_all_active_requests()

    result = []

    for request in all_ambulance_requests:
        ambulance = {'request': ambulance_request_schema.dump(request)}
        ambulance['translation'] = translate(request.request_description)
        ambulance['emergency_level'] = measure_severity(ambulance['translation']['translated_request_description'])
        # ambulance['severity'] = measure_severity(request.request_description)
        customer_schema_object = None
        driver_schema_object = None
        if request.customer_user_id:
            user = User.query.get(request.customer_user_id)
            user_schema_object = user_schema.dump(user)
            customer = Customer.query.filter(Customer.user_id == request.customer_user_id)
            customer = db.session.query(Customer).filter_by(user_id=request.customer_user_id).first()

            customer_schema_object = customer_schema.dump(customer)
            ambulance['customer'] = {**customer_schema_object, **user_schema_object}
        else:
            ambulance['customer'] = None

        if request.driver_user_id:
            user = User.query.get(request.driver_user_id)
            user_schema_object = user_schema.dump(user)
            driver = db.session.query(Driver).filter_by(user_id=request.driver_user_id).first()
            if driver:
                driver.latitude = str(driver.latitude)
                driver.longitude = str(driver.longitude)
                driver_schema_object = driver_schema.dump(driver)
                ambulance['driver'] = {**driver_schema_object, **user_schema_object}
            else:
                ambulance['driver'] = None
        else:
            ambulance['driver'] = None

        result.append(ambulance)

    if len(result) > 0:
        return jsonify({'result': True, 'data': result})
    else:
        return jsonify({'result': False, 'data': None})


@app.route("/get_single_request_by_user/<user_id>", methods=['GET'])
def get_single_request_by_user(user_id):
    all_ambulance_requests = AmbulanceRequestQuery.get_active_requests_by_user_id(user_id)

    result = []

    for request in all_ambulance_requests:
        ambulance = {'request': ambulance_request_schema.dump(request)}
        ambulance['translation'] = translate(request.request_description)
        ambulance['emergency_level'] = measure_severity(ambulance['translation']['translated_request_description'])
        customer_schema_object = None
        driver_schema_object = None
        if request.customer_user_id:
            user = User.query.get(request.customer_user_id)
            user_schema_object = user_schema.dump(user)
            customer = Customer.query.filter(Customer.user_id == request.customer_user_id)
            customer = db.session.query(Customer).filter_by(user_id=request.customer_user_id).first()

            customer_schema_object = customer_schema.dump(customer)
            ambulance['customer'] = {**customer_schema_object, **user_schema_object}
        else:
            ambulance['customer'] = None

        if request.driver_user_id:
            user = User.query.get(request.driver_user_id)
            user_schema_object = user_schema.dump(user)
            driver = db.session.query(Driver).filter_by(user_id=request.driver_user_id).first()
            if driver:
                driver.latitude = str(driver.latitude)
                driver.longitude = str(driver.longitude)
                driver_schema_object = driver_schema.dump(driver)
                ambulance['driver'] = {**driver_schema_object, **user_schema_object}
            else:
                ambulance['driver'] = None
        else:
            ambulance['driver'] = None

        result.append(ambulance)

    if len(result) > 0:
        return jsonify({'result': True, 'data': result})
    else:
        return jsonify({'result': False, 'data': None})


@app.route("/set_driver_status/<user_id>", methods=['POST'])
def set_driver_status(user_id):
    driver = db.session.query(Driver).filter_by(user_id=user_id).first()
    if driver:
        driver.status = request.json['is_driver_busy']
        db.session.commit()
        return jsonify({'result': True, 'message': 'Driver status changed'})
    else:
        return jsonify({'result': False, 'message': 'Driver not found'})


if __name__ == '__main__':
    # Threaded option to enable multiple instances for multiple user access support
    app.run(threaded=True, port=5000, debug=True)
