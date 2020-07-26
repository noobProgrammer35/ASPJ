from hashlib import pbkdf2_hmac
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_mail import Message,Mail
from math import radians, cos, sin, asin, sqrt
import os
import requests
import re
import socket




def generate_salt(): # salt is IV in hashing, this function generates random 16 bits in hexadecimal
    salt =  os.urandom(16)
    return salt.hex()


def generate_hash(plaintext_password,password_salt):
    password_hash = pbkdf2_hmac(
        'sha256',
        b"%b"  % bytes(plaintext_password,'utf-8'),
        b"%b" % bytes(password_salt,'utf-8'),
        10000
    )
    return password_hash.hex()


def generate_token(email):
    # serialize and sign the data
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email,current_app.config['SECURITY_PASSWORD_SALT'])


def confirmation_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age = expiration
        )
    except:
        return False
    return email



def send_email(to,subject,template):
    mail = Mail(current_app)
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender = 'piethonlee123@gmail.com'
    )
    mail.send(msg)

def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371 # Radius of earth in kilometers. Use 3956 for miles
    return c * r

center_point = [{'lat':1.3796268,'lng':103.8474183}]
test_point = [{'lat':1.3364408,'lng':103.8449139}]
lat1 = center_point[0]['lat']
lon1 = center_point[0]['lng']
lat2 = test_point[0]['lat']
lon2 = test_point[0]['lng']

radius = 0.2

a = haversine(lon1, lat1, lon2, lat2)


print('Distance (km) : ', a)
if a <= radius:
    print('Inside the area')
else:
    print('Outside the area')


def get_location():
    res = requests.get('http://ipinfo.io/')
    data = res.json()
    print(res.text)
    return data['loc'].split(',')

def get_ipaddress():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg','gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def banned_characters(field):
    return re.match('^[/\'\"#<>%]',str(field))

