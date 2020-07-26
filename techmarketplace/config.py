from flask import Flask
from techmarketplace.redisession import RedisSessionInterface
from datetime import timedelta
import redis
import os


def create_app():
    app = Flask(__name__)
    app.session_interface = RedisSessionInterface()

    # general
    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16)
    # email
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'piethonlee123@gmail.com'
    app.config['MAIL_PASSWORD'] = 'ASPJPYTHON123'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600
    # sqlalchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format('dbmsuser','Henry123')  # get from key vault
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = True
    app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'
    # flask-session
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url('redis://:RZ9IoOQMPab4XGaLee7NUAW6vccBceAU@redis-12106.c56.east-us.azure.cloud.redislabs.com:12106/0')
    return app