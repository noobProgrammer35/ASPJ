from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from hashlib import pbkdf2_hmac
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin,AdminIndexView,expose
from flask_login import LoginManager,current_user, UserMixin,login_user,AnonymousUserMixin
import os


# current_app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format('dbmsuser','Henry123') # get from key vault
# current_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# current_app.config['SQLALCHEMY_ECHO'] = True
# current_app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'

database = SQLAlchemy(current_app)
login = LoginManager(current_app)
login.login_view = '/login'
login.session_protection = None
login.refresh_view = '/login'
login.needs_refresh_message = (u"Session timedout, please re-login")
login.needs_refresh_message_category = "info"

@login.user_loader
def get_id(userid):
    return Customer.query.get(int(userid))


class Customer(database.Model, UserMixin):
    __tablename__ = 'users'
    userid = database.Column(database.Integer,primary_key=True)
    username = database.Column(database.String(50), unique=True)
    fname = database.Column(database.String(45))
    lname = database.Column(database.String(45))
    contact = database.Column(database.Integer())
    email = database.Column(database.String(45),unique=True)
    password_hash = database.Column(database.Text())
    password_salt = database.Column(database.Text())
    verified = database.Column(database.Boolean)
    account = database.relationship('Account',uselist=False,backref='account',lazy=True)

    def __init__(self,username,fname,lname,contact,password,verified,email):
        self.username = username
        self.fname = fname
        self.lname = lname
        self.contact = contact
        self.email = email
        self.verified = verified
        self.password_salt = self.generate_salt()
        self.password_hash = self.generate_hash(password,self.password_salt)

    def generate_hash(self,plaintext_password,salt):
        password_hash = pbkdf2_hmac(
            'sha256',
            b"%b" % bytes(plaintext_password, 'utf-8'),
            b"%b" % bytes(salt, 'utf-8'),
            10000
        )
        return password_hash.hex()

    def generate_salt(self):
        salt = os.urandom(16)
        return salt.hex()

    def get_id(self):
        return self.userid



class Account(database.Model):
    __tablename__ = 'account'
    accountid = database.Column(database.Integer,primary_key=True,unique=True)
    address = database.Column(database.String(55),nullable=False)
    credit_card = database.Column(database.LargeBinary,nullable=False)
    payment_method = database.Column(database.String(20))
    userid = database.Column(database.Integer,database.ForeignKey('users.userid'))

    def __init__(self,userid):
        self.address = ''
        self.payment_method = 'Credit Card'
        self.userid = userid




class Product(UserMixin,database.Model):
    __tablename__ = 'products'
    productid = database.Column(database.Integer,primary_key=True)
    Name = database.Column(database.String(45))
    Description = database.Column(database.String(100))
    stock = database.Column(database.Integer)
    price = database.Column(database.Float(2,6))
    Image = database.Column(database.String)
    Image2 = database.Column(database.String)
    model = database.Column(database.String,unique=True)

    def __init__(self,productName,productDescription,stock,price,imageFileName,Image2,model):
        self.Name = productName
        self.Description = productDescription
        self.stock = stock
        self.price = price
        self.Image =imageFileName
        self.Image2 = Image2
        self.model = model

    def get_id(self):
        return self.productid

    def __repr__(self):
        return "<Product %r>" % self.productid