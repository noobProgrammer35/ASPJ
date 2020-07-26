from flask_sqlalchemy import SQLAlchemy
from flask import current_app,render_template,Markup,request
from hashlib import pbkdf2_hmac
from flask_admin.contrib.sqla import ModelView
from flask_admin.form.upload import ImageUploadField
from flask_admin import Admin,AdminIndexView,expose,BaseView
from flask_login import LoginManager,current_user, UserMixin,login_user,AnonymousUserMixin
from flask import abort
from wtforms import FileField
import os
import base64
import pyotp



current_app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://dbmsuser:Henry123@localhost/mydb'
current_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
current_app.config['SQLALCHEMY_ECHO'] = True
current_app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'

database = SQLAlchemy(current_app)
login = LoginManager(current_app)
login.session_protection = None

@login.user_loader
def get_id(adminid):
    return Admin.query.get(int(adminid))


admin_role = database.Table('admin_role',database.Column('roleid',database.Integer,database.ForeignKey('roles.roleid'),primary_key=True),database.Column('adminid',database.Integer(),database.ForeignKey('admins.adminid'),primary_key=True))


class roles(database.Model):
    roleid = database.Column(database.Integer,primary_key=True)
    type = database.Column(database.String(30))

    def __init__(self,type):
        self.type = type

    def set_roleid(self,roleid):
        self.roleid = roleid

    def __repr__(self):
        return "<Role %r>" % self.roleid


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

class Customer(database.Model):
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


    def __init__(self,username,fname,lname,contact,email,password,verified):
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

    def generate_salt(self):
        salt = os.urandom(16)
        return salt.hex()


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




#class order
#class booking


class MyModelView(AdminIndexView):
    @expose('/')
    def index(self):
        arg1 = 'Hello'
        return self.render('index.html', arg1=arg1)
    def is_accessible(self):
        return current_user.is_authenticated
    def inaccessible_callback(self, name, **kwargs):
        return abort(404)

admin = Admin(current_app, template_mode='bootstrap3',index_view=MyModelView())


class Admin(database.Model,UserMixin):
    __tablename__ = 'admins'
    adminid = database.Column(database.Integer(),primary_key=True)
    username = database.Column(database.String(45),unique=True)
    password_hash = database.Column(database.Text())
    password_salt = database.Column(database.Text())
    contact = database.Column(database.Integer())
    otp_secret = database.Column(database.String(16))
    TFA = database.Column(database.Boolean)
    adminrole = database.relationship('roles',secondary=admin_role,backref=database.backref('admins',lazy='joined'))

    def __init__(self,username,password,contact):
        self.username = username
        self.password_salt = self.generate_salt()
        self.password_hash = self.generate_hash(password,self.password_salt)
        self.contact = contact
        self.otp_secret = pyotp.random_base32()
        self.TFA = False

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
        return self.adminid

    def get_totp_url(self):
        return  pyotp.totp.TOTP(self.otp_secret).provisioning_uri(self.username, issuer_name="Google")

    def verify_otp(self,token):
        totp = pyotp.TOTP(self.otp_secret)
        print(totp.now())
        if token == totp.now():
            return True
        else:
            return False

    def verify_password(self,password):
        return password == self.password_hash

    def __repr__(self):
        return "<admin %r>" % self.adminid


class CustomerModelView(ModelView):
    column_exclude_list = ('password_salt', 'password_hash','credit_card')
    can_create = False
    form_excluded_columns = ('password_hash', 'password_salt','credit_card')

    def is_accessible(self):
        if current_user.is_authenticated:
            current_admin_id = current_user.adminid
            query_role = roles.query.join(admin_role).join(Admin).filter(admin_role.c.adminid == current_admin_id and admin_role.c.roleid == roles.roleid).all()
            print(query_role)
            for role in query_role:
                print(role.type)
                if role.type == 'Super' or role.type == 'User Administrator':
                    return True

    def inaccessible_callback(self, name, **kwargs):
        return abort(404)


class ProductModelView(ModelView):

    create_template = 'product_create.html'
    edit_template = 'edit_product.html'
    def my_formatter(view,context,model,name):
        if model.Image:
            Image = "<img src ='../../static/upload/%s' height='100px' width='100px'>" % (model.Image)
            return Markup(Image)

    def _formatter(view, context, model, name):
        if model.Image2:
            Image = "<img src ='../../static/upload/%s' height='100px' width='100px'>" % (model.Image2)
            return Markup(Image)

    @expose('/edit/', methods=['GET', 'POST'])
    def edit_view(self):
        id = request.args.get('id')
        self._template_args['product'] = Product.query.filter_by(productid=id).first()
        return super(ProductModelView, self).edit_view()

    column_formatters = dict(Image=my_formatter,Image2=_formatter)


    def is_accessible(self):
        if current_user.is_authenticated:
            current_admin_id = current_user.adminid
            # meaning of query_role
            # select * from roles inner join admin_role
            # on adnmin_role,roleid = roles.roleid inner join Admin a on a.adminid = admin_role.adminid
            query_role = roles.query.join(admin_role).join(Admin).filter(admin_role.c.adminid == current_admin_id and admin_role.c.roleid == roles.roleid).all()
            print(query_role)
            for role in query_role:
                print(role.type)
                if role.type == 'Super' or role.type == 'Inventory Administrator':
                    return True

    def inaccessible_callback(self, name, **kwargs):
        return abort(404)


admin.index_view = MyModelView(name='admin')
admin.add_view(ProductModelView(Product,database.session,endpoint='product'))
admin.add_view(CustomerModelView(Customer,database.session))
admin.add_view(CustomerModelView(Account,database.session))
