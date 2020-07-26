from flask import jsonify,request,flash,Flask,render_template,redirect,session,url_for,Response,abort,json,escape,g
from flask_wtf.csrf import CSRFProtect,CSRFError
from flask_sqlalchemy import *
from techmarketplace.Form import RegisterForm, LoginForm,AccountForm,EmailForm,SearchForm,SupportForm
from techmarketplace import mysql_connect,utils,config,redisession
from flask_login import current_user,logout_user
from flask_paranoid import Paranoid
from opencensus.ext.azure import metrics_exporter
import datetime
from functools import wraps
import socket
from sqlalchemy import or_,and_
import requests
import psutil
from uuid import uuid4
import redis
import pickle

red = redis.Redis(host='redis-12106.c56.east-us.azure.cloud.redislabs.com', port=12106, db=0,
                   password='RZ9IoOQMPab4XGaLee7NUAW6vccBceAU')

app = config.create_app()
# exporter = metrics_exporter.new_metrics_exporter(connection_string='InstrumentationKey=bec9fb90-0c7a-417a-809e-6c5417e4ba98')
with app.app_context():
    from techmarketplace.api.routes import userAPI
    from techmarketplace import Models,server_session
    app.register_blueprint(userAPI.users_blueprint)
    Models.database.create_all()
    # a = Models.Admin.query.get(1)
    # try:
    #     x = Models.Admin('Henry123','password123',96279135,'superuser')
    #     Models.database.session.add(x)
    #     Models.database.session.commit()
    # except:
    #     Models.database.session.rollback()
    # print(Models.roles.query.filter_by(type='admin').first())
    # s = Models.Admin.query.filter_by(username='Henry223').first()
    # print(a.adminid)



csrf = CSRFProtect(app)
#session protection
paranoid = Paranoid(app)
paranoid.redirect_view = 'localhost:5000/register'
db = mysql_connect.read_config_file()




# session expiry, still need error emssage
@app.before_request
def before_request():
    # print(psutil.net_io_counters())
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=1)
    # session.modified = True
    g.user = current_user

# @app.errorhandler(403)
# def handle_403(e):
#     return render_template('403.html') , 403

def login_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        try:
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            else:
                return f(*args,**kwargs)
        except:
            abort(404)
    return wrap



def verify_require(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if current_user.is_authenticated:
            if current_user.verified == 0:
                return redirect(url_for('users.unconfirmed'))
            else:
                return f(*args,**kwargs)
        else:
            return f(*args, **kwargs)
    return wrap


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return '<h3>Sorry server encountered an error. Please try again by refreshing your browser</h3>'


@app.route('/')
@verify_require
def home_page():

    searchForm = SearchForm()
    # print(request.headers.get('X-Forwarded-For', request.remote_addr))
    # print(paranoid._get_remote_addr())
    # print(test.session)
    # # for key in red.scan_iter():
    # #     print(json.loads(red.get(key)))
    # d = socket.gethostname()
    # print(socket.gethostbyname(d))
    if request.remote_addr in ['127.0.0.1']:

        return render_template('index.html',searchForm =searchForm)

@app.route('/login')
def login():

    searchForm = SearchForm()
    errors = ''
    if current_user.is_authenticated:
        return redirect(url_for('home_page'))
    form = LoginForm()
    return render_template('login.html',form=form,errors=errors,searchForm=searchForm)

@app.route('/register')
def register():
    searchForm = SearchForm()
    form = RegisterForm()
    return render_template('register.html',form=form,searchForm=searchForm)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    print(session)
    return redirect(url_for('home_page'))

#can consider as broken access control
@app.route('/profile/<username>')
@verify_require
@login_required
def profile(username):
    searchForm = SearchForm()
    print(current_user.is_active)
    if current_user.is_authenticated and current_user.username == username:
        return render_template('profile.html', active='profile',searchForm=searchForm)
    else:
        abort(404)

@app.route('/profile/<username>/account')
@verify_require
def account(username):
    searchForm = SearchForm()
    print(current_user.account.accountid)
    if current_user.is_authenticated and current_user.username == username:
        return render_template('account.html',searchForm=searchForm)
    else:
        abort(404)

@app.route('/profile/<username>/account/update')
@verify_require
def account_update_page(username):
    searchForm = SearchForm()
    if current_user.is_authenticated and current_user.username == username:
        form = AccountForm()
        return render_template('accountUpdate.html',form=form,searchForm=searchForm)
    else:
       abort(404)

def adminLogin():
    pass
    # if vulnerability remove these and check for domain hostname
    # current_location = utils.get_location()
    # target_point = [{'lat':1.3793037,'lng':103.8476829}]
    # current_point = [{'lat':current_location[0],'lng':current_location[1]}]
    # radius = 0.1
    # distance = utils.haversine(target_point[0]['lng'],target_point[0]['lat'],float(current_point[0]['lng']),float(current_point[0]['lat']))
    # if distance < radius:

    # form = AdminLoginForm()
    # return render_template('private/adminLogin.html',form=form)
    # else:
    #     abort(403)

@app.route('/reset')
def reset_link():
    searchForm = SearchForm()
    errors=''
    form = EmailForm()
    return render_template('reset.html',form=form,errors=errors,searchForm=searchForm)


@app.route('/support')
def support():
    searchForm = SearchForm()
    form = SupportForm()
    return render_template('support.html',searchForm=searchForm,form=form)

@app.route('/catalog')
def catalog():
    searchForm = SearchForm()
    products = Models.database.session.query(Models.Product).all()
    return render_template('shop.html',products=products,itemCount=len(products),searchForm=searchForm)

@app.route('/catalog/<productid>' , methods=['POST','GET'])
def single_product_detail(productid):
    searchForm = SearchForm()
    product = Models.Product.query.filter_by(productid=productid).first()
    return render_template('single_product_details.html',product=product,searchForm=searchForm)

@app.route('/result')
def search_result():
    searchForm = SearchForm()
    query = request.args.get('query')
    search = "%{}%".format(query)
    result = Models.database.session.query(Models.Product).filter(or_(Models.Product.Name.ilike(search),Models.Product.Description.ilike(search),Models.Product.model.ilike(search))).all()

    print(result)
    return render_template('search.html',product=result,itemCount=len(result),query=query,searchForm=searchForm), 201


if __name__ == '__main__':
    app.config.update(
        SESSION_COOKIE_HTTPONLY = True
    )
    # app.config.update(
    #     SESSION_COOKIE_SAMESITE='LAX'
    # )
    app.run(debug=True)