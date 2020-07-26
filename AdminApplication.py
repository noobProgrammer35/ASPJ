from flask import jsonify,request,flash,Flask,render_template,redirect,session,url_for,Response,abort,json
from flask_wtf.csrf import CSRFProtect,CSRFError
from flask_sqlalchemy import *
from techmarketplace.Form import RegisterForm, LoginForm,AdminLoginForm,TwoFactorForm
from flask_login import login_user,logout_user,current_user
import io
import pyqrcode
import os
from flask_paranoid import Paranoid


app = Flask(__name__,template_folder='backend')
app.config['SECRET_KEY'] = os.urandom(32)
app.config['UPLOAD_FOLDER'] = 'static\\upload'



with app.app_context():
    from techmarketplace.api.routes import adminAPI
    from techmarketplace import AdminModels

    app.register_blueprint(adminAPI.admin_blueprint)
    # try:
    #     x = AdminModels.Admin('Jamess', 'password123', 96279135)
    #     AdminModels.database.session.add(x)
    #     AdminModels.database.session.commit()
    # except:
    #     AdminModels.database.session.rollback()

paranoid = Paranoid(app)
paranoid.redirect_view = 'https://google.com'

@app.route('/')
def login():
    print(session)
    if 'user' in session or current_user.is_authenticated:
        abort(404)
    form = AdminLoginForm()
    return render_template('adminLogin.html',form=form)

@app.route('/twofactor')
def twofactor():

    if 'user' in session:
        admin = AdminModels.Admin.query.filter_by(username=session['user']).first()
        if admin.TFA:
            form = TwoFactorForm()
            return render_template('twofactorPage.html',form=form) ,200 ,{
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
        else:
            abort(404)
    else:
        abort(404)

@app.route('/TwoFactorSetUp')
def TwoFactorSetup():
    if 'user' not in session:
        abort(404)
    admin = AdminModels.Admin.query.filter_by(username=session['user']).first()
    if admin is None:
        abort(404)
    if admin.TFA:
        abort(404)
    form = TwoFactorForm()
    return render_template('TwoFactorSetUp.html',form=form),200 ,{
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

# @app.route('/a')
# def admin_customer():
#     return self.render('index.html')

if __name__ == '__main__':
    # this works
    # app.config.update(
    #     SESSION_COOKIE_SECURE = True,
    #     SESSION_COOKIE_HTTPONLY = True,
    #     SESSION_COOKIE_SAMESITE='Lax',
    # )
    app.run(debug=True,host='127.0.0.1',port=5001)