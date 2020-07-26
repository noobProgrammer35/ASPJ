from flask import Blueprint,render_template,request,redirect,url_for,session,jsonify,flash,abort,current_app,json,escape,Markup,make_response
from flask_recaptcha import ReCaptcha
import pickle
from flask_mail import Mail,Message
from flask_login import current_user,login_user,logout_user
from itsdangerous import URLSafeTimedSerializer
from mysql import connector
from techmarketplace import mysql_connect,utils,Models,vault,log
from techmarketplace.Form import RegisterForm, LoginForm,AccountForm,EmailForm,PasswordResetForm,SearchForm,SupportForm
import os
import redis
from uuid import uuid4
from datetime import timedelta
import socket
import requests


red = redis.Redis(host='redis-12106.c56.east-us.azure.cloud.redislabs.com', port=12106, db=0,
                   password='RZ9IoOQMPab4XGaLee7NUAW6vccBceAU')
path =  os.path.join(os.path.dirname(os.getcwd()),'techmarketplace', 'config.ini')
print(path)
db = mysql_connect.read_config_file(path)

users_blueprint = Blueprint('users',__name__,template_folder='templates')

current_app.config.update({'RECAPTCHA_ENABLED': True,
                   'RECAPTCHA_SITE_KEY':
                       '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                   'RECAPTCHA_SECRET_KEY':
                       '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'})

recaptcha = ReCaptcha(app=current_app)



# @users_blueprint.route('/register',methods=['POST'])  # create user
# def register():
#     form = RegisterForm(request.form)
#     if form.validate_on_submit():
#         username = form.username.data
#         fname = form.fname.data
#         lname = form.lname.data
#         contact = form.contact.data
#         email = form.email.data
#         password = form.confirm.data
#         try:
#             #open connection
#             conn = connector.MySQLConnection(**db)
#             mycursor = conn.cursor(prepared=True)
#             #senstive data exposure
#             password_salt = utils.generate_salt()
#             password_hash = utils.generate_hash(password,password_salt)
#             insert_tuple = (username,fname,lname,contact,email,password_hash,password_salt,0)
#             mycursor.execute('SELECT username,email FROM users WHERE username=%s or email=%s LIMIT 1',(username,email))
#             result = mycursor.fetchall()
#             for x,y in result:
#                 print(x)
#             row = mycursor.rowcount
#             print(row)
#             if row == 0:
#                 mycursor.execute('INSERT INTO users (username,fname,lname,contact,email,password_hash,password_salt,verified) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',insert_tuple)
#                 conn.commit()
#                 token = utils.generate_token(email)
#                 print(token)
#                 confirm_url = url_for('users.confirm_email',token=token,_external=True)
#                 html = render_template('activate.html',confirm_url=confirm_url)
#                 subject = 'Please confirm your account'
#                 utils.send_email(email,subject,html)
#                 flash('dog shit')
#                 return redirect(url_for('login'))
#             else:
#                 for username,email in result:
#                     if username == username and email ==  email:
#                         flash('Username and email existed please use another one!')
#                     elif username == username:
#                         flash('This is an existing username, please choose another one')
#                     elif email == email:
#                         flash('This is an existing email, please choose another one')
#                 return redirect(url_for('register'))
#         except connector.Error as error:
#             print(error)
#         finally:
#             if conn.is_connected():
#                 mycursor.close()
#                 conn.close()
#
#     else:
#         print(form.errors)
#     return render_template('register.html',form=form), 200

@users_blueprint.route('/register',methods=['POST','GET'])
def register():
    if current_user.is_authenticated:
        abort(404)
    searchForm = SearchForm()
    form = RegisterForm()

    if form.validate_on_submit():
        username = Models.Customer.query.filter_by(username=str(escape(form.username.data))).first()
        email = Models.Customer.query.filter_by(email=str(escape(form.email.data))).first()
        if email is None and username is None:
            user = ''
            try:
                user = Models.Customer(str(escape(form.username.data)),str(escape(form.fname.data)),str(escape(form.lname.data)),form.contact.data,str(escape(form.confirm.data)),0,str(escape(form.email.data)))
                Models.database.session.add(user)
                Models.database.session.commit()
            except Exception as errors:
                print('test')
                log.logger.exception(errors)
                Models.database.session.rollback()
            token = utils.generate_token(user.email)
            confirm_url = url_for('users.confirm_email',token=token, _external=True)
            html = render_template('activate.html',confirm_url=confirm_url)
            subject = 'Please confirm your account'
            utils.send_email(form.email.data, subject, html)
            log.logger.info('A new user has sucessfully registered with username of {0}'.format(form.username.data),extra={'custom_dimensions':{'Source':request.remote_addr}})
            return redirect(url_for('login'))
        else:
            if email is not None and username is not None:
                flash('Username and email exist')
            elif email is not None:
                flash('Email exist')
            elif username is not None:
                flash('Username exist')
            return redirect(url_for('register'))
    else:
        print(form.username.data)
        if utils.banned_characters(form.username.data) or utils.banned_characters(
                form.password.data) or utils.banned_characters(form.fname.data) or utils.banned_characters(
                form.lname.data) or utils.banned_characters(form.email.data) or utils.banned_characters(
                form.confirm.data):
            print('d')
            log.logger.critical('Malicious characters detected in register form',
                                extra={'custom_dimensions': {'Source': request.remote_addr}})
            # ban ip addr for next step
    return render_template('register.html',form=form,searchForm=searchForm)




# @users_blueprint.route('/login',methods=['POST'])
# def login():
#     errors = 'dddd'
#     form = LoginForm()
#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data
#         try:
#             conn = connector.MySQLConnection(**db)
#             mycursor = conn.cursor(prepared=True,)
#             # vulnerable code
#             # sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
#             mycursor.execute("SELECT*FROM users where username=%s LIMIT 1;", (username,))
#             account = mycursor.fetchone()
#             conn.commit()
#             if account:
#                 saved_password_salt = account[7]
#                 saved_password_hash = account[6]
#                 password_hash = utils.generate_hash(password,saved_password_salt)
#                 if password_hash == saved_password_hash:
#                     session['username'] = account[1]
#                     session['email'] = account[5]
#                     session['verified'] = account[8]
#                     r = requests.post('https://www.google.com/recaptcha/api/siteverify',
#                                       data={'secret':
#                                                 '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
#                                             'response':
#                                                 request.form['g-recaptcha-response']})
#                     google_response = json.loads(r.text)
#                     print(google_response)
#                     if google_response['success']:
#                         if account[8] == 1:
#                             return redirect(url_for('home_page'))
#                         else:
#                             return redirect(url_for('users.unconfirmed'))
#                     else:
#                         errors = 'Please capture the recaptcha'
#
#                 else:
#                    errors= 'invalid username or password'
#
#             else:
#                 errors = 'Invalid username or password'
#         except connector.Error as error:
#             print(error)
#         finally:
#             if conn.is_connected():
#                 mycursor.close()
#                 conn.close()
#     else:
#         print(form.errors)
#     print(errors)
#     return render_template('login.html',form=form,errors=errors)

@users_blueprint.route('/login',methods=['POST','GET'])
def login():
    searchForm = SearchForm()

    if current_user.is_authenticated:
        # print(current_user.username)
        abort(404)
    errors = ''
    form = LoginForm()
    if form.validate_on_submit():
        if utils.banned_characters(form.username.data) or utils.banned_characters(form.password.data):
            log.logger.critical('Malicious characters such as \'\"<>#/ detected')
            errors = 'Invalid username or password'
            return redirect(url_for('login'))
        user = Models.Customer.query.filter_by(username=str(escape(form.username.data))).first()
        if user != None:
            saved_password_hash = user.password_hash
            saved_password_salt = user.password_salt
            password_hash = utils.generate_hash(str(escape(form.password.data)),saved_password_salt)
            if password_hash == saved_password_hash:
                if user.verified == 1:
                    print('verified authen')
                    u = Models.Customer.query.get(user.userid)
                    login_user(u)
                    response = make_response(redirect(url_for('home_page')))
                    log.logger.info('{0} successfully logs into his account'.format(u.username))
                    return redirect(url_for('home_page'))
                else:
                    u = Models.Customer.query.get(user.userid)
                    login_user(u)
                    log.logger.warning('{0} successfully logs into his account without activating it'.format(u.username))
                    return redirect(url_for('users.unconfirmed'))
            else:
                errors = 'Invalid username or password'
        else:
            errors = 'Invalid username or password'
    else:

        print(form.errors)

    return render_template('login.html',form=form,errors=errors,searchForm=searchForm)



# checked if confirm later()
@users_blueprint.route('/confirm/<token>')
def confirm_email(token):
    # try:
    #     print(token)
    #     email = utils.confirmation_token(token)
    #     print(email)
    #     conn = connector.MySQLConnection(**db)
    #     mycursor = conn.cursor()
    #     mycursor.execute('update users set verified = 1 where email=%s',(email,))
    #     conn.commit()
    # except connector.Error as error:
    #     print(error)
    # finally:
    #     mycursor.close()
    #     conn.close()
    email = utils.confirmation_token(token)
    if not email:
        errors = 'Token Expired Please login to request to resend'
        return redirect(url_for('login',errors=errors))
    user = Models.Customer.query.filter_by(email=email).first()
    user.verified = True
    Models.database.session.commit()
    account = Models.Account(user.userid)
    print(account)
    Models.database.session.add(account)
    Models.database.session.commit()
    log.logger.info('{0} successfully confirm and activated his account through email'.format(user.username))
    return redirect(url_for('home_page'))

@users_blueprint.route('/unconfirmed')
def unconfirmed():
    if current_user.is_authenticated:
        if current_user.verified == 0:
            searchForm = SearchForm()
            return render_template('unconfirm.html',searchForm=searchForm)
        else:
            abort(404)
    else:
        abort(404)

@users_blueprint.route('/resend')
def resend():
    token = utils.generate_token(current_user.email)
    confirm_url = url_for('users.confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = 'Please confirm your account'
    utils.send_email(current_user.email,subject,html)
    flash('Email sent!')
    return redirect(url_for('users.unconfirmed'))


@users_blueprint.route('/profile/<username>/account/update',methods=['POST'])
def accountUpdate(username):
    if current_user.is_authenticated and current_user.username == username:
        form = AccountForm()
        searchForm = SearchForm()
        if form.validate_on_submit():
            key_vault = vault.Vault()
            try:
                key_vault.key_client.get_key(username)
            except:
                key_vault.set_key(username,4096,key_vault.key_ops)
            user = Models.Customer.query.filter_by(username=username).first()
            user.account.payment_method = form.payment_method.data
            user.account.credit_card = key_vault.encrypt(username,form.credit_card.data)
            user.account.address = form.address.data
            Models.database.session.commit()
            key_vault.key_client.close()
            key_vault.secret_client.close()
            log.logger.info('{0} successfuly updated his/her account'.format(user.username))
            return redirect(url_for('account',username=username))
        else:
            log.logger.exception(form.errors)
            print(form.errors)
        return render_template('accountUpdate.html', form=form,searchForm=searchForm)
    else:
        abort(404)


@users_blueprint.route('/reset',methods=['POST'])
def reset_link():
    searchForm = SearchForm()
    error = ''
    form = EmailForm()
    if form.validate_on_submit():
        if Models.Customer.query.filter_by(email=str(escape(form.email.data))).first():
            token = utils.generate_token(form.email.data)
            password_reset_url = url_for('users.reset_password_link',token=token,_external=True)
            html = render_template('reset_email.html',password_reset_url=password_reset_url)
            utils.send_email(form.email.data,'Password Recovery',html)
            errors = 'We have emailed youthe password link to reset!'
            return redirect(url_for('reset_link',errors=errors))
        else:
            error = 'This email is not registered with us!'

    return render_template('reset.html',form=form,errors=error,searchForm=searchForm)


@users_blueprint.route('/reset/<token>',methods=['GET','POST'])
def reset_password_link(token):
    searchForm = SearchForm()
    email = utils.confirmation_token(token)
    if not email:
        message = 'Link is expired please request again'
        return redirect(url_for('login',errors=message))
    form = PasswordResetForm()
    if form.validate_on_submit():
        try:
            user = Models.Customer.query.filter_by(email=email).first()
        except:
            flash('Invalid email')
            return redirect(url_for('login'))

        salt = user.generate_salt()
        user.password_salt = salt
        user.password_hash = user.generate_hash(form.password.data,salt)
        Models.database.session.commit()
        log.logger.info('{0} has succesfully reset his password'.format(user.username))
        return redirect(url_for('login'))
    return render_template('reset_password.html',form=form,token=token,searchForm=searchForm)

@users_blueprint.route('/search',methods=['POST'])
def search():
    searchForm = SearchForm()
    if searchForm.validate_on_submit():
        query = searchForm.search.data
        return redirect(url_for('search_result',query=query))
    # if request.method == 'POST':
    #     query = request.form['search']
    #
    #     return redirect(url_for('search_result',query=query))

@users_blueprint.route('/support',methods=['POST'])
def support():
    searchForm = SearchForm()
    form = SupportForm()
    if form.validate_on_submit():
        mail = Mail(current_app)
        msg = Message(
            subject = form.subject.data,
            recipients=['piethonlee123@gmail.com'],
            body=form.message.data,
            sender=form.name.data,
            reply_to=form.email.data
        )
        mail.send(msg)
        flash('Email has sent to u')
        redirect(request.url)

    return render_template('support.html',searchForm=searchForm,form=form)


def generate_sid():
    return str(uuid4())

def testRegenerate(response):
    serializer = pickle
    id = request.cookies.get('session')
    sessionid = 'session:' + id
    print(sessionid + "  FUCK")
    raw_value = red.get(sessionid)
    session = serializer.loads(raw_value)
    print(session)
    red.delete(str(sessionid))
    sid = generate_sid()
    new_sid = 'session:'+sid
    red.setex(new_sid.encode(),int(current_app.permanent_session_lifetime.total_seconds()),serializer.dumps(session))
    response.set_cookie('user',sid)
    return response
    # for key in red.scan_iter():
    #     s = red.get(key)
    #     print(key)
    #     session = serializer.loads(s)
    #     print(session)
    #     prefix = 'session:'
    #     sid = generate_sid()
    #     newID = prefix+sid
    #     key = newID.encode()
    #     red.setex(key,int(current_app.permanent_session_lifetime.total_seconds()),serializer.dumps(session))
    #

