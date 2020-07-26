from flask import Blueprint,render_template,request,redirect,url_for,session,jsonify,flash,abort,current_app,json
from techmarketplace.Form import AdminLoginForm,TwoFactorForm
from techmarketplace import AdminModels,utils
from flask_login import login_user,logout_user,current_user
from werkzeug.utils import secure_filename
import pyqrcode
import os
import io

admin_blueprint = Blueprint('admins',__name__,template_folder='backend')

#show qr code to only those wh havent activate 2FA
# steps verify login credential > verify token > login
# if not activated 2fa prompt to activate page whicyh is qr code, in activate page make a textfield to verify token if correct then tfa enabled for that user

@admin_blueprint.route('/',methods=['POST'])
def login():
    if 'user' in session or current_user.is_authenticated:
        abort(404)
    form = AdminLoginForm()
    if form.validate_on_submit():
        username =  form.username.data
        password = form.password.data
        admin = AdminModels.Admin.query.filter_by(username=username).first()
        if admin != None:
            saved_password_salt = admin.password_salt
            password_hash = utils.generate_hash(password,saved_password_salt)
            if admin.verify_password(password_hash):
                # current = AdminModels.Admin.query.get(admin.adminid)
                # login_user(current)
                if not admin.TFA:
                    session['user'] = admin.username
                    print(session)
                    return redirect(url_for('TwoFactorSetup'))
                else:
                    session['user'] = admin.username
                    return redirect(url_for('twofactor'))
            else:
                print(3)
        else:
            print(2)
    else:
        print(1)
    return render_template('adminLogin.html',form=form)



@admin_blueprint.route('/qrcode')
def qrcode():
    if 'user' not in session:
        abort(404)
    user = AdminModels.Admin.query.filter_by(username=session['user']).first()
    if user is None:
        abort(404)
    print(user)
    url = pyqrcode.create(user.get_totp_url())
    stream = io.BytesIO()
    url.svg(stream, scale=5)
    # remove cache
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@admin_blueprint.route('/twofactor',methods=['POST'])
def authenticate():
    if 'user' not in session:
        abort(404)
    user = AdminModels.Admin.query.filter_by(username=session['user']).first()
    if user is None:
        abort(404)
    if not user.TFA:
        abort(404)
    del session['user']
    print(user.username)
    form = TwoFactorForm()
    if form.validate_on_submit():
        print('dadadadadadad')
        token = form.token.data
        if user.verify_otp(token):
            current = AdminModels.Admin.query.get(user.adminid)
            login_user(current)

            return redirect(url_for('admin.index'))
    else:
        print('not validated')

    return render_template('twofactorPage.html',form=form)

@admin_blueprint.route('/TwoFactorSetUp',methods=['POST'])
def TFASetup():
    if 'user' not in session:
        abort(404)
    admin = AdminModels.Admin.query.filter_by(username=session['user']).first()
    if admin is None:
        abort(404)
    if admin.TFA:
        abort(404)
    form = TwoFactorForm()
    if form.validate_on_submit():

        if admin.verify_otp(form.token.data):
            admin.TFA = True
            AdminModels.database.session.commit()
            del session['user']
            return redirect(url_for('login'))
        else:
            del session['user']
            flash('Key in wrongly please re login to key in again')
            return redirect(url_for('TwoFactorSetup'))
    return render_template('TwoFactorSetUp.html',form=form)

@admin_blueprint.route('/product_create',methods=['POST','GET'])
def product_create():
    if request.method == 'POST':
        name = request.form['Name']
        description = request.form['Description']
        stock = request.form['stock']
        price = request.form['price']
        Image = request.files['Image']
        Image2 = request.files['Image2']
        model = request.form['model']

        products = AdminModels.Product.query.filter_by(model=model).first()
        if products is None:

            if name in ['\\','/','<','>','\'','\"'] or description in  ['\\','/','<','>','\'','\"'] or model in ['\\','/','<','>','\'','\"'] :
                flash('Suspcious character detected. Please do not try to do malicious stuff')
                return redirect('/admin/product/new')
            if name == '' or description == '' or model =='':
                flash('Please fill in everything')
                return redirect('/admin/product/new')

            if price == '' or stock == '':
                flash('Stock or price must be integer')
                return redirect('/admin/product/new')

            if Image.filename=='' or Image2.filename == '':
                flash('No selected file')
                return redirect('/admin/product/new')
            if Image and Image2 and utils.allowed_file(Image.filename) and utils.allowed_file(Image2.filename):
                ImageName = secure_filename(Image.filename)
                ImageName2 = secure_filename(Image2.filename)
                path = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName)
                path2 = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName2)
                Image.save(path)
                Image2.save(path2)
                product = AdminModels.Product(name, description, stock, price, ImageName, ImageName2,model)
                AdminModels.database.session.add(product)
                AdminModels.database.session.commit()
                return redirect(url_for('product.index_view'))
            else:
                flash('Inappoporiate file type')
                return redirect('/admin/product/new')
        else:
            flash('This model has already exist in our inventory')
            return redirect('/admin/product/new')


@admin_blueprint.route('/edit_product/<productid>',methods=['POST'])
def edit(productid):
    if request.method == 'POST':
        name = request.form['Name']
        description = request.form['Description']
        stock = request.form['stock']
        price = request.form['price']
        Image = request.files['Image']
        Image2 = request.files['Image2']
        model = request.form['model']
        product = AdminModels.Product.query.filter_by(productid=productid).first()
        if name in ['\\', '/', '<', '>', '\'', '\"'] or description in ['\\', '/', '<', '>', '\'', '\"'] or model in [
            '\\', '/', '<', '>', '\'', '\"']:
            flash('Suspcious character detected. Please do not try to do malicious stuff')
            return redirect('/admin/product/edit')
        if name == '' or description == '' or model == '':
            flash('Please fill in everything')
            return redirect('/admin/product/edit/?={0}&url=/admin/product/'.format(product.productid))

        if price == '' or stock == '':
            flash('Stock or price must be integer')
            return redirect('/admin/product/edit/?={0}&url=/admin/product/'.format(product.productid))

        if Image.filename == '' or Image2.filename == '':
            flash('No selected file')
            return redirect('/admin/product/edit/?={0}&url=/admin/product/'.format(product.productid))
        if Image and Image2 and utils.allowed_file(Image.filename) and utils.allowed_file(Image2.filename):
            if product.model == model:
                product.Name = name
                product.Description = description
                product.stock= stock
                product.price = price
                ImageName = secure_filename(Image.filename)
                ImageName2 = secure_filename(Image2.filename)
                path = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName)
                path2 = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName2)
                Image.save(path)
                Image2.save(path2)
                product.Image = ImageName
                product.Image2 = ImageName2
                product.model = model
                AdminModels.database.session.commit()
                return redirect(url_for('product.index_view'))

            else:
                models = AdminModels.Product.query.filter_by(model=model).first()
                if models is None:
                    product.Name = name
                    product.Description = description
                    product.stock = stock
                    product.price = price
                    ImageName = secure_filename(Image.filename)
                    ImageName2 = secure_filename(Image2.filename)
                    path = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName)
                    path2 = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName2)
                    Image.save(path)
                    Image2.save(path2)
                    product.Image = ImageName
                    product.Image2 = ImageName2
                    product.model = model
                    AdminModels.database.session.commit()
                    return redirect(url_for('product.index_view'))
