from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,IntegerField,validators,TextAreaField,SelectField
import email_validator


class RegisterForm(FlaskForm):
    username = StringField('Username',validators=[validators.DataRequired('Username is required!'),validators.Length(min=8,max=50,message='Username must be between 8 to 50 characters'),validators.Regexp('^[A-Za-z\d]+$',message='Whitespace or any symbols is not allowed for Last Name')])
    fname = StringField('Name',validators=[validators.DataRequired('First Name is required'),validators.Length(max=45,message='First Name cannot exceed more than 45 characters'),validators.Regexp('^[A-Za-z]+$',message='Whitespace or any symbols is not allowed for First Name')])
    lname = StringField('Name',validators=[validators.DataRequired('Last Name is required'),validators.Length(max=45,message='Last name cannot exceed more than 45 characters'),validators.Regexp('^[A-Za-z]+$',message='Whitespace or any symbols is not allowed for Last Name')])
    contact = IntegerField('Contact',validators=[validators.DataRequired('Contact is required'),validators.NumberRange(min=8,message='Contact should be 8 digits long!')])
    email = StringField('Email',validators=[validators.DataRequired('Email is required'),validators.Email(message='Please enter valid email address')])
    password = PasswordField('Password',validators=[validators.DataRequired('Password is required'),validators.EqualTo('confirm',message='Password does not match'),validators.Length(min=8,message='Password minimum 8 characters'),validators.Regexp('^.*(?=.{8,10})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$',message='Password must contain at least 8 characters with uppercase,lowercase,symbol and numbers.')])
    confirm = PasswordField('Confirm Password')


class LoginForm(FlaskForm):
    username = StringField('Username',validators=[validators.DataRequired('Username is required!')])
    password = PasswordField('Password',validators=[validators.DataRequired('Password is required')])


class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired('Username is required!')])
    password = PasswordField('Password', validators=[validators.DataRequired('Password is required')])
    # token = StringField('Token', validators=[validators.DataRequired(), validators.Length(6, 6)])


class TwoFactorForm(FlaskForm):
    token = StringField('Token', validators=[validators.DataRequired(), validators.Length(6, 6)])


class AccountForm(FlaskForm):
    address = TextAreaField('Address',validators=[validators.Length(max=55,message='Please do not exceed more than 55 characters')])
    payment_method = SelectField('Payment Method',choices = [('Credit Card','Credit Card')])
    credit_card = StringField('Credit Card',validators=[validators.Length(min=16,message='Credit card should be 16 digit'),validators.regexp('^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$',message='Please enter a valid credit card')])


class EmailForm(FlaskForm):
    email = StringField('Email',validators=[validators.DataRequired('Email is required'),validators.Email(message='Please enter valid email address')])

class PasswordResetForm(FlaskForm):
    password = PasswordField('Password',validators=[validators.DataRequired('Password is required'),validators.EqualTo('confirm',message='Password does not match'),validators.Length(min=8,message='Password minimum 8 characters'),validators.Regexp('^.*(?=.{8,10})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$',message='Password must contain at least 8 characters with uppercase,lowercase,symbol and numbers.')])
    confirm = PasswordField('Confirm Password')

class SearchForm(FlaskForm):
    search = StringField()

class SupportForm(FlaskForm):
    name = StringField('Name',validators=[validators.DataRequired('Name is required'),validators.Length(max=45,message='Name cannot exceed more than 45 characters'),validators.Regexp('^[A-Za-z]+$',message='Whitespace or any symbols is not allowed for Name')])
    email = StringField('Email',validators=[validators.DataRequired('Email is required'),validators.Email(message='Please enter valid email address')])
    subject = StringField('Name',validators=[validators.DataRequired('Subject is required'),validators.Length(max=50,message='subject  cannot exceed more than 50 characters'),validators.Regexp('^[A-Za-z\d]+$',message='Whitespace or any symbols is not allowed for Last Name')])
    message = TextAreaField('Message',validators=[validators.DataRequired('Message is required'),validators.Length(max=200,message='Message cannot exceed more than 200 characters')])