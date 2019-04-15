import os
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from flask import redirect, flash, make_response

# libraries for connecting to data
from model import Base, User, Item, Category
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, asc

from flask_httpauth import HTTPBasicAuth
import json

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests

# set libraries and variables for image uploads
from werkzeug.utils import secure_filename
from flask import send_from_directory

UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

auth = HTTPBasicAuth()

# Connect to Item Catalog Database
engine = create_engine('sqlite:///itemCatalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create Flask App and configure uploads folder
app = Flask(__name__, static_url_path='/static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# only allow up to 4MB image upload to server
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


@auth.verify_password
def verify_password(username_or_token, password):
    print("Looking for user %s" % username_or_token)
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user:
            return False
    g.user = user
    return True


@auth.error_handler
def auth_error():
    return "Access Denied"


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/logout')
def logout():
    gdisconnect()
    login_session.clear()
    return redirect(url_for('showCatalog'))


# Show item catalog
@app.route('/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(asc(Item.name))
    if 'username' not in login_session:
        return render_template('publiccatalog.html',
                               items=items,
                               categories=categories)
    else:
        return render_template('catalog.html',
                               items=items,
                               categories=categories,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


# Show catalog categories
@app.route('/categories')
@auth.login_required
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return redirect('/login')
    else:
        return render_template('category.html',
                               categories=categories,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    print("Step 1 - Complete, received auth code %s" % code)

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    print("Step 2 Complete! Access Token : %s " % credentials.access_token)

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    user = getUserInfo(user_id)
    token = user.generate_auth_token(600)

    flash("You are now logged in as %s" % login_session['username'])
    print("Successfully logged in!")
    print(token)
    return render_template('successlogin.html', login_session=login_session)


# User Helper Functions
def createUser(login_session):
    newUser = User(username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except SQLAlchemyError as e:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'),
            400)
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Catalog Information

@app.route('/api/item/<int:item_id>/JSON')
def ItemJSON(item_id):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/api/items/JSON')
def itemsJSON():
    if 'username' not in login_session:
        return redirect('/login')
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


# CATEGORY ROUTES
# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'])
        session.add(newCategory)
        session.commit()
        flash('New %s Category Successfully Created' % (newCategory.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html',
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


# Edit category from the catalog
@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash('Category Successfully Edited')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('editCategory.html',
                               category=editedCategory,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


# Delete an item from the catalog
@app.route('/category/<int:category_id>/remove', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('Category Successfully Deleted')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCategory.html',
                               category=categoryToDelete,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


# Create a new item
@app.route('/item/new/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        # check if the post request has the file part
        if 'picture' not in request.files:
            flash('No picture image to upload')
            return redirect(request.url)
        file = request.files['picture']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected picture')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            print('file uploaded successfully')
            print(filename)

        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       price=request.form['price'], picture=filename,
                       category_id=request.form['category_id'],
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).all()
        return render_template('newItem.html',
                               categories=categories,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


# Edit an item from the catalog
@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')

    editedItem = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        # Check Authorization for the user to edit the record
        creator = getUserInfo(editedItem.user_id)
        if creator.id == login_session['user_id']:
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            if request.form['price']:
                editedItem.price = request.form['price']
            if request.form['category_id']:
                editedItem.category_id = request.form['category_id']
            session.add(editedItem)
            session.commit()
            flash('Item Successfully Edited')
            return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).all()
        return render_template('editItem.html',
                               item=editedItem,
                               categories=categories,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


# Delete an item from the catalog
@app.route('/item/<int:item_id>/remove', methods=['GET', 'POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        return redirect('/login')

    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        # Check Authorization for the user to edit the record
        creator = getUserInfo(itemToDelete.user_id)
        if creator.id == login_session['user_id']:
            session.delete(itemToDelete)
            session.commit()
            flash('Item Successfully Deleted')
            return redirect(url_for('showCatalog'))
        else:
            flash('You do not have authorization to delete this item.')
            return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteItem.html',
                               item=itemToDelete,
                               login=login_session['username'],
                               user_id=login_session['user_id'],
                               photo=login_session['picture'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
