from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, GroceryList, GroceryItem, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Grocery List App"

# Connect to Database and create session

engine = create_engine('sqlite:///groceryitemswithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Connect and anti-forgery state token

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
        for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Disconnect

@app.route('/disconnect')
def disconnect():

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        #flash("You have been logged out.")
        return redirect(url_for('showGroceryLists'))
    else:
        #flash("You are not logged in")
        return redirect(url_for('showGroceryLists'))

# Google Connect Method

@app.route('/gconnect', methods=['POST'])
def gconnect():

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# Google Disconnect Method

@app.route('/gdisconnect')

def gdisconnect():

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
	del login_session['access_token']
    	del login_session['gplus_id']
    	del login_session['username']
    	del login_session['email']
    	del login_session['picture']
    	response = make_response(json.dumps('Successfully disconnected.'), 200)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    else:
    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response


# User Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# API Endpoints

@app.route('/grocerylist/<int:grocerylist_id>/list/JSON')
def grocerylistListJSON(grocerylist_id):
    grocerylist = session.query(GroceryList).filter_by(id=grocerylist_id).one()
    items = session.query(GroceryItem).filter_by(
        grocerylist_id=grocerylist_id).all()
    return jsonify(GroceryItems=[i.serialize for i in items])

@app.route('/grocerylist/<int:grocerylist_id>/list/<int:list_id>/JSON')
def groceryItemJSON(grocerylist_id, list_id):
    Grocery_Item = session.query(GroceryItem).filter_by(id=list_id).one()
    return jsonify(Grocery_Item=Grocery_Item.serialize)

@app.route('/grocerylist/JSON')
def grocerylistsJSON():
    grocerylists = session.query(GroceryList).all()
    return jsonify(grocerylists=[r.serialize for r in grocerylists])


# Show all Grocery Lists

@app.route('/')
@app.route('/grocerylist/')
def showGroceryLists():
    #grocerylists = session.query(GroceryList).all()
    grocerylists = session.query(GroceryList).order_by(asc(GroceryList.name))
    if 'username' not in login_session:
        return render_template('publicgrocerylists.html', grocerylists=grocerylists)
    else:
        return render_template('grocerylists.html', grocerylists=grocerylists)


# Create a new Grocery List

@app.route('/grocerylist/new/', methods=['GET', 'POST'])
def newGroceryList():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newGroceryList = GroceryList(name=request.form['name'], user_id=login_session['user_id'])
        session.add(newGroceryList)
        #flash('New Grocery List %s Created' % newGroceryList.name)
        session.commit()
        return redirect(url_for('showGroceryLists'))
    else:
        return render_template('newGroceryList.html')


# Edit a Grocery List

@app.route('/grocerylist/<int:grocerylist_id>/edit/', methods=['GET', 'POST'])
def editGroceryList(grocerylist_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedGroceryList = session.query(
        GroceryList).filter_by(id=grocerylist_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedGroceryList.name = request.form['name']
            #flash('Grocery list Edited %s' % editedGroceryList.name)
            return redirect(url_for('showGroceryLists'))
    else:
        return render_template(
            'editGroceryList.html', grocerylist=editedGroceryList)


# Delete a Grocery List

@app.route('/grocerylist/<int:grocerylist_id>/delete/', methods=['GET', 'POST'])
def deleteGroceryList(grocerylist_id):
    if 'username' not in login_session:
        return redirect('/login')
    grocerylistToDelete = session.query(
        GroceryList).filter_by(id=grocerylist_id).one()
    if request.method == 'POST':
        session.delete(grocerylistToDelete)
        #flash('%s Deleted' % grocerylistToDelete.name)
        session.commit()
        return redirect(
            url_for('showGroceryLists', grocerylist_id=grocerylist_id))
    else:
        return render_template(
            'deleteGroceryList.html', grocerylist=grocerylistToDelete)


# Show a Grocery List

@app.route('/grocerylist/<int:grocerylist_id>/')
@app.route('/grocerylist/<int:grocerylist_id>/list/')
def showList(grocerylist_id):
    grocerylist = session.query(GroceryList).filter_by(id=grocerylist_id).one()
    creator = getUserInfo(grocerylist.user_id)
    items = session.query(GroceryItem).filter_by(
        grocerylist_id=grocerylist_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publiclist.html', items=items, grocerylist=grocerylist, creator=creator)
    else:
        return render_template('list.html', items=items, grocerylist=grocerylist, creator=creator)


# Create a new List Item

@app.route('/grocerylist/<int:grocerylist_id>/list/new/', methods=['GET', 'POST'])
def newGroceryItem(grocerylist_id):
    grocerylist = session.query(GroceryList).filter_by(id=grocerylist_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if login_session['user_id'] != grocerylist.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add items to this grocery list. Please create your own list in order to add items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = GroceryItem(name=request.form['name'], description=request.form[
                           'description'], price=request.form['price'], catagory=request.form['catagory'], grocerylist_id=grocerylist_id, user_id=grocerylist.user_id)
        session.add(newItem)
        session.commit()
        #flash("New Item Created")
        return redirect(url_for('showList', grocerylist_id=grocerylist_id))
    else:
        return render_template('newgroceryitem.html', grocerylist_id=grocerylist_id)

    #return render_template('newGroceryItem.html', grocerylist=grocerylist)


# Edit a List Item

@app.route('/grocerylist/<int:grocerylist_id>/list/<int:list_id>/edit',
           methods=['GET', 'POST'])
def editGroceryItem(grocerylist_id, list_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(GroceryItem).filter_by(id=list_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['name']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['catagory']:
            editedItem.catagory = request.form['catagory']
        session.add(editedItem)
        #flash("Item Edited")
        session.commit()
        return redirect(url_for('showList', grocerylist_id=grocerylist_id))
    else:
        return render_template(
            'editgroceryitem.html', grocerylist_id=grocerylist_id, list_id=list_id, item=editedItem)


# Delete a List Item

@app.route('/grocerylist/<int:grocerylist_id>/list/<int:list_id>/delete',
           methods=['GET', 'POST'])
def deleteGroceryItem(grocerylist_id, list_id):
    grocerylist = session.query(GroceryList).filter_by(id=grocerylist_id).one()
    itemToDelete = session.query(GroceryItem).filter_by(id=list_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if login_session['user_id'] != grocerylist.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete this grocery list. Please create your own grocery list in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        #flash("Item Deleted")
        session.commit()
        return redirect(url_for('showList', grocerylist_id=grocerylist_id))
    else:
        return render_template('deleteGroceryItem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'secret'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
