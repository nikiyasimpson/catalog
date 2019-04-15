#Item Catalog
The following is a Flask full stack application demonstrating authentication using Google's oauth API.
The Top Furniture Catalog is a collection of furniture inventory for a store. Log in to add furniture to the collection using
your Google Account.

Users are only allowed to update their own items.

##How to Run
### Google Account
Must have a Google account to log in to the system from the web browser.

###Libraries
The following libraries need to be installed for the web server to run.
1. Flask: `pip install Flask` . For more documentation, visit [Flask Documentation](http://flask.pocoo.org/docs/1.0/installation/)
2. Flask HTTPAuth: `pip install flask_httpauth`. For more documentation, visit [Flask-HTTPAuth Documentation](https://flask-httpauth.readthedocs.io/en/latest/)

3. SQL Alchemy: `pip install SQLAlchemy`. [SQL Alchemy Documentation](https://pypi.org/project/SQLAlchemy/)
4. Oauth2Client: `pip install oauth2client` . [Oauth2Client](https://pypi.org/project/oauth2client/)


###To Run Web Server
To run web server, from the catalog directory run: `python application.py`

###To View Website
Open browser to `http://localhost:5000`


##Style References
[Bootstrap 4.3.1](https://getbootstrap.com/docs/4.3/layout/overview/)

[Libraries for File Upload](http://flask.pocoo.org/docs/1.0/patterns/fileuploads/)

##References
[Flexbox Solution for Horizontal Scrolling](https://codeburst.io/how-to-create-horizontal-scrolling-containers-d8069651e9c6)
[Card Hover Effects](https://codepen.io/jasonheecs/pen/GNNwpZ)

##Author
Nikiya M. Simpson
Udacity, Full Stack Web Development Program Student, 2019