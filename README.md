# Item Catalog
The following is a Flask full stack application demonstrating authentication using Google's oauth API.
The Top Furniture Catalog is a collection of furniture inventory for a store. Log in to add furniture to the collection using
your Google Account.

Catalog has been updated to run on Linux Ubuntu Server with PostgreSQL and Apache
Users are only allowed to update their own items.

## How to Run
### Google Account
Must have a Google account to log in to the system from the web browser.

### Libraries
The following libraries need to be installed for the web server to run.
1. Flask: `pip install Flask` . For more documentation, visit [Flask Documentation](http://flask.pocoo.org/docs/1.0/installation/)
2. Flask HTTPAuth: `pip install flask_httpauth`. For more documentation, visit [Flask-HTTPAuth Documentation](https://flask-httpauth.readthedocs.io/en/latest/)

3. SQL Alchemy: `pip install SQLAlchemy`. [SQL Alchemy Documentation](https://pypi.org/project/SQLAlchemy/)
4. Oauth2Client: `pip install oauth2client` . [Oauth2Client](https://pypi.org/project/oauth2client/)
5. Flask-Login: `pip install flask-login`. [Flask-Login](https://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager)
6. PostgreSql: `sudo apt-get install postgresql`[PostgreSql](https://www.godaddy.com/garage/how-to-install-postgresql-on-ubuntu-14-04/)
7. PassLIb: `sudo pip install passlib`
8. Request: `sudo pip install requests`
9. Apache: `sudo apt update` `sudo apt install apache2`. Steps to Install Server and Virtual host in References below under How to Install Apache Web Server on Ubuntu.

### To View Website
Open browser to `http://54.90.118.51.xip.io:80`
IP Address: 54.90.118.51
Port: 80

## Style References
[Bootstrap 4.3.1](https://getbootstrap.com/docs/4.3/layout/overview/)

[Libraries for File Upload](http://flask.pocoo.org/docs/1.0/patterns/fileuploads/)

## References
1.[Flexbox Solution for Horizontal Scrolling](https://codeburst.io/how-to-create-horizontal-scrolling-containers-d8069651e9c6)
2.[Card Hover Effects](https://codepen.io/jasonheecs/pen/GNNwpZ)
3.[Flask Login Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-v-user-logins)
4.[Add Google Oauth to Flask Application](https://medium.com/@bittu/add-google-oauth2-login-in-your-flask-web-app-9f455695341e)
5.[How to Deploy a Flask Applcation on Ubuntu Server](https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps)
6.[How to Install PostgreSQL on Ubuntu](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-16-04)
7.[Migrating SQLite to PostgreSQL](https://tutorialinux.com/today-learned-migrating-sqlite-postgres-easy-sequel/)
8.[How to Install Apache Web Server on Ubuntu](https://www.digitalocean.com/community/tutorials/how-to-install-the-apache-web-server-on-ubuntu-18-04-quickstart)

## Author
Nikiya M. Simpson
Udacity, Full Stack Web Development Program Student, 2019
