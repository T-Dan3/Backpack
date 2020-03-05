from flask import Flask, request, flash, url_for, redirect, render_template
from flask_sqlalchemy import SQLAlchemy, sqlalchemy
from sqlalchemy.sql import exists
from flask_login import LoginManager, UserMixin, login_required, current_user, logout_user, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///backpacks.sqlite3'
app.config['SECRET_KEY'] = "random string"

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

def create_app():
    """Construct the core application."""
    app = Flask(__name__, instance_relative_config=False)

    # Application Configuration
    app.config.from_object('config.Config')

    # Initialize Plugins
    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        # Import parts of our application
        from . import routes
        from . import login
        app.register_blueprint(routes.main_bp)
        app.register_blueprint(login.login_bp)

        # Initialize Global db
        db.create_all()

        return app

class items(db.Model):
   id = db.Column('item_id', db.Integer, primary_key = True)
   name = db.Column(db.String(100))
   quantity = db.Column(db.Integer)

   def __init__(self, name, quantity):
      self.name = name
      self.quantity = quantity

class User(UserMixin, db.Model):
   id = db.Column(db.Integer, primary_key = True)
   name = db.Column(db.String, nullable = False, unique = False)
   password = db.Column(db.String(100), nullable = False, unique = False)

   def set_password(self, password):
      self.password = generate_password_hash(password, method="sha256")

   def check_password(self, password):
      return check_password_hash(self.password, password)

   def __repr__(self):
      return '<User {}>'.format(self.username)

class LoginForm(FlaskForm):
    """User Login Form."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

User.query.delete()
user = User(name='Admin', password=generate_password_hash('password', method='sha256'))
db.session.add(user)
db.session.commit()

db.create_all()

@app.route('/')
def home():
    if current_user.is_authenticated:
       print("sjfhdjfsdf")
    return render_template("home.html", items = items.query.all())

@app.route('/login', methods=['GET', 'POST'])
def login():
   if current_user.is_authenticated:
      return redirect(url_for('home'))
   
   login_form = LoginForm(request.form)
   
   if request.method == "POST":
      print("posted")
      
      if login_form.validate():
         print("validated")
         name = request.form.get('username')
         password = request.form.get('password')
         user = User.query.filter_by(name=name).first()
         if user and user.check_password(password=password):
            login_user(user)
            print("logged in")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
      if not login_form.validate():
         print("not validated")
   return render_template("login.html", form=login_form)

@app.route('/new', methods= ['GET', 'POST'])
def new():
   if request.method == 'POST':
      if not request.form['name'] or not request.form['quantity']:
         flash('Please enter all the fields', 'error')
      else:
         item = items(request.form['name'], request.form['quantity'])
         test = db.session.query(exists().where(items.name == item.name)).scalar()
         if test == False:
            db.session.add(item)
            db.session.commit()
            flash('A record of {} {} was added'.format(item.quantity,item.name))
            return redirect(url_for('home'))
         else:
            m = items.query.filter_by(name = item.name).first()
            m.quantity = items.quantity + item.quantity
            db.session.add(m)
            db.session.commit()
            flash('Quantity of {} was increased by {}'.format(item.name, item.quantity))
            return redirect(url_for('home'))
   return render_template('new.html')

@app.route('/remove', methods= ['GET', 'POST'])
def remove():
   if request.method == 'POST':
      if not request.form['name'] or not request.form['quantity']:
         flash('Please enter all the fields', 'error')
      else:
         item = items(request.form['name'], request.form['quantity'])
         test = db.session.query(exists().where(items.name == item.name)).scalar()
         if test == True:
            m = items.query.filter_by(name = item.name).first()   
            print(m.quantity) 
            print(item.quantity)
            if (int(item.quantity) == m.quantity):
               items.query.filter_by(name=item.name).delete()
               db.session.commit()
               flash('Record was successfully deleted', 'nothing')
               return redirect(url_for('home'))
            elif (int(item.quantity) < m.quantity):
               m.quantity = items.quantity - item.quantity
               db.session.add(m)
               db.session.commit()
               flash('Quantity of {} was reduced by {}'.format(item.name, item.quantity))
               return redirect(url_for('home'))
            else:
               flash('There is only {} {} left in the backpack'.format(m.quantity, item.name), 'error')            
         else:
            flash('Item is not in the backpack', 'error')
   return render_template('remove.html')

@app.route('/logout')
@login_required
def logout():
   logout_user()
   return redirect(url_for('home'))

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to view that page.')
    return redirect(url_for('login'))


if __name__ == "__main__":
   db.create_all()
   app.run(debug=True)