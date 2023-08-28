from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap


app = Flask(__name__)
app.app_context().push()
Bootstrap(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///to_do.db"
app.config["SECRET_KEY"] = "ALKJDAJK34OJF"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    todos = relationship("ToDo", backref="author")


class ToDo(db.Model):
    __tablename__ = "todos"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    title = db.Column(db.String(40))
    subtitle = db.Column(db.String(400))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/start')
def start():
    return render_template("start.html")


@app.route('/register', methods=["GET", "POST"])
def register():

    if request.method == "POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("The email already exist!")
            return redirect(url_for('login'))

        else:
            hashed_salted_password = generate_password_hash(
                request.form.get('psw'),
                method='pbkdf2:sha256',
                salt_length=4
            )

            new_user = User(
                email=request.form.get('email'),
                password=hashed_salted_password,
                name=request.form.get('name')
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('show_tasks'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():

    if request.method == "POST":
        user_email = request.form.get('email')
        user_password = request.form.get('psw')
        author = current_user
        user = User.query.filter_by(email=user_email).first()

        if not user:
            flash("The email does not exist.")
            return redirect(url_for('register'))

        elif not check_password_hash(user.password, password=user_password):
            flash("The password does not match.")

        elif user and check_password_hash(user.password, password=user_password):
            login_user(user)
            return redirect(url_for("show_tasks"))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/task')
@login_required
def show_tasks():
    to_dos = db.session.query(ToDo).all()

    return render_template("tasks.html", form=to_dos, logged_in=True)


@app.route('/add', methods=["POST", "GET"])
def add_task():
    if request.method == "POST":
        new_to_do = ToDo(
            title=request.form.get("to-do"),
            subtitle=request.form.get("subtitle"),
            author=current_user
        )

        db.session.add(new_to_do)
        db.session.commit()

        return redirect(url_for('show_tasks'))
    return render_template('add.html')


@app.route('/contact')
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
