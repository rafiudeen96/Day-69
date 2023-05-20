from flask import Flask, render_template, redirect, url_for, flash, request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship,Mapped,mapped_column
from sqlalchemy import ForeignKey,Column,Integer
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES


class User(UserMixin,db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String,nullable=False)
    email = db.Column(db.String,nullable=False)
    password = db.Column(db.String,nullable=False)
    blogposts = relationship("BlogPost",back_populates="user")
    comments = relationship("Comments",back_populates="user")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer,db.ForeignKey("user.id"),nullable=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments",back_populates="blogposts")
    user = relationship("User",back_populates="blogposts")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey("user.id"),nullable=True)
    post_id = db.Column(db.Integer,db.ForeignKey("blog_posts.id"),nullable=True)
    comment = db.Column(db.Text,nullable=True)
    user = relationship("User",back_populates="comments")
    blogposts = relationship("BlogPost",back_populates="comments")


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)

@app.route('/')
def get_all_posts():
    authentication = current_user.is_authenticated
    posts = BlogPost.query.all()
    print(authentication)
    if authentication:
        print(current_user.id)
        if current_user.id == 1:
            admin = True
        else:
            admin = False
    else:
        admin = False
    return render_template("index.html", all_posts=posts, logged_in=authentication, admin=admin)


@app.route('/register',methods=["GET","POST"])
def register():
    form_object = RegisterForm()
    authentication = current_user.is_authenticated
    email_list = [str(user.email) for user in db.session.query(User).all()]
    if request.method == "POST":
        if form_object.validate_on_submit():
            name = form_object.name.data
            email = form_object.email.data
            password = form_object.password.data
            password = generate_password_hash(password,"pbkdf2:sha256",8)
            if email in email_list:
                error = "An account with this email address has already been registered. Please Log in instead"
                return redirect(url_for('login',error=error))
                # return render_template('login.html',error=error)
            else:
                add = User(name=name,email=email,password=password)
                db.session.add(add)
                db.session.commit()
                user = db.session.query(User).filter_by(email=email).first()
                login_user(user)
                return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=form_object,logged_in=authentication)


@app.route('/login',methods=["GET","POST"])
def login():
    error = request.args.get("error")
    if error is not None:
        message = error
    else:
        message = False
    error_message = request.args.get("error_message")
    if error_message is not None:
        login_error = error_message
    else:
        login_error = False
    authentication = current_user.is_authenticated
    form_object = LoginForm()
    email_in_db = [user.email for user in db.session.query(User).all()]
    if request.method == "POST":
        if form_object.validate_on_submit():
            email = form_object.email.data
            if email not in email_in_db:
                account_error = "Account does not exist"
                return render_template("login.html", form=form_object, logged_in=authentication, error=account_error)
            password = form_object.password.data
            user = db.session.query(User).filter_by(email=email).first()
            if check_password_hash(user.password,password):
                login_user(user)
                print(current_user.email)
                return redirect(url_for("get_all_posts"))
            else:
                password_error = "Invalid password"
                return render_template("login.html", form=form_object, logged_in=authentication, error=password_error)
    return render_template("login.html",form=form_object,logged_in=authentication,error=message,login_error=login_error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    authentication = current_user.is_authenticated
    comment_form = CommentForm()
    if authentication:
        if current_user.id == 1:
            admin = True
        else:
            admin = False
    else:
        admin = False
    if request.method == "POST":
        if comment_form.validate_on_submit():
            if authentication:
                add_comment = Comments(user_id=current_user.id, post_id=post_id, comment=comment_form.comment.data)
                db.session.add(add_comment)
                db.session.commit()
            else:
                return redirect(url_for("login",error_message="You need to login to comment"))
    comments = db.session.query(Comments).all()
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, comments=comments, comment_form=comment_form, logged_in=authentication,admin=admin)


@app.route("/about")
def about():
    authentication = current_user.is_authenticated
    return render_template("about.html",logged_in=authentication)


@app.route("/contact")
def contact():
    authentication = current_user.is_authenticated
    return render_template("contact.html",logged_in=authentication)


def admin_only(function):
    @wraps(function)
    def wrapper_function():
        if current_user.is_authenticated:
            if current_user.id == 1:
                return function()
            else:
                return abort(403)
        else:
            return "Not Logged in yet"
    return wrapper_function

@app.route("/new-post",methods=["GET","POST"])
@admin_only
def add_new_post():
    authentication = current_user.is_authenticated
    form = CreatePostForm()
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                author_id = current_user.id,
                body=form.body.data,
                img_url=form.img_url.data,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=authentication)


@app.route("/edit-post/<int:post_id>",methods=["GET","POST"])
@admin_only
def edit_post(post_id):
    authentication = current_user.is_authenticated
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=authentication)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
