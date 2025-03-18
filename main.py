import os
from datetime import date
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, url_for
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

# Import your forms from the forms.py
from forms import CommentForm, CreatePostForm, LoginUser, RegisterUser

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("DAY_69_SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)
gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(1000))

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(String(1000), nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")

    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterUser()

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = generate_password_hash(form["password"].data)

        check_user = User.query.filter_by(email=email).first()
        if check_user:
            flash("Email already registered!")
            return redirect(url_for("login"))
        else:
            new_user = User(email=email, password=password, name=name)  # type: ignore
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginUser()

    if form.validate_on_submit():
        email = form.email.data
        password = form["password"].data

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Wrong Password - Try again")
        else:
            flash("That user dosen't exist")

    return render_template("login.html", form=form)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            abort(403)  # Forbidden
        return f(*args, **kwargs)

    return decorated_function


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/")
def get_all_posts():
    admin = False
    logged = current_user.is_authenticated
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()

    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True

    return render_template("index.html", all_posts=posts, loggedin=logged, admin=admin)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    admin = False
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if current_user.is_authenticated:
        if current_user.id == 1:
            admin = True

    if form.validate_on_submit():
        new_comment = Comment(
            body=form.body.data, author=current_user, post=requested_post  # type: ignore
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template(
        "post.html",
        post=requested_post,
        admin=admin,
        loggedin=current_user.is_authenticated,
        form=form,
    )


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def add_new_post():
    form = CreatePostForm()

    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,  # type: ignore
            subtitle=form.subtitle.data,  # type: ignore
            body=form.body.data,  # type: ignore
            img_url=form.img_url.data,  # type: ignore
            author=current_user,  # type: ignore
            date=date.today().strftime("%B %d, %Y"),  # type: ignore
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template(
        "make-post.html", form=form, loggedin=current_user.is_authenticated
    )


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data  # type: ignore
        post.subtitle = edit_form.subtitle.data  # type: ignore
        post.img_url = edit_form.img_url.data  # type: ignore
        post.author = current_user  # type: ignore
        post.body = edit_form.body.data  # type: ignore
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template(
        "make-post.html",
        form=edit_form,
        is_edit=True,
        loggedin=current_user.is_authenticated,
    )


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route("/about")
def about():
    return render_template("about.html", loggedin=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", loggedin=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
