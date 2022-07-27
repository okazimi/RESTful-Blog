import os
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from flask_gravatar import Gravatar
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, login_manager
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# INITIALIZE FLASK APP
app = Flask(__name__)
# CONFIGURE APPLICATION SECRET KEY
app.config['SECRET_KEY'] = os.environ.get("KEY")
# INITIALIZE CKEDITOR FOR APPLICATION
ckeditor = CKEditor(app)
# INTIALIZE BOOTSTRAP FOR APPLICATION
Bootstrap(app)

# INITIALIZE LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# GRAVATAR IMAGE FOR COMMENTS
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CREATE BLOG POST TABLE
class BlogPost(db.Model):
    # TABLE NAME
    __tablename__ = "blog_posts"
    # DEFAULT TABLE COLUMNS
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # BIDIRECTIONAL RELATIONSHIP WITH USER
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    # ONE TO MANY COMMENT RELATIONSHIP
    comments = relationship("Comment", back_populates="parent_post")


# CREATE USER TABLE
class User(UserMixin, db.Model):
    # TABLE NAME
    __tablename__ = "users"
    # DEFAULT TABLE COLUMNS
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # BIDIRECTIONAL RELATIONSHIP WITH BLOG POST
    posts = relationship("BlogPost", back_populates="author")
    # ONE TO MANY RELATIONSHIP WITH COMMENT
    comments = relationship("Comment", back_populates="comment_author")


# CREATE COMMENT TABLE
class Comment(db.Model):
    # TABLE NAME
    __tablename__ = "comments"
    # DEFUALT TABLE COLUMNS
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # MANY COMMENTS TO ONE USER RELATIONSHIP
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    # MANY COMMENTS TO ONE BLOG POST
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# Line below only required once, when creating DB.
# db.create_all()


# CREATE USER LOADER CALLBACK FOR LOGIN MANAGER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ADMIN ONLY DECORATOR FUNCTION
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # IF CURRENT USER ID IS NOT 1 (A.K.A ADMIN), THEN RETURN UNAUTHORIZED ACCESS
        if current_user.id != 1:
            return abort(403)
        # OTHERWISE CONTINUE WITH ROUTINE FUNCTION
        return f(*args, **kwargs)
    return decorated_function


# HOME PAGE
@app.route('/')
def get_all_posts():
    # QUERY DATABASE FOR ALL BLOG POST
    posts = BlogPost.query.all()
    # RENDER INDEX.HTML AND PASS ALL POST AND CURRENT USER VARIABLES
    return render_template("index.html", all_posts=posts, current_user=current_user)


# REGISTER PAGE
@app.route('/register', methods=["GET", "POST"])
def register():
    # INITIALIZE FORM
    register_form = RegisterForm()
    # CHECK IF REGISTER FORM WAS SUBMITTED
    if register_form.validate_on_submit():
        # CREATE NEW USER
        new_user = User(
            email=register_form.email.data,
            password=generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8),
            name=register_form.name.data
        )
        # CHECK IF USER ALREADY EXISTS
        user = User.query.filter_by(email=new_user.email).first()
        # IF USER ALREADY EXISTS
        if user:
            # GENERATE FLASH MESSAGE
            flash("The provided email already exists, please login instead")
            # REDIRECT TO LOGIN PAGE
            return redirect(url_for('login'))
        # USER DOES NOT ALREADY EXIST
        else:
            # SAVE USER
            db.session.add(new_user)
            db.session.commit()
            # LOGIN USER
            login_user(new_user)
            # REDIRECT TO
            return redirect(url_for('get_all_posts'))
    # RETURN REGISTER HTML PAGE
    return render_template("register.html", form=register_form, current_user=current_user)


# LOGIN PAGE
@app.route('/login', methods=["GET", "POST"])
def login():
    # INITIALIZE LOGIN FORM
    login_form = LoginForm()
    # CHECK IF LOGIN FORM WAS SUBMITTED
    if login_form.validate_on_submit():
        # OBTAIN USER'S EMAIL AND PASSWORD
        email = login_form.email.data
        password = login_form.password.data
        # CHECK TO MAKE SURE USER IS IN DATABASE
        user = User.query.filter_by(email=email).first()
        # IF USER EXISTS
        if user:
            # CHECK ENTERED PASSWORD
            if check_password_hash(user.password, password):
                # IF PASSWORDS MATCH, LOGIN USER
                login_user(user)
                # REDIRECT USER TO HOME PAGE
                return redirect(url_for('get_all_posts'))
            # PASSWORD ENTERED IS INCORRECT
            else:
                # FLASH MESSAGE TO INFORM USER OF INCORRECT PASSWORD
                flash("Password entered is incorrect. Please try again.")
        # USER DOES NOT EXISTS
        else:
            # FLASH MESSAGE TO INFORM USER OF INCORRECT EMAIL
            flash("Email entered is incorrect. Please try again.")
    # RENDER LOGIN PAGE
    return render_template("login.html", form=login_form, current_user=current_user)


# LOGOUT BUTTON
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# SHOW POST PAGE
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    # INITIALIZE COMMENT FORM
    form = CommentForm()
    # OBTAIN REQUESTED POST FROM DATABASE
    requested_post = BlogPost.query.get(post_id)
    # CHECK IF COMMENT FORM WAS SUBMITTED
    if form.validate_on_submit():
        # IF USER IS NOT LOGGED IN
        if not current_user.is_authenticated:
            # PROMPT THEM TO LOGIN OR REGISTER
            flash("You need to login or register to comment.")
            # REDIRECT THEM TO LOGIN PAGE
            return redirect(url_for("login"))
        # IF USER IS LOGGED IN
        # CREATE NEW COMMENT
        comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        # SAVE COMMENT TO DATABASE
        db.session.add(comment)
        db.session.commit()
    # RENDER POST HTML AND PASS RELEVANT DATA
    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


# ABOUT PAGE
@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


# CONTACT PAGE
@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


# ADD NEW POST PAGE
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    # INITIALIZE CREATE POST FORM
    form = CreatePostForm()
    # IF FORM WAS SUBMITTED
    if form.validate_on_submit():
        # CREATE NEW POST OBJECT
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        # ADD POST TO DB
        db.session.add(new_post)
        db.session.commit()
        # REDIRECT TO HOME PAGE
        return redirect(url_for("get_all_posts"))
    # RENDER MAKE-POST.HTML AND PASS RELEVANT DATA
    return render_template("make-post.html", form=form, current_user=current_user)


# EDIT POST PAGE
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    # OBTAIN REQUEST POST FROM DATABASE
    post = BlogPost.query.get(post_id)
    # PRE-POPULATE CREATE POST FORM
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    # IF FORM WAS SUBMITTED
    if edit_form.validate_on_submit():
        # UPDATE REQUESTED POST WITH NEWLY ENTERED DATA
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        # SAVE TO DB
        db.session.commit()
        # REDIRECT TO POST PAGE
        return redirect(url_for("show_post", post_id=post.id))
    # RENDER MAKE A POST PAGE AND PASS RELEVANT DATA
    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True)


# DELETE POST PAGE
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    # OBTAIN POST TO BE DELETED FROM DB
    post_to_delete = BlogPost.query.get(post_id)
    # DELETE POST FROM DB
    db.session.delete(post_to_delete)
    db.session.commit()
    # REDIRECT TO HOME PAGE
    return redirect(url_for('get_all_posts'))


# FLASK APPLICATION CONFIGURATIONS
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
