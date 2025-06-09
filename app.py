
from flask import Flask, redirect, url_for, session, render_template, request
from flask_sqlalchemy import SQLAlchemy
import google.auth.transport.requests
from google_auth_oauthlib.flow import Flow
import os, pathlib
from google.oauth2 import id_token
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import config as config_module


app = Flask(__name__)
app.secret_key = config_module.SECRET_KEY

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(app)
login_manager = LoginManager(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Тільки для тестів http

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))

class Family(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))

class FamilyMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    family_id = db.Column(db.Integer, db.ForeignKey("family.id"))
    role = db.Column(db.String(50))  # "owner" або "member"

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    is_private = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

class ShoppingItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    is_bought = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/invite", methods=["POST"])
@login_required
def invite():
    email = request.form["invite_email"]
    invited_user = User.query.filter_by(email=email).first()

    # Знайти сім’ю поточного користувача
    family_member = FamilyMember.query.filter_by(user_id=current_user.id, role="owner").first()
    if not family_member:
        return "У вас немає сім’ї або ви не є власником", 400

    if invited_user:
        # Додаємо в сім'ю
        new_member = FamilyMember(user_id=invited_user.id, family_id=family_member.family_id, role="member")
        db.session.add(new_member)
        db.session.commit()
        return redirect(url_for("profile"))
    else:
        return "Користувача з таким email не знайдено", 404

@app.route("/notes")
@login_required
def notes():
    user_notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template("notes.html", notes=user_notes)

@app.route("/notes/add", methods=["GET", "POST"])
@login_required
def add_note():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        note = Note(title=title, content=content, user_id=current_user.id)
        db.session.add(note)
        db.session.commit()
        return redirect(url_for("notes"))
    return render_template("add_note.html")

@app.route("/notes/delete/<int:note_id>")
@login_required
def delete_note(note_id):
    note = Note.query.get(note_id)
    if note and note.user_id == current_user.id:
        db.session.delete(note)
        db.session.commit()
    return redirect(url_for("notes"))


@app.route("/shopping")
@login_required
def shopping():
    items = ShoppingItem.query.filter_by(user_id=current_user.id).all()
    return render_template("shopping.html", items=items)

@app.route("/shopping/add", methods=["POST"])
@login_required
def add_shopping():
    name = request.form["name"]
    item = ShoppingItem(name=name, user_id=current_user.id)
    db.session.add(item)
    db.session.commit()
    return redirect(url_for("shopping"))

@app.route("/shopping/toggle/<int:item_id>")
@login_required
def toggle_shopping(item_id):
    item = ShoppingItem.query.get(item_id)
    if item and item.user_id == current_user.id:
        item.is_bought = not item.is_bought
        db.session.commit()
    return redirect(url_for("shopping"))

@app.route("/shopping/delete/<int:item_id>")
@login_required
def delete_shopping(item_id):
    item = ShoppingItem.query.get(item_id)
    if item and item.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for("shopping"))


@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/calendar.events"
        ],
        redirect_uri=url_for("callback", _external=True),
    )

    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true"
    )

    session["state"] = state  # ← ОБОВʼЯЗКОВО!
    return redirect(auth_url)


@app.route("/wishlists")
@login_required
def wishlists():
    my_wishlists = Wishlist.query.filter_by(user_id=current_user.id).all()

    # Публічні списки інших членів родини
    member = FamilyMember.query.filter_by(user_id=current_user.id).first()
    public_wishlists = []
    if member:
        public_wishlists = (
            Wishlist.query
            .join(User)
            .join(FamilyMember)
            .filter(
                Wishlist.user_id != current_user.id,
                Wishlist.is_private == False,
                FamilyMember.family_id == member.family_id
            )
            .all()
        )

    return render_template("wishlists.html", my_wishlists=my_wishlists, public_wishlists=public_wishlists)


@app.route("/wishlists/add", methods=["GET", "POST"])
@login_required
def add_wishlist():
    if request.method == "POST":
        title = request.form["title"]
        is_private = True if request.form.get("is_private") else False
        wishlist = Wishlist(title=title, is_private=is_private, user_id=current_user.id)
        db.session.add(wishlist)
        db.session.commit()
        return redirect(url_for("wishlists"))
    return render_template("add_wishlist.html")


@app.route("/wishlists/delete/<int:wishlist_id>")
@login_required
def delete_wishlist(wishlist_id):
    wishlist = Wishlist.query.get(wishlist_id)
    if wishlist and wishlist.user_id == current_user.id:
        db.session.delete(wishlist)
        db.session.commit()
    return redirect(url_for("wishlists"))


@app.route("/family", methods=["GET", "POST"])
@login_required
def family():
    if request.method == "POST":
        family_name = request.form["family_name"]
        family = Family(name=family_name, owner_id=current_user.id)
        db.session.add(family)
        db.session.commit()

        member = FamilyMember(user_id=current_user.id, family_id=family.id, role="owner")
        db.session.add(member)
        db.session.commit()
        return redirect(url_for("profile"))
    return render_template("family.html")


@app.route("/callback")
def callback():
    flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/calendar.events"
    ],
    state=session["state"],  # ← ось це ключ
    redirect_uri=url_for("callback", _external=True),
)

    flow.fetch_token(authorization_response=request.url)




    credentials = flow.credentials
    session["credentials"] = {
    "token": credentials.token,
    "refresh_token": credentials.refresh_token,
    "token_uri": credentials.token_uri,
    "client_id": credentials.client_id,
    "client_secret": credentials.client_secret,
    "scopes": credentials.scopes
}

    request_session = google.auth.transport.requests.Request()
    id_info = id_token.verify_oauth2_token(credentials.id_token, request_session, config_module.GOOGLE_CLIENT_ID)

    user = User.query.filter_by(email=id_info["email"]).first()
    if not user:
        user = User(email=id_info["email"], name=id_info["name"])
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for("profile"))

@app.route("/profile")
@login_required
def profile():
    # Знаходимо родину користувача
    member = FamilyMember.query.filter_by(user_id=current_user.id).first()
    family_members = []

    if member:
        # Усі члени цієї родини
        family_members = (
            db.session.query(User)
            .join(FamilyMember)
            .filter(FamilyMember.family_id == member.family_id)
            .all()
        )
        user_notes = Note.query.filter_by(user_id=current_user.id).all()
        my_wishlists = Wishlist.query.filter_by(user_id=current_user.id).all()
        public_wishlists = []
    if member:
        public_wishlists = (
            Wishlist.query
            .join(User)
            .join(FamilyMember)
            .filter(
                Wishlist.user_id != current_user.id,
                Wishlist.is_private == False,
                FamilyMember.family_id == member.family_id
            )
            .all()
        )
    return render_template("profile.html", family_members=family_members,notes=user_notes,my_wishlists=my_wishlists,
        public_wishlists=public_wishlists)


@app.route("/create_event", methods=["GET", "POST"])
@login_required
def create_event():
    if "credentials" not in session:
        return redirect(url_for("login"))  # або показати повідомлення

    if request.method == "POST":
        creds = Credentials(
            token=session["credentials"]["token"],
            refresh_token=session["credentials"].get("refresh_token"),
            token_uri=session["credentials"]["token_uri"],
            client_id=session["credentials"]["client_id"],
            client_secret=session["credentials"]["client_secret"],
            scopes=session["credentials"]["scopes"],
        )

        service = build("calendar", "v3", credentials=creds)
        # 1. Знаходимо родину користувача
        family_member = FamilyMember.query.filter_by(user_id=current_user.id).first()
        attendees = []
        if family_member:
            family_id = family_member.family_id
            # 2. Збираємо email-и членів родини
            members = (
                db.session.query(User.email)
                .join(FamilyMember, User.id == FamilyMember.user_id)
                .filter(FamilyMember.family_id == family_id)
                .all()
            )
            attendees = [{"email": email} for (email,) in members if email != current_user.email]

      
    
        start = request.form["start"]
        end = request.form["end"]

            # Додаємо секунди, якщо їх нема
        if len(start) == 16:
            start += ":00"
        if len(end) == 16:
            end += ":00"

        event = {
        "summary": request.form["title"],
        "description": request.form["description"],
        "start": {"dateTime": start, "timeZone": "Europe/Kyiv"},
        "end": {"dateTime": end, "timeZone": "Europe/Kyiv"},
        "attendees": attendees,
        }


        service.events().insert(calendarId="primary", body=event, sendUpdates="all").execute()
        return redirect(url_for("profile"))

    return render_template("create_event.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

