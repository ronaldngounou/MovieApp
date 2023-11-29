from flask import Flask, request, render_template, session
from flask import redirect, make_response, jsonify
from functools import wraps
import os

from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required, verify_jwt_in_request
from flask_jwt_extended import JWTManager, get_jwt_identity, get_jwt
from flask_jwt_extended import set_access_cookies


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "secretkey"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
jwt = JWTManager(app)
jwt.init_app(app)
app = Flask(__name__)
app.secret_key = "secretkey"
app.config["UPLOADED_PHOTOS_DEST"] = "static"
app.config["JWT_SECRET_KEY"] = "secretkey"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)
jwt.init_app(app)

movies = [
    {
        "id": 0,
        "title": "Doctor Strange in the Multiverse of Madness",
        "year": 2022,
        "director": "Sam Raimi",
        "writters": "Jade Halley Bartlett, Steve Ditko, Stan Lee",
        "stars": "Benedict Cumberbatch, Elizabeth Olsen, Rachel McAdams",
    },
    {
        "id": 1,
        "title": "Moonfall",
        "year": 2022,
        "director": "Roland Emmerich",
        "writters": "Spenser Cohen, Roland Emmerich, Harald Kloser",
        "stars": "Halle Berry, Patrick Wilson, John Bradley",
    },
    {
        "id": 2,
        "title": "Death on the Nile",
        "year": 2022,
        "director": "Kenneth Branagh",
        "writters": "Agatha Christie, Michael Green",
        "stars": "Kenneth Branagh, Gal Gadot, Tom Bateman",
    },
]

users = [
    {"username": "testuser", "password": "testuser", "role": "admin"},
    {"username": "John", "password": "John", "role": "reader"},
    {"username": "Anne", "password": "Anne", "role": "admin"},
    {"username": "reader", "password": "reader", "role": "reader"},
    {"username": "admin", "password": "admin", "role": "admin"}
]


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        #claims = get_jwt_claims()
        claims = get_jwt()
        print(claims)
        #if claims['role'] != 'admin':
        if claims['fresh']['role'] != 'admin':
            return jsonify(msg='Admins only'), 403
        else:
            return fn(*args, **kwargs)
    return wrapper


def checkUser(username, password):
    for user in users:
        if username in user["username"] and password in user["password"]:
            return {"username": user["username"], "role": user["role"]}
    return None


@app.route("/", methods=["GET"])
def firstRoute():
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        validUser = checkUser(username, password)
        if validUser != None:
            # set JWT token

            user_claims = {"role": validUser["role"]}
            #access_token = create_access_token(username, user_claims=user_claims)
            access_token = create_access_token(username, user_claims)

            response = make_response(
                render_template(
                    "index.html", title="movies", username=username, movies=movies
                )
            )
            response.status_code = 200
            # add jwt-token to response headers
            # response.headers.extend({"jwt-token": access_token})
            set_access_cookies(response, access_token)
            return response

    return render_template("register.html")


@app.route("/logout")
def logout():
    # invalidate the JWT token

    return "Logged Out of My Movies"


@app.route("/movies", methods=["GET"])
@jwt_required()
def getMovies():
    try:
        username = get_jwt_identity()
        return render_template('movies.html', username=username, movies=movies)
    except:
        return render_template("register.html")
    

@app.route("/addmovie", methods=["GET", "POST"])
@jwt_required()
@admin_required
def addMovie():
    username = get_jwt_identity()
    if request.method == "GET":
        return render_template("addMovie.html", username=username)
    if request.method == "POST":
        # expects pure json with quotes everywheree
        id = len(movies)
        title = request.form.get("title")
        year = request.form.get("year")
        newmovie = {"id": id, "title": title, "year": year}
        movies.append(newmovie)
        return render_template(
            "movies.html", movies=movies, username=username, title="movies"
        )
    else:
        return 400


@app.route("/addimage", methods=["GET", "POST"])
@jwt_required()
@admin_required
def addimage():
    if request.method == "GET":
        return render_template("addimage.html")
    elif request.method == "POST":
        image = request.files["image"]
        id = request.form.get("number")  # use id to number the image
        imagename = "image_" + id + ".png"
        image.save(os.path.join(app.config["UPLOADED_PHOTOS_DEST"], imagename))
        print(image.filename)
        return "image loaded"

    return "all done"


if __name__ == "__main__":
    #app.run(debug=True, host="0.0.0.0", port=5000)
    app.run(debug=True, host="127.0.0.1", port=5000)
