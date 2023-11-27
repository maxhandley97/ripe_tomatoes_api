from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy.exc import IntegrityError
from marshmallow.validate import Length
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from datetime import timedelta
app = Flask(__name__)
ma = Marshmallow(app)
bcrypt=Bcrypt(app)
jwt = JWTManager(app)

## DB CONNECTION AREA

app.config["JWT_SECRET_KEY"] = "Backend best end" 
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://tomato:123456@localhost:5432/ripe_tomatoes_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

@app.cli.command('create')
def create_db():
    db.drop_all()
    db.create_all()
    print('Tables dropped & created')

@app.cli.command('seed')
def seed_db():

    movie1 = Movie(
        title = 'Spider-Man: No Way Home',
        genre = 'Action',
        length = 148,
        year = 2021
    )
    db.session.add(movie1)

    movie2 = Movie(
        title = 'Dune',
        genre = 'Sci-fi',
        length = 155,
        year = 2021
    )
    db.session.add(movie2)

    actor1 = Actor(
        first_name = 'Tom',
        last_name = 'Holland',
        gender = 'male',
        country = 'UK'
    )
    db.session.add(actor1)

    actor2 = Actor(
        first_name = 'Marisa',
        last_name = 'Tomei',
        gender = 'female',
        country = 'USA'
    )
    db.session.add(actor2)

    actor3 = Actor(
        first_name = 'Timothee',
        last_name = 'Chalemet',
        gender = 'male',
        country = 'USA'
    )
    db.session.add(actor3)

    actor4 = Actor(
        first_name = 'Zendaya',
        last_name = '',
        gender = 'female',
        country = 'USA'
    )
    db.session.add(actor4)

    admin_user = User(
        email = 'admin@py.py',
        password = bcrypt.generate_password_hash('password123').decode('utf8'),
        admin = True
    )
    db.session.add(admin_user)

    user_1 = User(
        email = 'user@py.py',
        password = bcrypt.generate_password_hash('123456789').decode('utf8'),
        admin = False
    )
    db.session.add(user_1)

   
    db.session.commit()
    print('Tables seeded') 



@app.route('/auth/signup', methods=['POST'])   

def auth_signup():
    try:
        user_fields = UserSchema(exclude=['id', 'admin']).load(request.json)
        stmt = db.select(User).filter_by(email=request.json['email'])
        user = db.session.scalar(stmt)
        user = User(
            email=user_fields['email'],
            password=bcrypt.generate_password_hash(user_fields['password']).decode('utf8'),
            admin=False
        )
        db.session.add(user)
        db.session.commit()
        expiry = timedelta(days=1)
        access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
        return jsonify({"user":user.email, "token": access_token })
        # return UserSchema().dump(user), 201
    except IntegrityError:
        return {'error': 'Email already exists'}, 409

@app.route('/auth/signin', methods=['POST'])
def auth_signin():
    user_fields = user_schema.load(request.json)
    stmt = db.select(User).filter_by(email=request.json['email'])
    user = db.session.scalar(stmt)
    if not user or not bcrypt.check_password_hash(user.password, user_fields["password"]):
        return abort(401, description="Incorrect username and password")
    expiry = timedelta(days=1)
    access_token = create_access_token(identity=str(user.id), expires_delta=expiry)
    return jsonify({"user":user.email, "token": access_token })




# MODELS AREA
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    admin = db.Column(db.Boolean(), nullable=False)


class Movie(db.Model):
    __tablename__= 'movies'
    id = db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String())
    genre = db.Column(db.String())
    length = db.Column(db.Integer())
    year = db.Column(db.Integer())

class Actor(db.Model):
    __tablename__= 'actors'
    id = db.Column(db.Integer,primary_key=True)  
    first_name = db.Column(db.String())
    last_name = db.Column(db.String())
    gender = db.Column(db.String())
    country = db.Column(db.String())

# SCHEMAS AREA
class UserSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'admin')
        password = ma.String(validate=Length(min=8))
    
user_schema = UserSchema()
users_schema = UserSchema(many=True)

class MovieSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'genre', 'length', 'year')

movie_schema = MovieSchema()
movies_schema = MovieSchema(many=True)

class ActorSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'gender', 'country')

actor_schema = ActorSchema()
actors_schema = ActorSchema(many=True)


# ROUTING AREA

@app.route('/')
def hello():
  return 'Welcome to Ripe Tomatoes API'

@app.route('/actors', methods=['GET'])
def get_actors():
    stmt = db.select(Actor)
    actors = db.session.scalars(stmt)
    return actors_schema.dump(actors)

@app.route('/movies', methods=['GET'])
def get_movies():
    stmt = db.select(Movie)
    movies = db.session.scalars(stmt)
    return movies_schema.dump(movies)

@app.route('/movies', methods=['POST'])
@jwt_required()
def add_movie():
    movie_fields = movie_schema.load(request.json)
    new_movie = Movie()
    new_movie.title=movie_fields['title'],
    new_movie.genre=movie_fields['genre'],
    new_movie.length=movie_fields['length'],
    new_movie.year=movie_fields['year']
    
    db.session.add(new_movie)
    db.session.commit()
    return jsonify(movie_schema.dump(new_movie))

@app.route('/movies/<movieId>', methods=['DELETE'])
@jwt_required()
def delete_user(movieId):
    #Parse incoming POST body through schema
    #Parse incoming POST body through schema
    Movie.query.filter_by(id=movieId).delete()
    
    if not movieId or not bcrypt.check_password_hash(user.password, user_fields["password"]):
        return abort(401, description="Incorrect username and password")
   
    db.session.commit()

    return "Successful deletion", 201 #return the n
    # print(request.json) - used for 
