from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ========== MODELS ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)  # Added department

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='unassigned')  # available, assigned, unusable
    assigned_to = db.Column(db.String(100), nullable=True)
    assigned_date = db.Column(db.DateTime, nullable=True)

class ReturnedAsset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, nullable=False)
    returned_by = db.Column(db.String(100))
    condition = db.Column(db.String(100))  # usable or unusable
    returned_date = db.Column(db.DateTime, default=datetime.utcnow)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    users = db.relationship('User', backref='department', lazy=True)


# ========== ROUTES ==========
@app.route('/')
def home():
    if 'user' not in session:
        return redirect('/login')
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user'] = user.username
            return redirect('/')
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return 'Username already exists'
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/add_asset', methods=['GET', 'POST'])
def add_asset():
    if 'user' not in session:
        return redirect('/login')
    if request.method == 'POST':
        asset = Asset(category=request.form['category'], name=request.form['name'])
        db.session.add(asset)
        db.session.commit()
        return redirect('/add_asset')
    return render_template('add_asset.html')

@app.route('/assign_asset', methods=['GET', 'POST'])
def assign_asset():
    if 'user' not in session:
        return redirect('/login')

    available_assets = Asset.query.filter_by(status='unassigned').all()

    if request.method == 'POST':
        category = request.form['category']
        user = request.form['assigned_to']

        existing_assignment = Asset.query.filter_by(assigned_to=user, category=category, status='assigned').first()
        if existing_assignment:
            return 'User must return the current asset before getting another in the same category.'

        asset_id = request.form['asset_id']
        asset = Asset.query.get(asset_id)
        if asset and asset.status == 'unassigned':
            asset.status = 'assigned'
            asset.assigned_to = user
            asset.assigned_date = datetime.utcnow()
            db.session.commit()
            return redirect('/assign_asset')
        return 'Asset not available'

    return render_template('assign_asset.html', assets=available_assets)

@app.route('/return_asset', methods=['GET', 'POST'])
def return_asset():
    if 'user' not in session:
        return redirect('/login')

    assigned_assets = Asset.query.filter_by(status='assigned').all()

    if request.method == 'POST':
        asset_id = request.form['asset_id']
        condition = request.form['condition']

        asset = Asset.query.get(asset_id)
        if asset:
            returned = ReturnedAsset(
                asset_id=asset.id,
                returned_by=asset.assigned_to,
                condition=condition,
                returned_date=datetime.utcnow()
            )
            db.session.add(returned)

            if condition == 'usable':
                asset.status = 'unassigned'
            else:
                asset.status = 'unusable'
            asset.assigned_to = None
            asset.assigned_date = None

            db.session.commit()
            return redirect('/return_asset')

    return render_template('return_asset.html', assets=assigned_assets)

@app.route('/report')
def report():
    if 'user' not in session:
        return redirect('/login')

    # Fetch all assets that are assigned
    assigned_assets = Asset.query.filter_by(status='assigned').all()

    # Prepare the report data
    report_data = []
    for asset in assigned_assets:
        report_data.append({
            'asset_name': asset.name,
            'category': asset.category,
            'assigned_to': asset.assigned_to,
            'assigned_date': asset.assigned_date
        })

    total_assets = Asset.query.count()
    assigned_assets_count = len(report_data)  # Count assigned assets
    unassigned_assets = Asset.query.filter_by(status='unassigned').count()
    unusable_assets = Asset.query.filter_by(status='unusable').count()

    return render_template('report.html', total=total_assets, assigned=assigned_assets_count,
                           unassigned=unassigned_assets, unusable=unusable_assets, report_data=report_data)


# ========== INITIALIZE ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)