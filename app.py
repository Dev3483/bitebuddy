from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from xhtml2pdf import pisa
from io import BytesIO
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from werkzeug.security import generate_password_hash
import random
import string
import os
from bidi.algorithm import get_display
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bitebuddy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    razorpay_order_id = db.Column(db.String(100), nullable=False)
    razorpay_payment_id = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='orders', lazy=True)
    items = db.relationship('OrderItem', backref='order', lazy=True)


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    food = db.relationship('Food', backref='order_items')


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    cart = db.relationship('CartItem', backref='user', lazy=True)
    favourites = db.relationship('FavouriteItem', backref='user', lazy=True)
    history = db.relationship('PurchaseHistory', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'


class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category=db.Column(db.String(100),nullable=False)
    image = db.Column(db.String(200), nullable=False)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    quantity=db.Column(db.Integer,nullable=False)
    food = db.relationship('Food', backref='cart_items')


class FavouriteItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    food = db.relationship('Food', backref='favourite_items')


class PurchaseHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    food = db.relationship('Food', backref='history_items')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/findrestaurant")
def findrestaurant():
    api_key = os.getenv('MAPTILER_API_KEY')
    return render_template("findrestaurant.html", api_key=api_key)

@app.route("/profile")
def profile():
    return render_template("profile.html")


@app.route('/update_address', methods=['GET', 'POST'])
@login_required
def update_address():
    if request.method == 'POST':
        new_address = request.form.get('address')
        current_user.address = new_address
        db.session.commit()
        flash('Address updated successfully!', 'success')
        # Redirect to a profile page or any other relevant page
        return redirect(url_for('profile'))
    return render_template('update_address.html')


@app.route('/signup', methods=['POST'])
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    first_name = request.form.get('fname')
    last_name = request.form.get('lname')
    password = request.form.get('password')

    # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        password=password
    )

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))


@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
    } for user in users])


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password== password:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)


@app.route("/main")
@login_required
def main():
    foods = Food.query.all()
    for food in foods:
        print(
            f'ID: {food.id}, Name: {food.name}, Price: {food.price}, Image: {food.image}')
    return render_template('main.html', foods=foods)


@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            otp = ''.join(random.choices(
                string.ascii_uppercase + string.digits, k=6))
            session['otp'] = otp
            session['email'] = email
            try:
                msg = Message(
                    'Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your OTP is {otp}'
                mail.send(msg)
                flash('An OTP has been sent to your email address.', 'info')
                return redirect(url_for('verify_otp'))
            except Exception as e:
                flash('Failed to send email.', 'danger')
                print('Error: ', e)
        else:
            flash('Email not found.', 'danger')
    return render_template('forgotpassword.html')

# Route to verify OTP


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'otp' in session and session['otp'] == otp:
            flash(
                'OTP verified successfully. You can now reset your password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify_otp.html')

# Route to reset password


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        password = request.form['password']
        if 'email' in session:
            email = session['email']
            user = User.query.filter_by(email=email).first()
            if user:
                user.password = password
                db.session.commit()
                session.pop('otp', None)
                session.pop('email', None)
                flash('Password has been updated.', 'success')
                return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/add_to_cart/<int:food_id>', methods=['POST'])
@login_required
def add_to_cart(food_id):
    # Default quantity to 1 if not provided
    quantity = request.form.get('quantity', 1)
    cart_item = CartItem(user_id=current_user.id,
                         food_id=food_id, quantity=int(quantity))
    db.session.add(cart_item)
    db.session.commit()
    return redirect(url_for('main'))


@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        msg = Message('Contact Us Message',
                      sender=email,
                      recipients=['bitebuddy56@gmail.com'],
                      body=f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}")
        mail.send(msg)

        flash('Message sent successfully!', 'success')
        return redirect(url_for('contactus'))

    return render_template('contactus.html')

@app.route('/like_food/<int:food_id>', methods=['POST'])
@login_required
def like_food(food_id):
    favourite_item = FavouriteItem(user_id=current_user.id, food_id=food_id)
    db.session.add(favourite_item)
    db.session.commit()
    print(food_id)
    return redirect(url_for('main'))


@app.route('/cart/increase/<int:cart_item_id>', methods=['POST'])
@login_required
def increase_cart_item(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        abort(403)
    cart_item.quantity += 1
    db.session.commit()
    return redirect(url_for('cart'))



@app.route('/cart/decrease/<int:cart_item_id>', methods=['POST'])
@login_required
def decrease_cart_item(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        abort(403)
    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        db.session.commit()
    else:
        flash('Quantity cannot be less than 1.', 'warning')
    return redirect(url_for('cart'))


@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.food.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


@app.route('/delete_cart/<int:cart_item_id>', methods=['POST'])
def delete_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    db.session.delete(cart_item)
    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/favourite')
@login_required
def favourites():
    favourite_items = FavouriteItem.query.filter_by(
        user_id=current_user.id).all()
    return render_template('favourite.html', favourite_items=favourite_items)


@app.route('/delete_favourite/<int:favourite_id>', methods=['POST'])
@login_required
def delete_favourite(favourite_id):
    favourite_item = FavouriteItem.query.get_or_404(favourite_id)
    if favourite_item.user_id != current_user.id:
        abort(403)  # Forbidden

    db.session.delete(favourite_item)
    db.session.commit()
    flash('Favourite item deleted!', 'success')
    return redirect(url_for('favourites'))


@app.route('/history')
@login_required
def history():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', orders=orders)



@app.route('/checkout')
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    for item in cart_items:
        history_item = PurchaseHistory(
            user_id=current_user.id, food_id=item.food_id)
        db.session.add(history_item)
        db.session.delete(item)
    db.session.commit()
    return redirect(url_for('history'))


@app.route('/bill')
def bill():
    cart_items = CartItem.query.all()
    total_price = sum(item.food.price for item in cart_items)
    return render_template('bill.html', cart_items=cart_items, total_price=total_price)


@app.route('/dummy_payment', methods=['GET', 'POST'])
@login_required
def dummy_payment():
    if request.method == 'POST':
        payment_id = 'DUMMY_PAY_' + str(current_user.id) + '_12345'
        order_id = 'DUMMY_ORDER_' + str(current_user.id) + '_12345'

        try:
            amount = float(request.form['amount'])
        except ValueError:
            flash('Invalid amount. Please enter a valid number.', 'danger')
            return redirect(url_for('dummy_payment'))

        new_order = Order(
            user_id=current_user.id,
            razorpay_order_id=order_id,
            razorpay_payment_id=payment_id,
            amount=amount
        )
        db.session.add(new_order)
        db.session.commit()

        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        for item in cart_items:
            order_item = OrderItem(
                order_id=new_order.id,
                food_id=item.food_id,
                quantity=item.quantity,
                price=item.food.price
            )
            db.session.add(order_item)
            db.session.delete(item)  # Remove item from cart
        db.session.commit()

        flash('Payment successful! Your order has been placed.', 'success')
        return redirect(url_for('history'))

    return render_template('dummy_payment.html')



@app.route('/download_bill')
@login_required
def download_bill():
    order = Order.query.filter_by(
        user_id=current_user.id).order_by(Order.id.desc()).first()

    if order is None:
        flash('No order found for the current user.', 'danger')
        return redirect(url_for('main'))

    order_items = OrderItem.query.filter_by(order_id=order.id).all()
    total_price = sum(item.price * item.quantity for item in order_items)

    html = render_template('bill.html', cart_items=order_items, total_price=total_price,order_id=order.razorpay_order_id,payment_id=order.razorpay_payment_id, user=current_user)

    result = BytesIO()
    pisa_status = pisa.CreatePDF(BytesIO(html.encode('UTF-8')), dest=result)

    if pisa_status.err:
        current_app.logger.error('Error generating PDF: %s', pisa_status.err)
        return 'Error generating PDF'

    result.seek(0)  # Reset the BytesIO object before reading from it

    response = make_response(result.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=bill.pdf'

    return response

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                db.session.delete(user)
                db.session.commit()
                flash('Account successfully deleted.', 'success')
                logout_user()  # Logout the user after account deletion
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to delete account. Please try again.', 'danger')
                print('Error:', e)
        else:
            flash('Email not found.', 'danger')
    return render_template('delete_account.html')



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


def clear_favourites():
    db.session.query(FavouriteItem).delete()
    db.session.commit()
    print('Favourites cleared')


#if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        db.session.query(Food).delete()
        if not Food.query.first():
            initial_foods = [
                # Sandwich Section
                Food(name='Veg Sandwich', price=70.00,category='Sandwiches',image='assets/veg-sandwich.jpg'),
                Food(name='Potato Sandwich', price=100.00, category='Sandwiches',image='assets/potato-cheese-sandwich.jpg'),
                Food(name='Grilled Caprese Panini', price=120.00,category='Sandwiches', image='assets/panini.jpg'),
                Food(name='Italian Toasted Sandwich', price=140.00,category='Sandwiches', image='assets/italian.jpg'),
                Food(name='Avocado Sandwich', price=150.00,category='Sandwiches', image='assets/avocado-sand.jpg'),
                # Indian Chinese
                Food(name='Chilli Paneer', price=150.00,category='Indian Chinese', image='assets/Chilli-Paneer.jpg'),
                Food(name='Chilli Potato', price=120.00,category='Indian Chinese', image='assets/chilli-potato.jpg'),
                Food(name='Veg Manchurian', price=100.00,category='Indian Chinese', image='assets/Veg-Manchurian.jpg'),
                Food(name='Tomato Soup', price=60.00,category='Indian Chinese', image='assets/tomato.jpg'),
                Food(name='Noodels', price=90.00,category='Indian Chinese', image='assets/noodels.jpg'),
                Food(name='Manchow Soup', price=85.00,category='Indian Chinese', image='assets/ManchowSoup.jpg'),
                Food(name='Manchurian Rice', price=130.00,category='Indian Chinese', image='assets/manchurian-rice.jpg'),
                # Indian Street Food
                Food(name='Pavbhaji', price=70.00,category='Indian Street Food', image='assets/paobhaji.jpg'),
                Food(name='Dabeli', price=100.00,category='Indian Street Food', image='assets/dabeli.jpg'),
                Food(name='Vadapav', price=120.00,category='Indian Street Food', image='assets/vadapav.jpg'),
                Food(name='Burger', price=140.00,category='Indian Street Food', image='assets/burger.jpg'),
                Food(name='Misal Pav', price=150.00,category='Indian Street Food', image='assets/misalpao.jpg'),
                Food(name='Panipuri', price=150.00,category='Indian Street Food', image='assets/panipuri.jpg'),
                Food(name='Delhi Chat', price=150.00,category='Indian Street Food', image='assets/delhichat.jpg'),
                # South Indian
                Food(name='Dosa', price=80.00,category='South Indian', image='assets/dosa.jpg'),
                Food(name='Idli', price=50.00,category='South Indian', image='assets/idli.jpg'),
                Food(name='Pongal', price=70.00,category='South Indian', image='assets/pongal.jpg'),
                Food(name='Puttu', price=60.00,category='South Indian', image='assets/puttu.jpg'),
                Food(name='Menduvada', price=60.00,category='South Indian', image='assets/vada.jpg'),
                Food(name='Appam', price=70.00,category='South Indian', image='assets/appam.jpg'),
                # Thalis
                Food(name='Gujarati Thali', price=180.00,category='Thalis', image='assets/gujaratithali.png'),
                Food(name='Maharaja Thali', price=500.00,category='Thalis', image='assets/maharaja-thali.jpg'),
                Food(name='Punjabi Thali', price=290.00,category='Thalis', image='assets/punjabithali.png'),
                Food(name='Rajasthani Thali', price=250.00,category='Thalis', image='assets/rajasthani.png'),
                # Biryani
                Food(name='Bamboo Biryani', price=200.00,category='Biryani', image='assets/bamboo-biryani.png'),
                Food(name='Dum Aloo Biryani', price=170.00,category='Biryani', image='assets/Dum-aloo-Biryani.jpg'),
                Food(name='Veg Biryani', price=150.00,category='Biryani', image='assets/veg-biryani.jpg'),
                Food(name='Pulav', price=120.00,category='Biryani', image='assets/pulao.jpg'),
                Food(name='Mug Pulav', price=140.00,category='Biryani', image='assets/mug-pulav.png'),
                # Pizza
                Food(name='California Pizza', price=350.00,category='Pizza', image='assets/california-pizza.jpg'),
                Food(name='Garlic Bread', price=120.00,category='Pizza', image='assets/Garlic-Breads.jpg'),
                Food(name='Greek Pizza', price=380.00,category='Pizza', image='assets/greek-pizza.jpg'),
                Food(name='Paneer Tikka Pizza', price=300.00,category='Pizza', image='assets/paneer-tikka-pizza.png'),
                Food(name='Margherita Pizza', price=200.00,category='Pizza', image='assets/pizza-margherita.jpg'),
                Food(name='Sicilian Pizza', price=450.00,category='Pizza', image='assets/Sicilian-Pizza.png'),
                Food(name='Veggie Pizza', price=380.00,category='Pizza', image='assets/Veggie_Pizza.jpg'),
                # North Indian
                Food(name='Rajma Chawal', price=120.00,category='North Indian', image='assets/rajma-chawal.jpg'),
                Food(name='Makke ki Roti & Sarson ki Sabji', price=130.00,category='North Indian', image='assets/make-ki-roti.JPG'),
                Food(name='Jeera Rice & Dal Fry', price=130.00,category='North Indian', image='assets/jeera-rice-dal-fry.jpg'),
                Food(name='Dal Bati', price=200.00,category='North Indian', image='assets/dal-bati.jpg'),
                Food(name='Chole Bhature', price=120.00,category='North Indian', image='assets/chole-bhature.jpg'),
                # Icecream
                Food(name='Almond Ice Cream', price=100.00,category='Icecream', image='assets/almond.jpg'),
                Food(name='Chocolate Ice Cream', price=80.00,category='Icecream', image='assets/choco.jpg'),
                Food(name='Coffee Ice Cream', price=90.00,category='Icecream', image='assets/coffeeice.jpg'),
                Food(name='Cream Ice Cream', price=70.00,category='Icecream', image='assets/creamice.jpg'),
                Food(name='Choco Chip Ice Cream', price=95.00,category='Icecream', image='assets/OIchocochip.jpg'),
                Food(name='Hazelnut Ice Cream', price=110.00,category='Icecream', image='assets/hazelnut.jpg'),
                Food(name='Pistachio Ice Cream', price=100.00,category='Icecream', image='assets/pistachio.jpg'),
                Food(name='Vanilla Ice Cream', price=75.00,category='Icecream', image='assets/vanilla.jpg'),
                # Beverages
                Food(name='Banana Milkshake', price=120.00,category='Beverages', image='assets/bananamilkshake.jpg'),
                Food(name='Cappuccino', price=60.00,category='Beverages', image='assets/cappucino.jpg'),
                Food(name='Caramel Milkshake', price=130.00,category='Beverages', image='assets/caramelmilkshake.jpg'),
                Food(name='Chocolate Milkshake', price=120.00,category='Beverages', image='assets/chocomilkshake.jpg'),
                Food(name='Cold Coffee', price=70.00,category='Beverages', image='assets/coldcoffee.jpg'),
                Food(name='Green Tea', price=50.00,category='Beverages', image='assets/greentea.jpg'),
                Food(name='Double Espresso', price=75.00,category='Beverages', image='assets/doubleespresso.png'),
                Food(name='Latte', price=80.00,category='Beverages', image='assets/latte.jpg'),
                Food(name='Lemon Tea', price=55.00,category='Beverages', image='assets/lemontea.jpg'),
                Food(name='Mocha', price=90.00,category='Beverages', image='assets/mocha.jpg'),
                Food(name='Tea', price=40.00, category='Beverages',image='assets/normaltea.jpg'),
                Food(name='Coffee', price=50.00, category='Beverages',image='assets/normalcoffee.jpg'),
                Food(name='Strawberry Milkshake', price=125.00, category='Beverages', image='assets/strawberrymilkshake.jpg')
            ]
            db.session.bulk_save_objects(initial_foods)
            db.session.commit()
            #app.run(debug=True)
