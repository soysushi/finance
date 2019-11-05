import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Load purchase history into memory
    # Index requires existing shares (shares not equal 0), stocks is a list containing dicts
    stocks = db.execute("SELECT UPPER(symbol) AS symbol, SUM(shares) AS total_shares, price FROM history WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
                        user_id=session["user_id"])

    # declaring a dict literal to hold the return values of lookup (which are key value pairs)
    current_quote = {}
    total = 0
    # assign a key for each of the key values for each stock (encasulated)
    for stock in stocks:
        current_quote[stock["symbol"]] = lookup(stock["symbol"])
        total += (stock["total_shares"] * current_quote[stock["symbol"]]["price"])
    # attain current cash
    user = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    cash_left = user[0]["cash"]
    total = total + cash_left

    return render_template("index.html", current_quote=current_quote, stocks=stocks, cash_left=cash_left, total=total)

    return apology("something went wrong")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if not quote:
            return apology("stock does not exist", 400)

        try:
            num_of_shares = int(request.form.get("shares"))
        except:
            return apology("shares must be a positive integer", 400)
        if num_of_shares <= 0:
            return apology("shares must be a positive integer", 400)

        total_cost = int(num_of_shares) * quote["price"]
        cash = db.execute("SELECT cash FROM users where id = :user_id", user_id=session["user_id"])
        if total_cost > cash[0]["cash"]:
            return apology("you don't have enough cash", 400)
        else:
            # insert into history
            db.execute("INSERT INTO history (user_id, symbol, shares, price, transacted) VALUES(:user_id, :symbol, :shares, :price, :transacted)",
                       user_id=session["user_id"],
                       symbol=request.form.get("symbol"),
                       shares=num_of_shares,
                       price=total_cost,
                       transacted=datetime.now())

            # purchase the stock
            db.execute("UPDATE users SET cash = cash - :total_cost WHERE id = :user_id",
                       total_cost=total_cost, user_id=session["user_id"])
        return redirect("/")

    else:
        return render_template("buy.html")
    return apology("SOMETHING'S WRONG!")


@app.route("/check", methods=["GET"])
def check():
    # Check the http parameter for username.
    username = request.args.get("username")

    check = db.execute("SELECT username FROM users WHERE username = :username", username=username)

    if not check:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Load purchase history into memory
    # Index requires existing shares (shares not equal 0), stocks is a list containing dicts
    stocks = db.execute("SELECT UPPER(symbol) AS symbol, shares, price, transacted FROM history WHERE user_id = :user_id GROUP BY transacted",
                        user_id=session["user_id"])

    return render_template("history.html", stocks=stocks)

    return apology("something went wrong")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("stock does not exist", 400)

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")

    return apology("TODO")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password"""
    if request.method == "POST":

        if not request.form.get("password"):
            return apology("must provide password", 400)
        if not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        # Ensure password and confirmation match
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("passwords do not match", 400)

        # store hashed password
        hash = generate_password_hash(password)
        # Store hashed password into database
        result = db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)
        # Log User out and Redirect to Login Page
        session.clear()
        return redirect("/")
    else:
        return render_template("change.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # POST request
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)
        if not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        # Ensure password and confirmation match
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("passwords do not match", 400)

        # store hashed password
        hash = generate_password_hash(password)
        # Store hashed password into database
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                            username=request.form.get("username"), hash=hash)
        if not result:
            return apology("username is taken", 400)
        # Log the user in
        session["user_id"] = result
        # Redirect user to home page and allow them to buy stocks
        return redirect("/")

    # GET request
    else:
        return render_template("register.html")

    return apology("everything failed", 403)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # load stock information based on user input, symbol
        stock = db.execute("SELECT UPPER(symbol) AS symbol, SUM(shares) AS total_shares, price FROM history WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
                           user_id=session["user_id"], symbol=request.form.get("symbol"))
        # if the input is not a positive integer or if the user does not own that many shares of the stock or any of the stock
        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("Please input a positive integer", 400)
        if stock[0]["total_shares"] < shares:
            return apology("You do not have that many shares to sell", 400)
        if stock[0]["total_shares"] <= 0:
            return apology("You do not have any shares to sell", 400)

        # if all error checking is good, calculate how much it is and update user history
        quote = lookup(request.form.get("symbol"))
        total_cost = shares * quote["price"]

        db.execute("UPDATE users SET cash = cash + :price WHERE id = :user_id", price=total_cost, user_id=session["user_id"])
        db.execute("INSERT INTO history (user_id, symbol, shares, price, transacted) VALUES(:user_id, :symbol, :shares, :price, :transacted)",
                   user_id=session["user_id"],
                   symbol=request.form.get("symbol"),
                   shares=-shares,
                   price=total_cost,
                   transacted=datetime.now())
        return redirect("/")

    else:
        stocks = db.execute("SELECT UPPER(symbol) AS symbol, SUM(shares) AS total_shares, price FROM history WHERE user_id = :user_id GROUP BY symbol HAVING total_shares > 0",
                            user_id=session["user_id"])
        return render_template("sell.html", stocks=stocks)

    return apology("someting went wrong")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
