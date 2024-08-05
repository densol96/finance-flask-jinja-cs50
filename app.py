import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    user_data = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    if len(user_data) != 1:
        return apology(f'No user with the id of {user_id}', 404)

    cash = user_data[0]["cash"]

    symbols_data = db.execute("SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE customer_id = ? GROUP BY symbol", user_id)
    for_render = []
    total_stock = 0
    for symbol in symbols_data:
        if symbol["total_shares"] == 0:
            continue
        row = {}
        row["symbol"] = symbol["symbol"]
        row["shares"] = symbol["total_shares"]
        row["price"] = lookup(symbol["symbol"])["price"]
        total = row["price"] * row["shares"]
        row["total"] = usd(total)
        for_render.append(row)
        total_stock += total
    return render_template("index.html", data=for_render, cash=usd(cash), total=usd(total_stock + cash))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        try:
            shares = int(request.form.get("shares"))
            if not symbol or shares < 1:
                raise Exception("Invalid symbol and/or shares input")
            symbol = symbol.upper()
        except:
            return apology("Invalid symbol and/or shares input", 400)
        result = lookup(symbol)
        if not result:
            return apology("No such symbol", 400)
        price = result["price"]
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if len(rows) != 1:
            return apology("User unavailable", 400)
        available = rows[0]["cash"]
        want = price * shares
        if(available < want):
            return apology("Not enough funds", 400)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", available - want, session["user_id"])
        db.execute("INSERT INTO transactions (customer_id, symbol, price, shares, total) VALUES (?, ?, ?, ?, ?)", session["user_id"], symbol, price, shares, want)
        return redirect("/")

@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE customer_id = ?", user_id)
    return render_template("history.html", transactions=transactions)

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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Invalid form request", 400)
        result = lookup(symbol)
        if not result:
            return apology("Invalid symbol", 400)
        return render_template("quoted.html", quote=result)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("Invalid username", 400)
        if not password or not confirmation or password != confirmation:
            return apology("Invalid password / confirmation", 400)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        except ValueError as e:
            return apology("Duplicate username", 400)
        return redirect("/login")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    user_id = session["user_id"]
    if request.method == "GET":
        transactions = db.execute("SELECT symbol, SUM(shares) AS shares_total FROM transactions WHERE customer_id = ? GROUP BY symbol", user_id)
        symbols = [data["symbol"] for data in transactions if data["shares_total"] != 0]
        return render_template("sell.html", stocks=symbols)
    else:
        symbol = request.form.get("symbol")
        try:
            shares = int(request.form.get("shares"))
            if not symbol or not shares or shares < 1:
                raise Exception("Error")
        except:
            return apology("Missing / invalid symbol / shares", 400)

        shares_db = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE customer_id = ? AND symbol = ?", user_id, symbol)

        if len(shares_db) != 1 or shares_db[0]["shares"] < shares:
            return apology("Not enough shares", 400)

        result = lookup(symbol)
        if not result:
            return apology("No such symbol", 400)
        current_price = result["price"]
        sold_for = current_price * shares
        db.execute("INSERT INTO transactions (customer_id, symbol, price, shares, total) VALUES (?, ?, ?, ?, ?)", user_id, symbol, current_price, -1 * shares, sold_for)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sold_for, user_id)
        return redirect("/")

# Allow users to change their passwords.
@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("password.html")
    else:
        current_password = request.form.get("old")
        new_password = request.form.get("new")
        confirm_password = request.form.get("confirmation")
        
        if not current_password or not new_password or not confirm_password:
            return apology("Invalid input", 400)

        if new_password != confirm_password:
            return apology("Passwords do not match", 400)

        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if len(user) != 1:
            return redirect("/login")

        if not check_password_hash(user[0]["hash"], current_password):
            return apology("Current password invalid", 400)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password) ,session["user_id"])
        return redirect("/login")

