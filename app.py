import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    """Show portfolio of stocks"""
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    holdings = db.execute("SELECT username, symbol, name, shares, price, total FROM holdings WHERE username = ?", username)
    total = 0
    for row in holdings:
        if row["username"] == username:
            total += row["total"]
        row["total"] = usd(row["total"])

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    total = usd(total + cash)
    cash = usd(cash)
    return render_template("index.html", holdings=holdings, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("/buy.html")
    else:
        symbol = request.form.get("symbol")
        nr = request.form.get("shares")
        try:
            nr = (int)(nr)
        except ValueError:
            return apology("INVALID SHARES NUMBER")
        if not lookup(symbol):
            return apology("INVALID SYMBOL")
        if nr < 1:
            return apology("INVALID SHARES NUMBER")

        stocks = lookup(symbol)
        name = stocks["name"]
        price = stocks["price"]
        symbol = stocks["symbol"]
        total = (int)(price) * nr
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        if cash[0]["cash"] < total:
            return apology("Insufficient funds")
        username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash[0]["cash"] - total, session["user_id"])
        db.execute("INSERT INTO transactions (username, symbol, shares, type, price, time) VALUES (?, ?, ?, ?, ?, ?)",
                   username[0]["username"], symbol, nr, "buy", usd(stocks["price"]), datetime.now())
        if not db.execute("SELECT * FROM holdings WHERE username = ? AND symbol = ?",
                          username[0]["username"], symbol):
            db.execute("INSERT INTO holdings (username, symbol, name, shares, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                       username[0]["username"], symbol, name, nr, usd(stocks["price"]), total)
        else:
            db.execute("UPDATE holdings SET shares = shares + ?, total = total + ? WHERE username = ? AND symbol = ?",
                       nr, total, username[0]["username"], symbol)

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    transactions = db.execute("SELECT symbol, type, shares, price, time FROM transactions WHERE username = ?", username)
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        stocks = lookup(request.form.get("symbol"))
        if not stocks:
            return apology("INVALID SYMBOL")
        else:
            return render_template("quoted.html", name=stocks["name"], price=usd(stocks["price"]), symbol=stocks["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")
        if not username:
            return apology("must provide username")
        if not password:
            return apology("must provide password")
        if not confirm_password:
            return apology("must provide password confirmation")
        usernames_list = db.execute("SELECT username FROM users")
        for name in usernames_list:
            if username == name["username"]:
                return apology("username is taken")
        if password != confirm_password:
            return apology("passwords are not the same")
        hashed_passwrd = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_passwrd)
        return redirect("/login")
    else:

        return render_template("/register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    holdings = db.execute("SELECT symbol, shares FROM holdings WHERE username = ?", username)
    if request.method == "GET":
        return render_template("sell.html", stocks=holdings)
    else:
        symbol = request.form.get("symbol")
        nr = int(request.form.get("shares"))
        valid_symbol = -1
        valid_nr = -1
        for row in holdings:
            if row["symbol"] == symbol:
                valid_symbol = 1
                if row["shares"] >= nr:
                    valid_nr = 1
        if valid_symbol == -1:
            return apology("invalid symbol")
        if nr < 1:
            return apology("invalid number of shares")
        if valid_nr == -1:
            return apology("insufficient shares owned")

        stocks = lookup(symbol)

        db.execute("INSERT INTO transactions (username, symbol, shares, type, price, time) VALUES (?, ?, ?, ?, ?, ?)",
                   username, symbol, nr, "sell", usd(stocks["price"]), datetime.now())
        db.execute("UPDATE holdings SET shares = shares - ?, total = total - ? WHERE username = ? AND symbol = ?",
                   nr, nr * (int)(stocks["price"]), username, symbol)
        db.execute("DELETE FROM holdings WHERE shares = 0")

        total = nr * (int)(stocks["price"])
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total, session["user_id"])
        return redirect("/")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add cash"""
    if request.method == "GET":
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        return render_template("add.html", cash=usd(cash[0]["cash"]))
    else:
        amount = request.form.get("cash")

        try:
            amount = (int)(amount)
        except ValueError:
            return apology("Invalid amount")

        if amount < 1:
            return apology("Invalid amount")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, session["user_id"])
        return redirect("/")
