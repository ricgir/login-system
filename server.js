require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");

const app = express();

/* ---------- MIDDLEWARE ---------- */

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "secretkey",
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());


/* ---------- DATABASE ---------- */

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error("Database connection failed:", err);
        return;
    }
    console.log("MySQL Connected");
});


/* ---------- GOOGLE AUTH STRATEGY ---------- */

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
},
function(accessToken, refreshToken, profile, done) {

    const username = profile.displayName;

    const sql = "SELECT * FROM users WHERE username=?";

    db.query(sql, [username], (err, results) => {

        if (err) return done(err);

        if (results.length === 0) {

            const insert = "INSERT INTO users(username,password) VALUES (?,?)";

            db.query(insert, [username, "google"], (err) => {
                if (err) return done(err);
                return done(null, profile);
            });

        } else {
            return done(null, profile);
        }

    });

}));


passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});


/* ---------- PAGE ROUTES ---------- */

app.get("/", (req, res) => {
    res.redirect("/login");
});

app.get("/login", (req, res) => {
    res.sendFile(__dirname + "/public/login.html");
});

app.get("/signup", (req, res) => {
    res.sendFile(__dirname + "/public/signup.html");
});


/* ---------- GOOGLE LOGIN ROUTES ---------- */

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {

        res.send(`
        <html>
        <head><link rel="stylesheet" href="/style.css"></head>
        <body class="center">
        <div class="box">
        <h2>Google Login Successful 🎉</h2>
        </div>
        </body>
        </html>
        `);

    }
);


/* ---------- SIGNUP ---------- */

app.post("/signup", async (req, res) => {

    const { username, password } = req.body;

    try {

        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = "INSERT INTO users (username,password) VALUES (?,?)";

        db.query(sql, [username, hashedPassword], (err) => {

            if (err) {
                return res.send(`
                <html>
                <head><link rel="stylesheet" href="/style.css"></head>
                <body class="center">
                <div class="box">
                <h2>User already exists ❌</h2>
                <a class="btn" href="/signup">Try Again</a>
                </div>
                </body>
                </html>
                `);
            }

            res.send(`
            <html>
            <head><link rel="stylesheet" href="/style.css"></head>
            <body class="center">
            <div class="box">
            <h2>Signup Successful ✅</h2>
            <a class="btn" href="/login">Go to Login</a>
            </div>
            </body>
            </html>
            `);

        });

    } catch (error) {
        res.send("Error creating user");
    }

});


/* ---------- LOGIN ---------- */

app.post("/login", (req, res) => {

    const { username, password } = req.body;

    const sql = "SELECT * FROM users WHERE username=?";

    db.query(sql, [username], async (err, results) => {

        if (err) return res.send("Database error");

        if (results.length === 0) {
            return res.send(`
            <html>
            <head><link rel="stylesheet" href="/style.css"></head>
            <body class="center">
            <div class="box">
            <h2>User not found ❌</h2>
            <a class="btn" href="/login">Try Again</a>
            </div>
            </body>
            </html>
            `);
        }

        const user = results[0];

        const match = await bcrypt.compare(password, user.password);

        if (match) {

            res.send(`
            <html>
            <head><link rel="stylesheet" href="/style.css"></head>
            <body class="center">
            <div class="box">
            <h2>Login Successful 🎉</h2>
            </div>
            </body>
            </html>
            `);

        } else {

            res.send(`
            <html>
            <head><link rel="stylesheet" href="/style.css"></head>
            <body class="center">
            <div class="box">
            <h2>Invalid Password ❌</h2>
            <a class="btn" href="/login">Try Again</a>
            </div>
            </body>
            </html>
            `);

        }

    });

});


/* ---------- SERVER ---------- */

app.listen(process.env.PORT, () => {
    console.log(`Server running on http://localhost:${process.env.PORT}`);
});