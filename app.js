/////// app.js

const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
require('dotenv').config()
const { body, validationResult } = require("express-validator");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb = process.env.MONGODB_URL;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    full_name: { type: String, required: true},
    username: { type: String, required: true },
    password: { type: String, required: true },
    membership_status: { type: Boolean, required: true}
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

passport.use(
    new LocalStrategy((username, password, done) => {
      User.findOne({ username: username }, (err, user) => {
        if (err) { 
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        if (bcrypt.compare(password, user.password, (err, res) => {
            if (res) {
              // passwords match! log user in
              return done(null, user)
            } else {
              // passwords do not match!
              return done(null, false, { message: "Incorrect password" })
            }
          })
        )
        return done(null, user);
      });
    })
);

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
});

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

app.get("/", (req, res) => {
    res.render("index", { user: req.user });
});

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form", { errors: req.errors});
});

app.get("/dashboard", (req, res) => {
    res.render("dashboard", { user: req.user });
});

app.post("/sign-up", (req, res, next) => {
    // Validate and sanitize fields.
    body("full_name")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Name must be specified."),
    body("username")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Username must be specified."),
    body("password")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Password must be specified."),
    // Process request after validation and sanitization.
    (req, res, next) => {
    // Extract the validation errors from a request.
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        res.render("sign-up-form", {
          errors: errors.array(),
        });
        return;
      }
    }
      // Data from form is valid.
      // Create a User object with escaped and trimmed data.
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if (err) {
            return next(err);
        }
        const user = new User({
            full_name: req.body.full_name,
            username: req.body.username,
            password: hashedPassword,
            membership_status: false
          }).save(err => {
            if (err) { 
              return next(err);
            }
            res.redirect("/dashboard");
          });
      });
    
});

app.post(
    "/log-in",
    passport.authenticate("local", {
      successRedirect: "/dashboard",
      failureRedirect: "/"
    })
);

app.get("/log-out", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
