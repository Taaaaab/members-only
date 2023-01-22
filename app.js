/////// app.js
var createError = require('http-errors');
const express = require("express");
const path = require("path");
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
require('dotenv').config()
const async = require("async");
const { body, validationResult } = require("express-validator");
const bodyParser = require("body-parser");
const compression = require("compression");
const helmet = require("helmet");

const app = express();

// Set up mongoose connection
const mongoose = require("mongoose");
mongoose.set('strictQuery', false);
// Set up mongoose connection
const dev_db_url = process.env.MONGODB_URL;
const mongoDB = process.env.MONGODB_URI || dev_db_url;

main().catch(err => console.log(err));
async function main() {
  await mongoose.connect(mongoDB);
}

app.use(compression()); // Compress all routes
app.use(helmet());
app.use(express.static(__dirname + "/public"));
app.set("views", __dirname + "/views");
app.set("view engine", "ejs");

const Schema = mongoose.Schema;
// Creating mongoose schema models
const User = mongoose.model(
  "User",
  new Schema({
    full_name: { type: String, required: true},
    username: { type: String, required: true },
    password: { type: String, required: true },
    membership_status: { type: Boolean, default: false},
    admin: { type: Boolean, default: false },
  })
);

const Message = mongoose.model(
  "Message",
  new Schema({
    text: { type: String, required: true },
    author: { type: String, required: true },
    dateStamp: { type: Date, required: true },
  })
);

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
const urlencodedParser = bodyParser.urlencoded({ extended: false });

app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form");
}); 

app.get("/dashboard", (req, res) => {
  Message.find()
  .exec(function (err, list_messages) {
    if (err) {
      return next(err);
    }
    if (req.user) {
      res.render("dashboard", { 
        user: req.user,
        message_list: list_messages,
      });
    } else {
      res.render("guest-dashboard", { 
        user: req.user,
        message_list: list_messages,
      });
    }
    
  });
});

app.get("/join-club", (req, res, next) => {
// Success
  res.render("join-club", {
    title: "Ready to join the club?",
    user: res.locals.currentUser,
  })
}); 

app.post("/sign-up", urlencodedParser, [
    // Validate and sanitize fields.
    body("full_name")
    .exists()
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Name must be specified."),
    body("username")
    .isEmail()
    .normalizeEmail()
    .trim()
    .isLength({ min: 3 })
    .withMessage("Username must be specified and at least 3 characters long."),
    body("password")
    .isLength({ min: 5 })
    .withMessage("Password must be specified and at least 5 characters."),
    body("confirmPassword")
    .custom(async (confirmPassword, { req }) => {
        const password = req.body.password

        if (password !== confirmPassword) {
            throw new Error("Password confirmation field does not match password.");
        }
    }),
], (req, res, next) => {
    // If errors, render form with errors array
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        // return res.status(422).jsonp(errors.array());
        const alert = errors.array();

        res.render("sign-up-form", {
            alert
        })
    } else {
    // Data from form is valid.
    // Create a User object with escaped and trimmed data.
      bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        const user = new User({
            full_name: req.body.full_name,
            username: req.body.username,
            password: hashedPassword,
            membership_status: false,
            admin: req.body.admin,
          }).save(err => {
            if (err) { 
              return next(err);
            }
            res.redirect("/");
          });
      });
    };
    
    
});

app.post("/dashboard", (req, res, next) => {
  // Create a Message object with escaped and trimmed data.
  const message = new Message({
      text: req.body.message,
      author: req.user.username,
      dateStamp: new Date()
    }).save(err => {
      if (err) { 
        return next(err);
      }
      res.redirect("/dashboard");
    });
  
});

app.post("/join-club", urlencodedParser, [
  // Validate and sanitize fields.
  body("passcode")
  .custom(async (passcode, { req }) => {
      const userCode = req.body.passcode
      const secretCode = "helloworld"
      if (userCode !== secretCode) {
          throw new Error("Sorry, incorrect passcode. Try again.");
      }
  }),
  (req, res, next) => {
  // If errors, render form with errors array
  const errors = validationResult(req);

  if(!errors.isEmpty()) {
      // return res.status(422).jsonp(errors.array());
      const alert = errors.array();

      res.render("join-club", {
        title: "Ready to join the club?",
        alert,
        user: res.locals.currentUser,
      })
    return;
  } 
  // Success, no errors. Update status and return message to user
  const userID = res.locals.currentUser._id
  User.findByIdAndUpdate(userID, { membership_status: true }, {new: true}, (err) => {
    if (err) {
      return next(err);
    }
  });
  res.render("join-club", {
    title: "Congratulations, you now have membership status!",
    user: res.locals.currentUser,
  });
  }
]);

app.delete("/dashboard/:id", (req, res) => {
  const id = req.params.id;

  Message.findByIdAndDelete(id)
  .then(result => {
    res.json({ redirect: "/dashboard" })
  })
  .catch(err => {
    console.log(err);
  })
})

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

module.exports = app;
