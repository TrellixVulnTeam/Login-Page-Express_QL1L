const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
let ejs = require('ejs');
var crypto = require('crypto');
var db = require('./db.js');
var passport = require('passport');
var LocalStrategy = require('passport-local');
const { response } = require('express');

const app = express();

app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/'));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    //cookie: { secure: true }
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));

// http://localhost:3000/
app.get('/', function (request, response) {
    // Render login template
    console.log(request.session)

    response.render('login');
});

app.post('/auth',
    passport.authenticate('local', { failureRedirect: '/login', failureMessage: true }),
    function (req, res) {
        res.redirect('/home');
    });


passport.use(new LocalStrategy(function verify(username, password, cb) {
    //console.log(username)

    db.get('SELECT * FROM users WHERE username = ?', [username], function (err, user) {
        if (err) { return cb(err); }
        if (!user) { return cb(null, false, { message: 'Incorrect username or password.' }); }

        crypto.pbkdf2(password, user.salt, 310000, 32, 'sha256', function (err, hashedPassword) {
            if (err) { return cb(err); }
            if (!crypto.timingSafeEqual(user.hashed_password, hashedPassword)) {
                return cb(null, false, { message: 'Incorrect username or password.' });
            }
            //console.log(user)
            return cb(null, user);
        });
    });
}));

app.post('/auth', passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/'
}));

// http://localhost:3000/home
app.get('/home', function (request, response) {
    // If the user is loggedin
    if (request.session.passport.user) {
        // Output username
        if (request.session.views) {
            request.session.views++
        } else {
            request.session.views = 1
        }
        //response.send('Welcome back, ' + request.session.passport.user.username + ' ' + request.session.views + '!');
        response.render('home', { user: request.session.passport.user, views: request.session.views })
    } else {
        // Not logged in
        console.log(request.session)
        response.send('Please login to view this page!');
    }
    response.end();
});

app.get('/logout', function (req, res) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.debug('App listening on :3000');
});


