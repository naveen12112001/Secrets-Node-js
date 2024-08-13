//Requiring Modules
require('dotenv').config(); //For hiding sensitive info such as API keys!
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
const session = require('express-session');//Level 5 Passport Authentication
const passport = require('passport');//Level 5 Passport Authentication
const passportLocalMongoose = require('passport-local-mongoose');//Level 5 Passport Authentication
const GoogleStrategy = require('passport-google-oauth20').Strategy;//Level 6 Oauth
const findOrCreate = require('mongoose-findorcreate');//Line no.69
const FacebookStrategy = require('passport-facebook');//Level 6 auth FB
// const md5 = require('md5');//Level 3 Encryption-MD5 Hashing function!
// const bcrypt = require('bcrypt'); //Level 4 Encryption-Salting and Hashing rounds!
// const saltRounds = 12;//Level 4 Encryption-Salting and Hashing rounds!
//Setting and Using
// Methods
const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true //Using body parser
}));

process.setMaxListeners(0);

app.use(express.static("public"));
//Most important to use it here!!!!!!!-Level 5 Auth Passport
app.use(session({
  secret: 'Hey there! This is our little secret!',
  resave: false,
  saveUninitialized: false
}));
//Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// Connecting and configuring
//Level 5 Auth Passport
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
// console.log(process.env.API_KEY);//Level 2
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId:String,
  facebookId:String,
  secret:[String]
});
//Initalizing passport-local-mongoose module//Level 5
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// const secret = process.env.SECRET;
// Level 2 Encryption-Using mongoose-encryption
// userSchema.plugin(encrypt,{secret:secret , encryptedFields: ['password']});

const User = new mongoose.model("User", userSchema);

// use static serialize and deserialize of model for passport session support//Serialize-create cookie Deserialize-Destroy cookie
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());//Only works for local strategy

passport.serializeUser(function(user, done) { //For google strategy!
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id ,username:profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/facebook/secrets",
    enableProof: true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id,username:profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });
app.get("/auth/facebook",
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
});


app.get("/login", function(req, res) {
    res.render("login");
  });

app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets",function(req,res){
  User.find({"secret":{$ne:null}},function(err,foundUsers){
    if(err){
      console.log(err);
    }
    else{
      if(foundUsers){
        res.render("secrets",{userSubmittedSecrets:foundUsers});
      }
    }
  });
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
})
app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});
app.post("/submit",function(req,res){
  const submittedSecret = req.body.inputsecret;
  //console.log(req.user.id);
  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        foundUser.secret.push(submittedSecret);
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});
app.post("/register", function(req, res) {

  User.register({username:req.body.username },req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })



  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash //Level 3-MD5 Hashing
  //   });
  //   newUser.save(function() {
  //     res.render("secrets");
  //   });
  // });//Level 4 Salting and Hashing
});

app.post("/login", function(req, res) {

    const user = new User({
      username:req.body.username,
      password:req.body.password
    });
    req.login(user,function(err){
      if(err){
        console.log(err);
      }
      else{
        passport.authenticate("local")(req,res,function(){
          res.redirect("/secrets");
        })
      }
    })






  // const username = req.body.username;
  // // const password = md5(req.body.password);//Level 3-MD5 Hash
  // const password = req.body.password;
  // // Level 1 Encryption-Plain Text
  // User.findOne({
  //   email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       // if (foundUser.password === password) {//First three Levels!
  //       bcrypt.compare(password, foundUser.password, function(err, result) { //4th Level salting and hashing
  //         if(result===true){
  //           res.render("secrets");
  //         }
  //       });
  //
  //       // }
  //     }
  //   }
  // })//Level 4 Salting and Hashing
});

app.listen(8080, function() {
  console.log("Server up and running on port 8080");
});
