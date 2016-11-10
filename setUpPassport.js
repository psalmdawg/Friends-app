var passport = require('passport');
var User = require('./models/user');
var LocalStrategy = require("passport-local").Strategy;

module.exports = function(){
  passport.serializeUser(function( user, done ){
    done(null, user._id);
  });
  passport.deserializeUser(function( id, done ){
    User.findById(id, function( err, user ){
      done(err, user);
    });
  });
};

passport.use("login", new LocalStrategy(function(username, password, done){
  User.findOne({username:username}, function(err, user){
    if(err) {return done(err);}
    if(!user) {
      return done(null, false, { message: "No user has that UserName :/" });
    }
    user.checkPassword(password, function(err, isMatch){
      if(err){ return done(err); }
      if(isMatch) {
        return done(null, user);
      } else {
        return done(null, false, {message: "Username and or password invalid"});
      }
    });
  });
}));

// 1. Look for a user with the supplied username.
// 2. If no user exists, then your user isn’t authenticated; say that you’ve finished with
// the message “No user has that username!”
// 3. If the user does exist, compare their real password with the password you sup-
// ply. If the password matches, return the current user. If it doesn’t, return “Invalid password.”
