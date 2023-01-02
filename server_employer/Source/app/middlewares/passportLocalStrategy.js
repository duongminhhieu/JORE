const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const employerModel = require('../models/employer.m');

module.exports = (app) => {
  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser(function (user, done) {
    done(null, user);
  });
  passport.deserializeUser(async function (user, done) {
    try {
      //const user = await userModel.getByUserName(username);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });

  passport.use(
    new LocalStrategy(
      {
        passReqToCallback: true,
        usernameField: "email",
        passwordField: "password",
      },
      async (req, email, password, done) => {
        try {
          const user = await employerModel.getEmployerByEmail(email);
          if (!user) {
            return done(null, false,  req.flash('messageDanger', 'Địa chỉ email hoặc mật khẩu không đúng!'));
          }

          if(!user.verify){
            return done(null, false,  req.flash('messageDanger', 'Tài khoản chưa được xác thực! Hãy vào email để xác thực'))
          }

          if(user.status !== 'approved') {
            return done(null, false,  req.flash('messageDanger', 'Tài khoản chưa được JORE xác thực! Hãy đợi Jore xác thực nhé!'))
          }

          const cmp = await bcrypt.compare(password, user.password);
          if (!cmp) {
            return done(null, false, req.flash('messageDanger', 'Địa chỉ email hoặc mật khẩu không đúng!'));
          }
          return done(null, user);
        } catch (error) {
          done(error);
        }
      }
    )
  );
};
