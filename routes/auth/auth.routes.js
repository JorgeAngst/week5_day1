const express = require("express")
const app = express.Router()

const passport = require("passport");

const User = require("../../models/user.model")

const bcrypt = require("bcrypt")
const bcryptSalt = 10

const ensureLogin = require("connect-ensure-login")



// Signup
app.get('/signup', (req, res) => res.render('signup'))

app.post('/signup', (req, res, next) => {

  const { username, password } = req.body

  if (username === "" || password === "") {
    res.render("signup", { message: 'Rellena todos los campos' })
    return
  }

  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render('signup', { message: 'El usuario ya existe' })
        return
      }

      const salt = bcrypt.genSaltSync(bcryptSalt)
      const hashPass = bcrypt.hashSync(password, salt)

      const newUser = new User({
        username,
        password: hashPass
      })

      newUser.save()
        //.then(user => {console.log('usuario creado:', user); res.redirect("/")})
        .then(x => res.redirect("/"))
        .catch(err => res.render("auth/signup", { message: `Hubo un error: ${err}` }))
    })
})





// Login
app.get("/login", (req, res, next) => {
  res.render("login", { "message": req.flash("error") })
})

app.post('/login', passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/auth/login",
  failureFlash: true,
  passReqToCallback: true
}))





app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
})



// Ruta privada
/*
app.get("/private-page", ensureLogin.ensureLoggedIn('/'), (req, res) => {
  res.render("private", { user: req.user })
})
*/


// Alternativa ruta privada
app.get('/private-page', ensureAuthenticated, (req, res) => {
  res.render('private', { user: req.user })
})

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect('/auth/login')
  }
}



module.exports = app
