const express = require('express');
const app = express()
const {pool} = require("./dbConfig")
const bcrypt =require("bcrypt")
const session = require("express-session")
const flash = require("express-flash")
const passport = require('passport')


const initializePassport = require('./passportConfig')

initializePassport(passport)

const PORT = process.env.PORT || 4000

app.set("view engine", "ejs")
app.use(express.urlencoded({extended:false}))
app.use(session({
    // a key you want to keep secret, it will encrypt all of our information we will store in the session
    secret:"secret", 

    // should we resave our session variables if nothing is changed?
    resave: false,

    // Do we want to save session details if there has been no value placed in the session
    saveUninitialized: false,
}))

app.use(passport.initialize())
app.use(passport.session())

// if we want to display flash messages
app.use(flash())
app.get("/", (req,res) => {
    res.render("index");
});
app.get("/user/register", checkAuthenticated, (req,res) => {
    res.render("register");
});

app.get("/user/login", checkAuthenticated, (req,res) => {
    res.render("login");
});

app.get("/user/dashboard", checkNotAuthenticated,(req,res) => {
    res.render("dashboard", {user: req.user.name});
});

app.get('/user/logout', (req, res)=>{
    req.logOut()
    req.flash('success_msg', "You have been logged out")
    res.redirect('/user/login')
})

// Validation checks
app.post('/user/register',async(req, res)=>{
    let {name, email, password, password2} = req.body

    console.log({
        name,
        email,
        password,
        password2});

    // errors array, push every error in this array
    let errors = [];

    if(!name || !email || !password || !password2){
        errors.push({message: "Please enter all fields"})
    }
    if(password.length < 6){
        errors.push({message: "Password should be at least 6 characters"})
    }
    if(password != password2){
        errors.push({message: "Passwords do not match"})
    }
    if(errors.length>0){
        res.render("register", {errors})
    }else{
        //form validation has passed

        let hashedPassword = await bcrypt.hash(password, 10)
        console.log(hashedPassword);
        pool.query(
            `SELECT * FROM users
            WHERE email =$1`, [email], (err, results)=>{
                if(err){
                    throw err
                }
                console.log(results.rows);
                if(results.rows.length > 0 ){
                    errors.push({message:'Email already registered'})
                    res.render('register', {errors})
                }else{ // the user doesn't exist in the db
                    pool.query(
                        `INSERT INTO users (name, email, password)
                        VALUES($1, $2, $3)
                        RETURNING id, password`, [name, email, hashedPassword], (err, results)=>{
                            if(err){
                                throw err
                            }
                            console.log(results.rows);
                            req.flash('Sucess_msg', "You are now registered. Please log in")
                            res.redirect('/user/login')
                        }
                    )
                }
            }
        )
    }
})

app.post('/user/login', passport.authenticate('local', {
    successRedirect: '/user/dashboard', 
    failureRedirect: '/user/login',
    failureFlash:true

}))

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/user/dashboard")
    }
    next()
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next()
    }
    res.redirect("/user/login")
}
app.listen(PORT, ()=>{
    console.log(`Server runing on port: http://localhost:${PORT}`);
});