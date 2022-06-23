// for password
const LocalStrategy = require('passport-local').Strategy
const {pool} = require('./dbConfig')
const bcrypt = require('bcrypt')

function initialize(passport){
    const authenticateUser = (email, password, done)=>{
        pool.query(
            // check if user exists
            `SELECT * FROM users WHERE email = $1`, [email],
            (err, results)=>{
                if(err){
                    throw err
                }
                if(results.rows.length > 0 ){
                    const user = results.rows[0]
                    console.log(user.password);
                    // compare password to the password in db
                    bcrypt.compare(password, user.password, (err, isMatch)=>{
                        if(err){
                            throw err
                        }
                        // password matches
                        if(isMatch){
                            // done function will store the user in the session cookie object for use in the app
                            return done(null, user)
                        }else{
                            return done(null, false, {message: "Password is not correct"})
                        }
                    })
                }else{
                    return done(null, false, {message: "Email not registered"})
                }
            }
        )

    }
    passport.use(
        new LocalStrategy(
            {
            usernameField: "email",
            passwordField: "password"
            },
            authenticateUser
        )
    )

    // Takes the user id and stores it in the session cookie
    passport.serializeUser((user,done) => done(null, user.id))
    
    // Uses the ID stored in the session cookie and obtains the user details from the databse
    passport.deserializeUser ((id, done)=>{
        pool.query(
            `SELECT* FROM users WHERE id =$1`, [id], (err, results)=>{
                if(err){
                    throw err
                }
                return done(null, results.rows[0])
            }
        )
    })
}

module.exports = initialize 
