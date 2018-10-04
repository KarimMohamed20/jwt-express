var dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const app = new express();
const passport = require("passport");
const passportJWT = require("passport-jwt");
const JwtStrategy = passportJWT.Strategy;
const JWTExtract = passportJWT.ExtractJwt;
const parser = require("body-parser");
const knex = require("knex");
const bookshelf = require("bookshelf");
const securePassword = require('bookshelf-secure-password');
const knexDB = knex({
    client: "pg",
    connection: "postgres://jwtuser:letmepass@localhost/jwt_test"
});
const db = bookshelf(knexDB);
const jwt = require("jsonwebtoken");

db.plugin(securePassword);



const User = db.Model.extend({
    tableName: "login_user",
    hasSecurePassword: true
});


const opts = {
    jwtFromRequest: JWTExtract.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET_OR_KEY
};

const strategy = new JwtStrategy(opts, (payload, next) => {
    User.forge({ id: payload.id }).fetch().then(
        res => {
            next(null, res);
        }
    );
});


app.use(parser.urlencoded({
    extended: false
}));
app.use(parser.json());

passport.use(strategy);

app.use(passport.initialize());
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
    res.send("Hello, World");
});

app.post('/addUser', (req, res) => {
    if (!req.body.email || !req.body.password) {
        return res.state(401).send('no fields');
    }

    const user = new User({
        email: req.body.email,
        password: req.body.password
    });

    user.save().then(() => { res.send("ok") });
});

app.post("/getToken", (req,res)=>{

    if (!req.body.email || !req.body.password) {
        return res.status(401).send('Try another e-mail or password');
    } // Error in mail END

    User.forge({email:req.body.email}).fetch().then(result=>{
        if(!result){
            res.status(400).send("user not found");
        }

        result.authenticate(req.body.password).then(
            user=>{
                const payload={id:user.id};
                const token=jwt.sign(payload,process.env.SECRET_OR_KEY);
                res.send(token)
            }).catch(err, res =>{
                res.status(401).send({err:err});
            });
    }); // User Forge END

}); // Method END

app.get("/protected",
    passport.authenticate('jwt', { session: false}),
    (req, res) => {
        res.send("I am protected")
    });
app.listen(PORT);