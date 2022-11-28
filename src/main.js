require('dotenv').config()
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const authHelper = require('./helpers/authenticator')
const userSchema = require('../../../Libraries/lifter-libraries/src/models/user.js')
const mongoose = require('mongoose')
const _authHelper = new authHelper()
app.use(express.json())

mongoose.connect("mongodb://localhost:27017/lifter-users")

const Users = mongoose.model('Users', userSchema)




const RefreshTokens = mongoose.model('RefreshTokens', mongoose.Schema({
    token: {type: Object, required: true}
}))





// Access auth content example
app.get("/secret", _authHelper.authenticateToken, (req, res) =>{
    
    res.send(`Welcome ${req.user.firstName}`)
})

// Get all available users
app.get("/users", async (req, res) =>{
    const users = await Users.find()
    console.log(users)
    res.end()
})

// Register an user
app.post('/register', async (req, res) =>{
    try{
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        const user = new Users({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            age: req.body.age,
            location: "unknown"
        })

        user.save()
        
        res.status(201).send("User created!")
    }
    catch (err){
        console.log(err)
        res.status(500).send(err)
    }
})

//Log in
app.post("/login", async (req, res) =>{
    const user = await Users.findOne({email: req.body.email}).lean()
    if(user == null){
        return res.status(400).send("Cannot find user")
    }
    try{
        if (await bcrypt.compare(req.body.password, user.password)){
            // User is now authenticated => Authorize
            
            const accessToken = _authHelper.generateAccessToken(user)
            const refreshToken = _authHelper.generateRefreshToken(user)
            
            res.json({
                accessToken: accessToken, refreshToken: refreshToken
            })
        }
        else{
            res.send("Incorrect password!")
            // User failed to authenticate
        }
    }
    catch (err){
        console.log(err)
        res.status(500).send()
    }
})

app.post('/token', async (req, res) =>{
    const refreshToken = req.body.refreshToken
    if (refreshToken == null) return res.sendStatus(401)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) =>{
        if (err) return res.sendStatus(403)
        const newUser = {
            _id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            age: user.age,
            location: user.location,
            __v: user.__v
        }
        const accessToken = _authHelper.generateAccessToken(newUser)
        const refreshToken = _authHelper.generateRefreshToken(newUser)
        
        res.json({
            accessToken: accessToken, refreshToken: refreshToken
        })
    })
})


app.listen(3000, () => {
    console.log("Accounts services is up and running on port 3000")
})