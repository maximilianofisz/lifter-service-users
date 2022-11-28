const jwt = require('jsonwebtoken')

class authHelper{
    authenticateToken(req, res, next){
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]
        if (token == null){
            return res.sendStatus(401)
        }
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=>{
            if(err) return res.sendStatus(403)
            req.user = user
            next()
        })   
    }
    
    generateAccessToken(user){
        return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h"})
    }

    generateRefreshToken(user){
        return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "1d"})
    }
}



module.exports = authHelper