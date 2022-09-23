const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());

const users = [
     {
        id:"1",
        username:'anix001',
        password:"anix001",
        isAdmin: true,
     },
     {
        id:"2",
        username:'anix002',
        password:"anix002",
        isAdmin: false,
     }
];

let refreshTokens = [];

app.post("/api/refresh", (req, res)=>{
    //take the refresh token from the user
    const refreshToken = req.body.token;

    //send error if there is no token or its invalid
    if(!refreshToken) return res.status(401).json({message:"Your are not authenticated !!"});
    if(!refreshTokens.includes(refreshToken)){
        return res.status(403).json({message:"Refresh token is not valid"})
    }
     //if everything is okay generate new access and refresh tokens

     jwt.verify(refreshToken, "myRefreshSecretKey", (err, user)=>{
        err && console.log(err);
        refreshTokens = refreshTokens.filter((token)=> token !== refreshToken);
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);
        refreshTokens?.push(newRefreshToken);
        res.status(200).json({
            accessToken:newAccessToken,
            refreshToken:newRefreshToken,
        });
     });

})

//access token generate function
const generateAccessToken = (user)=>{
    return jwt.sign({id:user.id, isAdmin:user.isAdmin}
        , "mySecretKey",
        {expiresIn:"15m"}
        );
};

//refresh token generate function
const generateRefreshToken = (user) => {
    return jwt.sign({id:user.id, isAdmin:user.isAdmin}
        , "myRefreshSecretKey"
        );
};

app.post("/api/login", (req, res)=>{
    const {username, password} = req.body; 
    const user = users.find((u)=>{
        return u.username === username && u.password === password;
    });
    if(user){
        // Generating access token
        const accessToken= generateAccessToken(user);
        //Generating refresh token
        const refreshToken = generateRefreshToken(user);
        refreshTokens?.push(refreshToken);
        res.status(200).json({
            status:200,
            username:user.username,
            isAdmin:user.isAdmin,
            accessToken,
            refreshToken,
        });
    }else{
        res.status(400).json({
            status:400,
            message:"username or password incorrect!",
        });
    }
});

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if(authHeader){
       const token = authHeader.split(" ")[1];

       jwt.verify(token,"mySecretKey",(err, user)=>{
          if(err){
            return res.status(403).json({message:"Token is not valid!"});
          }
          req.user = user;
          next();
       });
    }else{
        res.status(401).json({message:"You are not authenticated!!"});
    }
}

//user logout api
app.post("/api/logout", verifyToken, (req, res)=>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json({message:"Logout Successfully."})
})

//delete user api
app.delete("/api/users/:userId", verifyToken, (req, res) =>{
    if(req.user.id === req.params.userId || req.user.isAdmin){
        res.status(200).json({message:"user has been deleted!!"});
    }else{
        res.status(403).json({message:"You are not allowed to delete this user!!"})
    }
})
  

app.listen(5000, ()=>console.log("Backend running on port 5000"))