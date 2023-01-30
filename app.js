const mongoose= require('mongoose')
const express = require('express')
const dotenv=require('dotenv');
const { UserRouter } = require('./routes/users');
const { memosRouter } = require('./routes/memos');
const { User } = require('./models/User');
const jwt = require("jsonwebtoken");
dotenv.config(); // require('dotenv').config()
//mongodb
mongoose.connect
("mongodb+srv://Noobenyy101:azertyuiop123@cluster0.mctfqj9.mongodb.net/users?retryWrites=true&w=majority")
.then(()=>console.log("connected to mongodb atlas"))
.catch(err=>console.log(err))

//express
const app=express();

app.use(express.static("./public"))

//middleware to parse json data on body request
app.use(express.json())

// injection du middleware des sessions
// app.use(session({
//     secret: "yahia",
//     resave: false,
//     saveUninitialized: true,
//     cookie: { httpOnly:true }
//   }))

//injection de token
app.use((req,res,next)=>{

    const token = req.header("x-auth-token");

    if (!token) return res.status(401).json({ message: "Access denied, No token provided" });

    try { 

        const decoded = jwt.verify(token, "secretkeyappearhere"); 

        req._userId = decoded; 

        next(); 

    } catch (ex) { 

        res.status(400).send("Invalid Token."); 

    }  
})

  


app.use('/users',UserRouter)

app.get('/hi',(req,res)=>{
    res.send({message:"hi"});
})

// check authentification (gard / interceptor)
/*app.use((req,res,next)=>{

    if(!req.user.login)
        return res.status(403).json({message:"you need to login first"})
    next();
})*/

app.use('/memos',memosRouter)

const port = 3000
app.listen(port, ()=>{
    console.log('server listening on port : ',port)
})