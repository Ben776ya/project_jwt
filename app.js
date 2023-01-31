const mongoose= require('mongoose')
const express = require('express')
const dotenv=require('dotenv');
const { UserRouter } = require('./routes/users');
const { memosRouter } = require('./routes/memos');
const { User } = require('./models/User');
const cors = require('cors');
const jwt = require("jsonwebtoken");
dotenv.config(); // require('dotenv').config()
//mongodb
mongoose.connect
(process.env.DB_LOG)
.then(()=>console.log("connected to mongodb atlas"))
.catch(err=>console.log(err))

//express
const app=express();
app.use(cors({
    origin: '*'//allow all requests 
}));

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
// 

  


app.use('/register',UserRouter)


app.get('/hi',(req,res)=>{
    res.send({message:"hi"});
})
app.use('/',(req,res,next)=>{

        const token = req.header("x-auth-token");
    
        if (!token) return res.status(401).json({ message: "Access denied, No token provided" });
    
        try { 
    
            const decoded = jwt.verify(token, process.env.TOKEN_SECRET); 
    
            req._userId = decoded; 
    
            next(); 
    
        } catch (ex) { 
    
            res.status(400).send("Invalid Token."); 
    
        }  
    });


app.use('/memos',memosRouter)
    





const port = process.env.PORT || 3000
app.listen(port, ()=>{
    console.log('server listening on port : ',port)
})