const express=require('express');
const jwt = require("jsonwebtoken")
const bcrypt=require('bcrypt');
const { User } = require('../models/User');

const router=express.Router();

router.post('/register',async (req,res)=>{
    //recuperation des donnees
   const {login, pwd, pwd2, name} = req.body;
   // const login=req.body.login
   // const pwd=req.body.pwd
   // const pwd2=req.body.pwd2
   // const name=req.body.name
   

   // verification des donnes
    if(!login || !pwd || !pwd2 || !name)
        return res.status(400).json({message:'all fields are required'});
      
    if(pwd!=pwd2)
        return res.status(400).json({message:'passwords don t match'});
    
    let searchUser = await User.findOne({login:login})
    if(searchUser)
        return res.status(400).json({message:'login already exists'});
    

    const mdpCrypted= await bcrypt.hash(pwd,10)
    const user = new User({
        login:login,
        nom:name,
        pwd:mdpCrypted,
        memos:[]
    })
    user.save().then(() =>{
        const token = jwt.sign({ login: user.login }, "secretkeyappearshere", { expiresIn: "1h" });
        return res.status(201).json({ message: 'success', token: token }); 
    }).catch(err => res.status(500).json({message:err}));
});


router.post("/login",async (req,res, next)=>{
    const {login,pwd}=req.body
    const findUser= await User.findOne({login:login})
    if(!findUser)
        return res.status(404).json({message:'no user found'});
    
    const match = await bcrypt.compare(pwd,findUser.pwd)
    if (!match) {
        const error = Error("Wrong details please check at once");
        return next(error);
    }
        // insertion d une propriete dans la session
    let token;
    try{

    token = jwt.sign(
        {loginl : findUser.login},"secretkeyappearhere",
        {expiresIn: "1h"}
    );
    } catch(err){
        console.log(err);
        const error = new Error("Error! Something went wrong.");
        return next(error);
    }
    return res
        .status(200)
        .json({
            success :true,
            data:{
                login : findUser.login,
                token : token,
            },
        });
    //     req.session.login=login;
    //     return res.json({message:'login success',nom:findUser.nom});//200
    // res.status(400).json({message:'incorrect password'});
});
router.post("/logout",async (req,res)=>{
   req.session.destroy();
    res.json({message:'logout success'});
})

module.exports = {UserRouter: router};
