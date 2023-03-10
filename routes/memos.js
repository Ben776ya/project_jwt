const express= require('express')
const {Memo} = require('../models/Memo');
const { User } = require('../models/User');
const jwt = require("jsonwebtoken")
const router = express.Router();

// ajouter
router.post("",authenticateToken,async (req,res)=>{

    // recuperation des donnees envoyees
   const {date, content} =  req.body
   // verification
   if(!date || !content)
    return res.status(400).json({message:"date and content are required"})

    // creer une instance du model
    const memo=new Memo({
        date:date,
        content:content
    })
    try{
    const dataMemo =  await memo.save()
    const user=req.user;
    user.memos.push(dataMemo)
    const data = await user.save();
    res.json(data.memos[data.memos.length-1]);
    }catch(err)
    {
        res.status(500).send({message:err})
    }

})

// lister
router.get("", authenticateToken,async (req,res)=>{
    const nbr = req.query.nbr || req.user.memos.length
    const dataToSend=req.user.memos.filter((elem,index)=>index<nbr)
    res.json(dataToSend)
})




//supprimer ( method utilise en http : delete. l identifiant de la ressource doit etre dournie au niveau du URL)
// delete localhost:30000/memos/1245
router.delete("/:idMemo", authenticateToken,async (req,res)=>{
    
    const idMemo = req.params.idMemo
    try{
    const user= req.user;

    if(!user.memos.find(memo=>memo._id==idMemo))
        throw ("not allowed sorry")
        
    // suppression depuis la collection des memos
    await Memo.findByIdAndDelete(idMemo)
    
    user.memos.remove({_id:idMemo})
    await user.save();

    res.json({message:'delete with success'})
    
    }
    catch(err){
        res.status(500).send({message:err})
    }
})

function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ');
    if(token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.TOKEN_SECRET , (err, user)=>{
        if(err) return res.sendStatus(403)
        req.User = user
        next()
    })
    
}


module.exports.memosRouter= router;
