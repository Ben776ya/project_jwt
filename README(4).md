
# [JWT implementation]


A JSON web token(JWT) is JSON Object which is used to securely transfer information over the web(between two parties). It is generally used for authentication systems and can also be used for information exchange.

This is used to transfer data with encryption over the internet also these tokens can be more secured by using an additional signature. These token consists of header JSON and payload JSON along with the optional signature, The each of three remains concatenated with the “.”, Below is the sample example of JSON Web Token. 

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2MTU0OWIwMTIwMWUyZjMzZWE3NmFkZjYiLCJlbWFpbCI6InNtdHdpbmtsZTQ1MkBnbWFpbC5jb20iLCJpYXQiOjE2MzI5MzQ2NTgsImV4cCI6MTYzMjkzODI1OH0._oHr3REme2pjDDdRliArAeVG_HuimbdM5suTw8HI7uc
```
We use JWT to solve the challenge proposed by the stateless HTTP stateless requets.

But how does JWT work?

Well in the first step, the server generates a token with some configurations i.e payload, signature, expiry, etc. Next time when any request from the client-side arrives with the authorization header containing the JWT token, the server decodes that token and uses the details, and permits the access accordingly.

![alt text](https://media.geeksforgeeks.org/wp-content/uploads/20210925202132/Untitled1-660x404.png)

## [Install JWT Package:]
After initializing the project we install jsonwebtoken 
```
npm init
npm install jsonwebtoken
```
## Create Route for tokens

## Server Side

### users.js

In the users routes We had routes for login, register and the logout.

#### [Login Route:]

We first recuperate the data from the request body (login, pwd, pwd2, name). Then we check if all fields are filled and if the passwords match. If they do not match, an error message is sent. we then search for an existing user with the same login and if one exists, an error message is sent. If everything checks out, we hash the password and create a new user with the login, name and hashed password. And then finally we sign a JWT token with the login of the user and send it back in the response.

```
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
        //creation and signing of the Token and sending back in the respnse
    let token;
    try{

    token = jwt.sign(
        {loginl : findUser.login},process.env.TOKEN_SECRET,
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

});

```

#### [Register Route:]

In the register router, we takes the login and password from the request body, find the user with the given login in the database, compare the given password with the one stored in the database and if they match, we create a token and return it as part of a success response. If no user is found or if the passwords don't match, we return an error message. With JWT now, when i user registers he is automatically logged in thanks to the token generated

```
router.post('/register',async (req,res)=>{
    //recuperation des donnees
   const {login, pwd, pwd2, name} = req.body;

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
        // Token signing and sending it in the respnse
        const token = jwt.sign({ login: user.login }, process.env.TOKEN_SECRET, { expiresIn: "1h" });
        return res.status(201).json({ message: 'success', token: token }); 
    }).catch(err => res.status(500).json({message:err}));
});

```
#### [Logout Route:]

Instead of destroying the session like before, we just delete the token from the Client-side memory. So basically our logout route will look Something like this:

```
router.post("/logout", async (req, res) => {
    res.json({ message: "Logged out successfully" });
  });

```

### [memos.js:]

In the memos's routes in order to get or post any memos you only need to be verified. So for that we create a ```authenticateToken()``` function taht authenticates a token, and pass it to the get and post functions.

So the function takes in a request, response, and a next parameter. The function first creates a variable called authHeader and assigns it to the authorization header of the request. It then creates another variable called token and assigns it to the authHeader split by spaces. If the token is null, it will send an error status of 401. Otherwise, it will use JWT to verify the token with a secret key. If there is an error verifying the token, it will send an error status of 403. If there are no errors verifying the token, it will assign the user to req.User and call next().

```
function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ');
    if(token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.TOKEN_SECRET, (err, user)=>{
        if(err) return res.sendStatus(403)
        req.User = user
        next()
    })
    
}

```
So now when defining our routes we pass the function as parameter, and from which we can access our user ```user = req.user``` if the token is verified.
Here's an example for getting the memos route:
```
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

```
And did the same for the other routes.

### [app.js:]

And now the final part we inject our middleware. It's a middleware function that checks for a valid JSON Web Token (JWT) in the request header. If a token is present, it will be verified using the secret key provided. If the token is valid, the user ID associated with the token will be stored in the request object and the request will be allowed to proceed to its next destination. If no token is present or if it is invalid, an error message will be sent back to the user.

But first we declare the middleware for registration ``` app.use('/register',UserRouter) ``` because the token is not generated yet. And let after our function middleware handel the rest of the routes.

``` 
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

```
And with this we've finish all changes needed for JWT implementation in the Server Side. 

## [JWT Client Side:]

In order to provide a secure and efficient way to authenticate users for subsequent requests to the server, we store it in the Client Side storage. The token acts as proof of identity, allowing the client to make authorized requests on behalf of the user without the need for the user to re-enter their credentials.
We do this by storing the token when the user authenticates:

```
export const authentifier=(login,pwd)=>{
    const dataToSend = {login:login,pwd:pwd}
    fetch(url+"/users/login",{
        method:"POST",
        body:JSON.stringify(dataToSend),
        headers:{
            'Content-Type': 'application/json'
        }
    }).then(res=>{
        if(res.ok)
        {
            window.location="#application"
            loginElement.classList.add("hidden")
            logoutElement.classList.remove("hidden")
            viderLogin();
            res.json().then(data=>{
                const {nom}=data;
                logoutElement.children[0].innerText="Logout("+nom+")"

                // insertion du JWT dans le local storage
                localStorage.setItem('token', token);
            }).catch(err=>alert(err))
            // (Logout (Sarah))
        }
        else{
            alert("echec d'authentification")
        }
    })
    .catch(err=>console.log(err));
}

```

And to log out all we have to do is remove the token from the local storage, after retrieving it from the header :

```
export const logout=()=>{

    fetch(url+"/users/logout",{ // tu dois injecter le token dans la requete
        method:"POST",
        headers:{
            'Authorization' :  `Bearer ${token}`
        }
    }).then(res=>{
        if(res.ok)
        {
            logoutElement.children[0].innerText="Logout"
            logoutElement.classList.add("hidden")
            loginElement.classList.remove("hidden")
            // suppression du JWT  du local Storage
            localStorage.removeItem("jwt");
        }
        else{
            alert("error dans le logout")
        }
    })
    .catch(err=>alert(err));
}

```

And for the registeration, we do a little bit of both by storing the token in the local storage and sending it in the request's header:

```

export const register =(email,name,pwd,pwd2)=>{

    const dataToSend={
        login:email,
        name:name,
        pwd:pwd,
        pwd2:pwd2
    }
    const jwtToken = localStorage('jwt')
    fetch(url+"/users/register",{
        method:"POST",
        body:JSON.stringify(dataToSend),
        headers:{
            'Content-Type': 'application/json',
            'Authorization' :  `Bearer ${jwtToken}`
        }
    }).then(res=>{
        if(res.ok)
        {
            alert("success");
            window.location="#login"
            viderRegister();
            //vider
        }
        else{
            res.json()
            .then(data=>{
                const {message}=data;
                alert(message)
            })
            .catch(err=>{ alert("erreur");
                        console.log(err);
                    })
        }
    })
    .catch(err=>{
        alert("erreur");
        console.log(err);
    });

```

