const jwt = require("jsonwebtoken");
const config = require("../config/auth.config.js");
const db = require("../models");
var bcrypt = require("bcryptjs");

//2fa
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')
//2fa

const User = db.user;
const Tokens = db.idtoken;

let accessTokens = [];

//ipaddress, user
let blockedUsers = [];
let signupUsers = [];
let accessUsers = [];

/*
pri registraciji sem preveril vhodne podatke kasneje pa sem ga zacasno shranil v pomnilnik. Ko je uporabnik potrdil preko 2fa ga je validiral in vnesel v bazo
*/


//
validateUserId = (req, res, next) => {
  console.log("------------------------------------------------------------------------------validate user")
  console.log(signupUsers)
  var tempUser = signupUsers.find(x => {return x.userid === req.params.userid});
  if(!tempUser)
  {
    tempUser = accessUsers.find(x => {return x.userid === req.params.userid});
  }
  if(!tempUser)
  {
    return res.status(500).send({
      message: "Invalid user access!"
    });
  }

  req.body.secret = tempUser.secret;
  req.body.username = tempUser.username;
  req.body.password = tempUser.password;
  verify2fa(req,res,next);
}


verifyRequestAccess = (req, res, next) => {
  console.log("requestaccess")
  verifytest(req,res)
  console.log("dela")
}

verifyGetTokenInfo = (req,res,next) => {
  console.log("access")
  let accesstoken = req.headers["x-access-token"];

  let idtoken = req.headers["x-id-token"];
  console.log(idtoken);
  if(idtoken)
  {
    jwt.verify(idtoken, config.ID_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        //login
        return res.status(401).send({message: "Unauthorized, please relogin!"});
      }
      console.log(decoded)

      Tokens.findOne({
        where:{value: idtoken}
      }).then(token =>{
        if(!token)
        {
          return res.status(401).send({message: "Token does not exist"});
        }
        console.log(token.active)
        if(!token.active)
        {
          let tempuser = accessUsers.find(x => {return x.token === idtoken});
          console.log(!tempuser)
          if(!tempuser)
          {
            console.log(decoded.id)
            User.findOne({
              where:{id: decoded.id}
            }).then(user => {
            if(!user)
            {
              return res.status(401).send({message: "Unknown token - user"});
            }
            tempuser = {
              userid: require('crypto').randomBytes(64).toString('hex'),
              id: user.id,
              username: user.username,
              password: user.password,
              ipaddress: req.header('x-forwarded-for') || req.connection.remoteAddress,
              secret: user.secret,
              token: idtoken
            };
            accessUsers.push(tempuser);
              return res.status(401).send({
              message: "Please verify identity",
              userid: tempuser.userid
              });
            })        
          }
          else
          {
            return res.status(401).send({
              message: "Please verify identity",
              userid: tempuser.userid
              });
          }
        }
        else
        {
          var accessToken = jwt.sign({id: decoded.id}, config.ACCESS_TOKEN_SECRET,{ expiresIn : 3600 });

          res.status(200).send({
            accessToken: accessToken
          });
        }
        
      })      
    })
  }
  else if(accesstoken)
  {
    jwt.verify(accesstoken, config.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        //logout
        return res.status(401).send({message: "Unauthorized! Token timedout Please request a new one"});
      }
      return res.status(200).send({message: "Authorized, Token is valid!"});

    })
  }

};

verifyAccessToken1 = (req, res, next) => {
  jwt.verify(accesstoken, config.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      //logout
      return res.status(401).send({message: "Unauthorized! Token timedout Please request a new one"});
    }
    next();

  })
};

verifyAccessToken = (req, res, next) => {
  let token = req.headers["x-access-token"];
  let ipaddress = req.header('x-forwarded-for') || req.connection.remoteAddress
  req.body.token = token;

  if (!token && token != null) {
    return res.status(400).send({
      message: "Critical error with requesting!"
    });
  }

  jwt.verify(token, config.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({
        message: "Unauthorized, please relogin!"
      });
    }
    
    console.log("najde token")
    console.log(decoded)
    User.findOne({
      where: {id: decoded.id}
    }).then(user => {
      if(user)
      {
        if(user.ipaddress == ipaddress)
        {
          // mejbi noum rabu IDja
          req.userId = decoded.id;
          console.log("konca")
          next();
        }
        else
        {
          user.userid = require('crypto').randomBytes(64).toString('hex');
          blockedUsers.push(user);
          return res.status(401).send({
            userid: user.userid
          });
        }
      }
      else
      {
        return res.status(401).send({
          message: "User with this token does not exist!"
        });
      }
    })
  });
};

checkForValidValuesSignin = (req, res, next) => {
  console.log(req.body)
  if (!req.body.username || !req.body.password) {
    res.status(500).send({
      message: "please fill all the boxes and try again!"
    });
    return;
  }

//verify for forbiden simbols 
  // Username
  var tempUser = accessUsers.find(x => {return x.username === req.body.username});
  console.log(tempUser)
  if(tempUser != null)
  {
    res.status(200).send({
      message: "user is blocked, need to be verified!",
      userid: tempUser.userid
    }); 
    return;
  }

  User.findOne({
      where: {username: req.body.username}
      }).then(user => {
        console.log(user)
      if (!user) {
        return res.status(404).send({ message: "User Not found." });
      }

      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (!passwordIsValid) {
        res.status(401).send({
          accessToken: null,
          message: "Invalid Password!"
        });
        return 
      }
    next();
    })
};

checkForValidValuesRequest = (req, res, next) => {
  if (!req.body.token) {
    res.status(500).send({
      message: "please fill all the boxes and try again!"
    });
    return;
  }
  next()
//verify for forbiden simbols 
  // Username
};

const authJwt = {
  verifyGetTokenInfo: verifyGetTokenInfo,
  validateUserId: validateUserId,
  verify2fa: verify2fa,
  SignUp2fa: SignUp2fa,
  verifyRequestAccess: verifyRequestAccess,
  checkForValidValuesSignin: checkForValidValuesSignin,
  verifyAccessToken: verifyAccessToken,
};

module.exports = authJwt;
