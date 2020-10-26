const db = require("../models");
const config = require("../config/auth.config");
const User = db.user;
const Role = db.role;
const Tokens = db.idtoken;

const Op = db.Sequelize.Op;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");


//username,password,email
exports.signup = (req, res) => {
    
    console.log("mainsignup")
  // Save User to Database
  User.create({
    username: req.body.username,
    password: bcrypt.hashSync(req.body.password, 8),
    ipaddress: req.header('x-forwarded-for') || req.connection.remoteAddress,
    secret: req.body.secret
  })
    .then(user => {
      if (req.body.roles) {
        Role.findAll({
          where: {
            name: {
              [Op.or]: req.body.roles
            }
          }
        }).then(roles => {
          user.setRoles(roles).then(() => {
            res.status(200).send({ message: "User registered successfully!" });
          });
        });
      } else {
        // user role = 1
        console.log("Token")
        console.log(user.id)
        console.log("idToken")
        var idtoken = jwt.sign({id: user.id}, config.ID_TOKEN_SECRET);
        console.log("accessToken")
        var accessToken = jwt.sign({id: user.id}, config.ACCESS_TOKEN_SECRET,{ expiresIn : 3600 });
        console.log(idtoken)

        Tokens.create({
          value: idtoken,
          active: 1
        }).then(function(token) {console.log("dela", token.toJSON)})
        .catch(function(err) {
          // print the error details
          console.log(err, idtoken);
      });
        console.log("id: " + idtoken)
        console.log("access: " + accessToken)
        user.setRoles([1]).then(() => {
          res.status(200).send({ message: "User registered successfully!", idtoken: idtoken, accesstoken: accessToken});
        });
      }
    })
    .catch(err => {
      res.status(500).send({ message: err.message });
    });
};

//username,password
exports.signin = (req, res) => {
  User.findOne({
    where: {
      username: req.body.username
    }
  })
    .then(user => {
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

      var idtoken = jwt.sign(user.id, config.ID_TOKEN_SECRET);
      var accessToken = jwt.sign(user.id, config.ACCESS_TOKEN_SECRET,{ expiresIn: 1800 });

      var authorities = [];
      user.getRoles().then(roles => {
        for (let i = 0; i < roles.length; i++) {
          authorities.push("ROLE_" + roles[i].name.toUpperCase());
        }
        res.status(200).send({
          id: user.id,
          username: user.username,
          roles: authorities,
          idToken: idtoken,
          accessToken: accessToken
        });
      });
    })
    .catch(err => {
      res.status(500).send({ message: err.message });
    });
};

//token
exports.requestAccess = (req, res) => {
  let idtoken = req.body["x-id-token"];

  if (!idtoken) {
    return res.status(403).send({
      message: "No token provided!"
    });
  }
  console.log(idtoken)

  Idtoken.findOne({
    where: {value: idtoken}
  }).then(token => {
    if(!token)
    {

      jwt.verify(idtoken, config.ID_TOKEN_SECRET, (err, userid) => {
        if (err)
        {
          console.log(err)
          return res.status(403).send({
            message: "Expired or nonexisting token!"
        });
        }
        
        User.findOne({
          where: {id: userid.id}
        }).then(user =>{
          console.log(user)
          if(!user)
          {
            return res.status(403).send({
              message: "This user does not exist!"
          });
          }
          console.log(user)

          const accessToken = jwt.sign(user.id, config.ACCESS_TOKEN_SECRET)

          res.json({accessToken: accessToken })

          })
      });
    }
  })
};
