const db = require("../models");
const controller = require("../controllers/auth.controller");
const User = db.user;

checkDuplicateUsernameOrEmail = (req, res, next) => {
  if(req.body.username == null || req.body.password == null)
  {
    res.status(500).send({
      message: "please enter user credentials and try again!"
    });
    return
  }

  // Username
  User.findOne({
    where: {
      username: req.body.username
    }
  }).then(user => {
    if (user) {
      res.status(400).send({
        message: "Failed! Username is already in use!"
      });
      return;
    }

    User.findOne({
      where: {
        email: req.body.email
      }
    }).then(user => {
      if (user) {
        res.status(400).send({
          message: "Failed! Email is already in use!"
        });
        return;
      }
      next();
    });
  });
};

checkForValidValuesSignUp = (req, res, next) => {
  if (!req.body.username || !req.body.password) {
    res.status(500).send({
      message: "please fill all the boxes and try again!"
    });
    return;
  }
//verify for forbiden simbols 
  // Username
  User.findOne({
    where: {
      username: req.body.username
    }
  }).then(user => {
    if (user) {
      res.status(400).send({
        message: "Failed! Username is already in use!"
      });
      return;
    }
    next();
  });
};

const verifySignUp = {
  checkForValidValuesSignUp: checkForValidValuesSignUp,
};

module.exports = verifySignUp;
