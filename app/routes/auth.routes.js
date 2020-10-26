const { verifySignUp } = require("../middleware");
const { authJwt } = require("../middleware");
const { updateVerify } = require("../middleware");
const controller = require("../controllers/auth.controller");

module.exports = function(app) {
  app.use(function(req, res, next) {
    res.header(
      "Access-Control-Allow-Headers",
      "x-access-token, Origin, Content-Type, Accept"
    );
    next();
  });

  app.post(
    "/api/auth/signup",
    [
      verifySignUp.checkForValidValuesSignUp,
      verifySignUp.checkRolesExisted
    ],
    authJwt.SignUp2fa
  );

  app.post(
    "/api/auth/signup/:userid",

    authJwt.validateUserId,
    controller.signup
  );

  app.post("/api/auth/signin", authJwt.checkForValidValuesSignin, controller.signin);

  app.post("/api/auth/signin/:userid", 
  authJwt.validateUserId, 
  controller.signin);

    //idtoken,
  app.get("/api/auth/requestAccess", authJwt.verifyGetTokenInfo, controller.requestAccess);
    //userid, tfacode
  app.post("/api/auth/requestAccess/:userid", authJwt.validateUserId, controller.requestAccess);
};

