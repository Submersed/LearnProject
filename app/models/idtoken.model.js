module.exports = (sequelize, Sequelize) => {
    const Idtoken = sequelize.define("idtokens", {
      value: {
        type: Sequelize.STRING
      },
      active: {
        type: Sequelize.TINYINT
      }
    });
  
    return Idtoken;
  };