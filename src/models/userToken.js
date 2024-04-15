'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class userToken extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      userToken.belongsTo(models.User, {
        foreignKey: "userId",
      })
    }
  }
  userToken.init({
    accessToken: DataTypes.STRING,
    refreshToken: DataTypes.STRING,
    expires: DataTypes.DATE
  }, {
    sequelize,
    modelName: 'userToken',
  });
  return userToken;
};