'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class UserToken extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      UserToken.belongsTo(models.User, {
        foreignKey: "userId",
      })
    }
  }
  UserToken.init({
    accessToken: DataTypes.STRING,
    refreshToken: DataTypes.STRING,
    expires: DataTypes.DATE,
    userId: DataTypes.UUID
  }, {
    sequelize,
    modelName: 'UserToken',
  });
  return UserToken;
};