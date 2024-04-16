'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class UserLogin extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      UserLogin.belongsTo(models.User);
    }
  }
  UserLogin.init({
    loginProvider: DataTypes.STRING,
    providerKey: DataTypes.STRING,
    providerDisplayName: DataTypes.STRING,
    userId: DataTypes.INTEGER,
    accountAvatar: DataTypes.STRING,
    accountName: DataTypes.STRING,
    isUnlink: DataTypes.BOOLEAN
  }, {
    sequelize,
    modelName: 'UserLogin',
  });
  return UserLogin;
};