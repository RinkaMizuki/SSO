'use strict';
const {
  Model
} = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      User.belongsTo(models.Service, {
        foreignKey: 'serviceId',
      });
      User.hasOne(models.UserToken);
      User.hasMany(models.UserLogin);
    }
  }
  User.init({
    email: DataTypes.STRING,
    username: DataTypes.STRING,
    password: DataTypes.STRING,
    role: DataTypes.STRING,
    serviceId: DataTypes.UUID,
    emailConfirm: DataTypes.BOOLEAN,
    phone: DataTypes.STRING,
    f2a: DataTypes.BOOLEAN
  }, {
    sequelize,
    modelName: 'User',
  });

  return User;
};