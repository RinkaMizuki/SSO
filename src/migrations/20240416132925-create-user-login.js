'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('UserLogins', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      loginProvier: {
        type: Sequelize.STRING,
        primaryKey: true,
        allowNull: false,
      },
      providerKey: {
        type: Sequelize.STRING,
        primaryKey: true,
        allowNull: false,
      },
      providerDisplayName: {
        type: Sequelize.STRING
      },
      userId: {
        type: Sequelize.INTEGER,
        references: {
          model: 'Users', // "table name"
          key: 'id',
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      accountAvatar: {
        type: Sequelize.STRING
      },
      accountName: {
        type: Sequelize.STRING
      },
      isUnlink: {
        type: Sequelize.BOOLEAN
      },
      createdAt: {
        type: 'TIMESTAMP',
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
        allowNull: false
      },
      updatedAt: {
        type: 'TIMESTAMP',
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
        allowNull: false
      }
    });
  },
  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('UserLogins');
  }
};