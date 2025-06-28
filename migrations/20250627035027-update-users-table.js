'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    // Add new columns to users table
    await queryInterface.addColumn('users', 'email', {
      type: Sequelize.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true
      }
    });

    await queryInterface.addColumn('users', 'google_id', {
      type: Sequelize.STRING,
      allowNull: true,
      unique: true,
      field: 'google_id'
    });

    await queryInterface.addColumn('users', 'display_name', {
      type: Sequelize.STRING,
      allowNull: true,
      field: 'display_name'
    });

    await queryInterface.addColumn('users', 'avatar', {
      type: Sequelize.STRING,
      allowNull: true
    });

    // Rename passwordHash to password_hash for consistency
    await queryInterface.renameColumn('users', 'passwordHash', 'password_hash');
    
    // Make password_hash nullable for Google-authenticated users
    await queryInterface.changeColumn('users', 'password_hash', {
      type: Sequelize.STRING,
      allowNull: true
    });
  },

  async down(queryInterface, Sequelize) {
    // Revert the changes
    await queryInterface.changeColumn('users', 'password_hash', {
      type: Sequelize.STRING,
      allowNull: false
    });
    
    await queryInterface.renameColumn('users', 'password_hash', 'passwordHash');
    
    await queryInterface.removeColumn('users', 'avatar');
    await queryInterface.removeColumn('users', 'display_name');
    await queryInterface.removeColumn('users', 'google_id');
    await queryInterface.removeColumn('users', 'email');
  }
};
