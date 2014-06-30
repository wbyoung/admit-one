'use strict';

var bluebird = require('bluebird'), Promise = bluebird;
var bcrypt = bluebird.promisifyAll(require('bcrypt'));
var raise = require('../raise');
var helpers = require('../helpers'),
    findUser = helpers.findUser,
    extractParams = helpers.extractParams;

module.exports = function(adapter, middleware, opts) {
  var users = adapter.users;

  /**
   * User creation middleware.
   *
   * This takes care of creating a user and properly creating a secure password
   * digest for the user.
   *
   * When creation is successful, this middleware sets the following:
   *
   *  - `req.auth.user` is set to information about the authenticated user that
   *    is safe to send back to the client.
   *  - `req.auth.db.user` is set to the authenticated user.
   *  - `req.auth.token` is set to the value of the most recently generated
   *    token that can be used to authenticate further requests.
   *  - `res.headers['Authorization']` to the authorization token.
   *
   * @function
   */
  return function(req, res, next) {
    Promise.resolve()
    .bind({})
    .then(extractParams(req, opts.params.create, 'username', 'password'))
    .then(findUser(adapter, opts))
    .tap(raise.verify.not.defined(422, 'username taken'))
    .then(function() {
      return bcrypt.hashAsync(this.password, opts.bcryptRounds);
    })
    .then(function(digest) { this.passwordDigest = digest; })
    .then(function() {
      var attributes = {};
      attributes[opts.username] = this.username;
      attributes[opts.passwordDigest] = this.passwordDigest;
      return users.create(attributes);
    })
    .tap(raise.verify.defined(500, 'server error', '(failed to create user)'))
    .then(function(user) { this.user = user; })
    .then(function() { return middleware._login(this.user, req, res); })
    .then(function() {
      next();
    })
    .catch(raise.catch(function(e) {
      req.auth = {};
      res.json(e.code, { error: e.message });
    }))
    .done();
  };
};
