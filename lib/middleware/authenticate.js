'use strict';

var bluebird = require('bluebird'), Promise = bluebird;
var bcrypt = bluebird.promisifyAll(require('bcrypt'));
var raise = require('../raise');
var helpers = require('../helpers'),
    findUser = helpers.findUser,
    extractParams = helpers.extractParams;

module.exports = function(adapter, middleware, opts) {
  var users = adapter.users;
  var attrs = adapter.attrs;

  /**
   * Authentication middleware
   *
   * Authenticate a user given a request to generate a new session. The request
   * must contain a body with `session[email]` and `session[passowrd]`. The
   * user will be authenticated. If unsuccessful, this middleware simply
   * returns the proper HTTP error code and does not allow further middleware
   * to process the request. If successful, the middleware generates a new
   * token for later authorization requests, and updates the user in the
   * database to contain that value.
   *
   * When authentication is successful, this middleware sets the following:
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
    .then(extractParams(req, opts.params.authenticate, 'username', 'password'))
    .then(findUser(adapter, opts))
    .tap(raise.verify.defined(401, 'invalid credentials', '(username)'))
    .then(function(user) { this.user = user; })
    .then(function() { return attrs.all(this.user)[opts.passwordDigest]; })
    .then(function(digest) {
      return bcrypt.compareAsync(this.password, digest);
    })
    .tap(raise.verify.defined(401, 'invalid credentials', '(password)'))
    .then(function() { return middleware.login(this.user, req, res); })
    .then(function() { next(); })
    .catch(raise.catch(function(e) {
      req.auth = {};
      res.json(e.code, { error: e.message });
    }))
    .done();
  };
};
