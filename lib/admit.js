'use strict';

var _ = require('lodash');
var bluebird = require('bluebird'), Promise = bluebird;
var bcrypt = bluebird.promisifyAll(require('bcrypt'));
var crypto = require('crypto');
var uuid = require('node-uuid');
var raise = require('./raise');
var helpers = require('./helpers'),
    param = helpers.param,
    defaults = helpers.defaults;

module.exports = function(options) {
  var exports = {};

  // intentionally extend options object to provide defaults to modules that
  // extend admit-one.
  var opts = defaults(options || {}, {
    username: 'username',
    password: 'password',
    params: { create: {}, authenticate: {} },
    bcryptRounds: 12
  });
  var users = opts._users;
  var attrs = opts._attrs;

  opts.passwordDigest = opts.passwordDigest ||
    opts.password + 'Digest';
  opts.params.create.username = opts.params.create.username ||
    'user[' + opts.username + ']';
  opts.params.create.password = opts.params.create.password ||
    'user[' + opts.password + ']';
  opts.params.authenticate.username = opts.params.authenticate.username ||
    'session[' + opts.username + ']';
  opts.params.authenticate.password = opts.params.authenticate.password ||
    'session[' + opts.password + ']';


  /**
   * Logs in the user.
   *
   * This helper method is designed to be used during user signup. It performs
   * the same steps that are described in the authentication middleware to set
   * up `req.auth` and update the user in the database. It is still the
   * caller's responsibility to return the generated token in the response.
   *
   * @function
   * @return {promise}
   */
  var login = exports.login = function(user, req, res) {
    return Promise.resolve()
    .bind({})
    .then(function() {
      var token = this.token = uuid.v4().replace(/-/g, '');
      var shasum = crypto.createHash('sha1'); shasum.update(token);
      var digest = shasum.digest('hex');
      return users.addToken(user, digest);
    })
    .tap(raise.verify.defined(500, 'server error', '(failed to add token)'))
    .then(function() {
      req.auth = req.auth || {};
      req.auth.user = user;
      req.auth.token = this.token;
      res.setHeader('Authorization', 'Token ' + req.auth.token);
    });
  };

  /**
   * User creation middleware.
   *
   * This takes care of creating a user and properly creating a secure password
   * digest for the user.
   *
   * When creation is successful, this middleware sets the following:
   *
   *  - `req.auth.user` is set to the authenticated user.
   *  - `req.auth.token` is set to the value of the most recently generated
   *    token that can be used to authenticate further requests.
   *  - `res.headers['Authorization']` to the authorization token.
   *
   * @function
   */
  exports.create = function(req, res, next) {
    var params, username, password, passwordDigest;

    Promise.resolve()
    .bind({})
    .then(function() {
      if (!(params = req.body)) { raise(400, 'missing body'); }
      if (!(username = param(params, opts.params.create.username))) {
        raise(400, 'missing parameter ' + opts.params.create.username);
      }
      if (!(password = param(params, opts.params.create.password))) {
        raise(400, 'missing parameter ' + opts.params.create.password);
      }
    })
    .then(function() { return users.find(username); })
    .tap(raise.verify.not.defined(422, 'username taken'))
    .then(function() {
      return bcrypt.hashAsync(password, opts.bcryptRounds);
    })
    .then(function(digest) { passwordDigest = digest; })
    .then(function() {
      return users.create(username, passwordDigest);
    })
    .tap(raise.verify.defined(500, 'server error', '(failed to create user)'))
    .then(function(user) { this.user = user; })
    .then(function() { return login(this.user, req, res); })
    .then(function() {
      next();
    })
    .catch(raise.catch(function(e) {
      req.auth = {};
      res.json(e.code, { error: e.message });
    }))
    .done();
  };


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
   *  - `req.auth.user` is set to the authenticated user.
   *  - `req.auth.token` is set to the value of the most recently generated
   *    token that can be used to authenticate further requests.
   *  - `res.headers['Authorization']` to the authorization token.
   *
   * @function
   */
  exports.authenticate = function(req, res, next) {
    var params, username, password;

    Promise.resolve()
    .bind({})
    .then(function() {
      if (!(params = req.body)) { raise(400, 'missing credentials'); }
      if (!(username = param(params, opts.params.authenticate.username))) {
        raise(400, 'missing parameter ' + opts.params.authenticate.username);
      }
      if (!(password = param(params, opts.params.authenticate.password))) {
        raise(400, 'missing parameter ' + opts.params.authenticate.password);
      }
    })
    .then(function() { return users.find(username); })
    .tap(raise.verify.defined(401, 'invalid credentials', '(username)'))
    .then(function(user) { this.user = user; })
    .then(function() { return attrs.passwordDigest(this.user); })
    .then(function(digest) {
      return bcrypt.compareAsync(password, digest);
    })
    .tap(raise.verify.defined(401, 'invalid credentials', '(password)'))
    .then(function() { return login(this.user, req, res); })
    .then(function() { next(); })
    .catch(raise.catch(function(e) {
      req.auth = {};
      res.json(e.code, { error: e.message });
    }))
    .done();
  };

  /**
   * Authorization middleware
   *
   * Authorize the user based on information submitted in the HTTP header,
   * `Authorization`. The header must match the format `Token value` where
   * `value` is the token previously given by authentication. If unsuccessful,
   * this middleware simply returns the proper HTTP error code and does not
   * allow further middleware to process the request.
   *
   * When authorization is successful, this middleware sets the following:
   *
   *  - `req.auth.user` is set to the authenticated user.
   *  - `req.auth.token` is set to the value of the token used to authenticate
   *    the user.
   *
   * @function
   */
  exports.authorize = function(req, res, next) {
    Promise.resolve()
    .bind({})
    .then(function() {
      var authorization = req.get('Authorization');
      var match = authorization && authorization.match(/^token\s+(\w+)$/i);
      var token = this.token = match && match[1];
      if (!token) { raise(401, 'invalid credentials', '(token)'); }

      var shasum = crypto.createHash('sha1'); shasum.update(token);
      var digest = shasum.digest('hex');

      return users.findByToken(digest);
    })
    .tap(raise.verify.defined(401, 'invalid credentials', '(user lookup)'))
    .then(function(user) { this.user = user; })
    .then(function() {
      req.auth = req.auth || {};
      req.auth.user = this.user;
      req.auth.token = this.token;
      next();
    })
    .catch(raise.catch(function(e) {
      req.auth = {};
      res.json(e.code, { error: e.message });
    }))
    .done();
  };

  /**
   * Middleware for invalidating session
   *
   * Invalidate a session by clearing out a token associated with a user. The
   * token to clear is taken from the authorization information, and it is
   * therefore necessary for this middleware to be installed after the
   * authorization middleware. If unsuccessful, this middleware simply returns
   * the proper HTTP error code and does not allow further middleware to
   * process the request. If successful, the middleware updates the user in the
   * database so the token may no longer be used to authorize requests.
   *
   * When invalidation is successful, this middleware sets the following:
   *
   *  - `req.auth.user` is set to the undefined.
   *  - `req.auth.token` is set to undefined.
   *
   * @function
   */
  exports.invalidate = function(req, res, next) {
    Promise.resolve()
    .then(function() {
      if (!req.auth) { raise(401, 'not authorized', '(auth)'); }
      if (!req.auth.user) { raise(401, 'not authorized', '(auth[user])'); }
      if (!req.auth.token) { raise(401, 'not authorized', '(auth[token])'); }
    })
    .then(function() {
      var shasum = crypto.createHash('sha1'); shasum.update(req.auth.token);
      var digest = shasum.digest('hex');
      return users.removeToken(req.auth.user, digest);
    })
    .tap(raise.verify.defined(500, 'server error', '(failed to remove token)'))
    .then(function() {
      req.auth.user = undefined;
      req.auth.token = undefined;
      res.setHeader('Authorization', 'Invalidated');
      next();
    })
    .catch(raise.catch(function(e) {
      req.auth = {};
      res.json(e.code, { error: e.message });
    }))
    .done();
  };

  return exports;
};

module.exports.__uuid = uuid;
module.exports.helpers = helpers;
