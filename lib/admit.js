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

module.exports = function(adapter, options) {
  var exports = {};
  var opts = defaults({}, options, {
    username: 'username',
    password: 'password',
    params: { create: {}, authenticate: {} },
    bcryptRounds: 12
  });

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


  // create the adapter and give it access to all of the options that have been
  // passed to admit-one.
  try { adapter = require('admit-one-' + adapter)(opts); }
  catch (e) {
    try { adapter = require(adapter)(opts); }
    catch (e) {
      throw new Error('Could not find admit-one adapter ' + adapter + '.');
    }
  }

  var users = adapter.users;
  var attrs = adapter.attrs;
  exports._adapter = adapter;

  var extractParams = function(req, names/*, param, ...*/) {
    var params = Array.prototype.slice.call(arguments, 2);
    return function() {
      if (!req.body) { raise(400, 'missing body'); }
      params.forEach(function(name) {
        if (!(this[name] = param(req.body, names[name]))) {
          raise(400, 'missing parameter ' + names[name]);
        }
      }, this);
    };
  };

  var findUser = function() {
    var query = {};
    query[opts.username] = this.username;
    return users.find(query);
  };

  var createHexDigest = function(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
  };

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
      var digest = createHexDigest(token);
      return users.addToken(user, digest);
    })
    .tap(raise.verify.defined(500, 'server error', '(failed to add token)'))
    .then(function() {
      req.auth = req.auth || {};
      req.auth.user = _.omit(attrs.all(user), opts.passwordDigest);
      req.auth.db = { user: user };
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
   *  - `req.auth.user` is set to information about the authenticated user that
   *    is safe to send back to the client.
   *  - `req.auth.db.user` is set to the authenticated user.
   *  - `req.auth.token` is set to the value of the most recently generated
   *    token that can be used to authenticate further requests.
   *  - `res.headers['Authorization']` to the authorization token.
   *
   * @function
   */
  exports.create = function(req, res, next) {
    Promise.resolve()
    .bind({})
    .then(extractParams(req, opts.params.create, 'username', 'password'))
    .then(findUser)
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
   *  - `req.auth.user` is set to information about the authenticated user that
   *    is safe to send back to the client.
   *  - `req.auth.db.user` is set to the authenticated user.
   *  - `req.auth.token` is set to the value of the most recently generated
   *    token that can be used to authenticate further requests.
   *  - `res.headers['Authorization']` to the authorization token.
   *
   * @function
   */
  exports.authenticate = function(req, res, next) {
    Promise.resolve()
    .bind({})
    .then(extractParams(req, opts.params.authenticate, 'username', 'password'))
    .then(findUser)
    .tap(raise.verify.defined(401, 'invalid credentials', '(username)'))
    .then(function(user) { this.user = user; })
    .then(function() { return attrs.all(this.user)[opts.passwordDigest]; })
    .then(function(digest) {
      return bcrypt.compareAsync(this.password, digest);
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
   *  - `req.auth.user` is set to information about the authenticated user that
   *    is safe to send back to the client.
   *  - `req.auth.db.user` is set to the authenticated user.
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
      var digest = createHexDigest(token);
      return users.findByToken(digest);
    })
    .tap(raise.verify.defined(401, 'invalid credentials', '(user lookup)'))
    .then(function(user) { this.user = user; })
    .then(function() {
      req.auth = req.auth || {};
      req.auth.user = _.omit(attrs.all(this.user), opts.passwordDigest);
      req.auth.db = { user: this.user };
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
   *  - `req.auth.user` is set to undefined.
   *  - `req.auth.db.user` is set to undefined.
   *  - `req.auth.token` is set to undefined.
   *
   * @function
   */
  exports.invalidate = function(req, res, next) {
    Promise.resolve()
    .then(function() {
      if (!req.auth) { raise(401, 'not authorized', '(auth)'); }
      if (!req.auth.user) { raise(401, 'not authorized', '(auth[user])'); }
      if (!req.auth.db.user) { raise(401, 'not authorized', '(auth[db][user])'); }
      if (!req.auth.token) { raise(401, 'not authorized', '(auth[token])'); }
    })
    .then(function() {
      var digest = createHexDigest(req.auth.token);
      return users.removeToken(req.auth.db.user, digest);
    })
    .tap(raise.verify.defined(500, 'server error', '(failed to remove token)'))
    .then(function() {
      req.auth.user = undefined;
      req.auth.db.user = undefined;
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
