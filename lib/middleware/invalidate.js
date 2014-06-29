'use strict';

var bluebird = require('bluebird'), Promise = bluebird;
var crypto = require('crypto');
var raise = require('../raise');

module.exports = function(adapter/*, middleware, opts*/) {
  var users = adapter.users;

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
  return function(req, res, next) {
    Promise.resolve()
    .then(function() {
      if (!req.auth) { raise(401, 'not authorized', '(auth)'); }
      if (!req.auth.user) { raise(401, 'not authorized', '(auth[user])'); }
      if (!req.auth.db.user) { raise(401, 'not authorized', '(auth[db][user])'); }
      if (!req.auth.token) { raise(401, 'not authorized', '(auth[token])'); }
    })
    .then(function() {
      var digest = crypto.createHash('sha1')
        .update(req.auth.token).digest('hex');
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
};
