'use strict';

var _ = require('lodash');
var bluebird = require('bluebird'), Promise = bluebird;
var crypto = require('crypto');

module.exports = function(adapter, middleware, opts) {
  var users = adapter.users;
  var attrs = adapter.attrs;

  /**
   * Extraction middleware
   *
   * Extract the user based on information submitted in the HTTP header,
   * `Authorization`. The header must match the format `Token value` where
   * `value` is the token previously given by authentication. If unsuccessful,
   * this middleware does not cause the request to fail.
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
  return function(req, res, next) {
    Promise.resolve()
    .bind({})
    .then(function() {
      var authorization = req.get('Authorization');
      var match = authorization && authorization.match(/^token\s+(\w+)$/i);
      var token = this.token = match && match[1];
      var user;
      if (token) {
        var digest = crypto.createHash('sha1').update(token).digest('hex');
        user = users.findByToken(digest);
      }
      return user;
    })
    .then(function(user) {
      req.auth = req.auth || {};
      req.auth.token = this.token;
      if (user) {
        req.auth.user = _.omit(attrs.all(user), opts.passwordDigest);
        req.auth.db = { user: user };
      }
      next();
    })
    .catch(next)
    .done();
  };
};
