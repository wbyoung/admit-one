'use strict';

var _ = require('lodash');
var bluebird = require('bluebird'), Promise = bluebird;
var crypto = require('crypto');
var raise = require('../raise');

module.exports = function(adapter, middleware, opts) {
  var users = adapter.users;
  var attrs = adapter.attrs;

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
  return function(req, res, next) {
    Promise.resolve()
    .bind({})
    .then(function() {
      var authorization = req.get('Authorization');
      var match = authorization && authorization.match(/^token\s+(\w+)$/i);
      var token = this.token = match && match[1];
      if (!token) { raise(401, 'invalid credentials', '(token)'); }
      var digest = crypto.createHash('sha1').update(token).digest('hex');
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
};
