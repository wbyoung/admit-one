'use strict';

var _ = require('lodash');
var bluebird = require('bluebird'), Promise = bluebird;
var crypto = require('crypto');
var uuid = require('node-uuid');
var raise = require('../raise');

module.exports = function(adapter, middleware, opts) {
  var users = adapter.users;
  var attrs = adapter.attrs;

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
  return function(user, req, res) {
    return Promise.resolve()
    .bind({})
    .then(function() {
      var token = this.token = uuid.v4().replace(/-/g, '');
      var digest = crypto.createHash('sha1').update(token).digest('hex');
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
};
