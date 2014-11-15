'use strict';

var _ = require('lodash');
var bluebird = require('bluebird'), Promise = bluebird;
var crypto = require('crypto');
var raise = require('../raise');

module.exports = function(adapter, middleware, opts) {
  var users = adapter.users;
  var attrs = adapter.attrs;
  var extract = require('./extract')(adapter, middleware, opts);

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
    extract(req, res, function(err) {
      if (err) { next(err); }

      Promise.resolve().then(function() {
        var auth = req.auth;
        if (!auth.token) { raise(401, 'invalid credentials', '(token)'); }
        if (!auth.user) { raise(401, 'invalid credentials', '(user lookup)'); }
      })
      .then(next)
      .catch(raise.catch(function(e) {
        req.auth = {};
        res.json(e.code, { error: e.message });
      }))
      .done();
    });
  };
};
