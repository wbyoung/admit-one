'use strict';

require('./helpers');

var sinon = require('sinon');
var expect = require('chai').expect;

var admit = require('..');
var path = require('path');
var bluebird = require('bluebird'), Promise = bluebird;

describe('admit-one', function() {
  before(function() {
    this.admit = admit('fake');
  });

  beforeEach(function() {
    this.user = { username: 'user', passwordDigest: 'digest' };
    this.req = {};
    this.res = {};
    this.res.setHeader = sinon.spy();
    this.results = {};
    this.results.authorizationHeader = 'Token 123';
    this.results.findByToken = this.user;
    this.req.get = sinon.spy(function(header) {
      return header === 'Authorization' && this.results.authorizationHeader;
    }.bind(this));
    sinon.stub(this.admit._adapter.users, 'findByToken',
      function() { return this.results.findByToken; }.bind(this));
  });

  afterEach(function() {
    this.admit._adapter.users.findByToken.restore();
  });

  describe('authorize', function() {
    it('rejects requests without authorization header', function(done) {
      this.results.authorizationHeader = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'invalid credentials (token)' });
        done();
      };
      this.admit.authorize(this.req, this.res, function() {
        throw new Error('what');
      });
    });

    it('restricts access when token is invalid', function(done) {
      this.results.findByToken = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'invalid credentials (user lookup)' });
        done();
      };
      this.admit.authorize(this.req, this.res, null);
    });

    it('authorizes when token is valid', function(done) {
      this.admit.authorize(this.req, this.res, function() {
        expect(this.req.auth.user).to.eql({ username: 'user' });
        expect(this.req.auth.db.user).to.eql(this.user);
        expect(this.req.auth.token).to.eql('123');
        done();
      }.bind(this));
    });
  });
});
