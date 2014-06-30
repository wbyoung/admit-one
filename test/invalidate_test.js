'use strict';

var sinon = require('sinon');
var chai = require('chai');
var expect = chai.expect;
chai.use(require('sinon-chai'));

var admit = require('..');
var path = require('path');
var bluebird = require('bluebird'), Promise = bluebird;

require('./allow-fixture-loading');

describe('admit-one', function() {
  before(function() {
    sinon.stub(admit.__uuid, 'v4').returns('7a4d3e20-73a5-4254-9a17-4900bb2ed824');
    this.admit = admit('fake');
  });
  after(function() {
    admit.__uuid.v4.restore();
  });

  beforeEach(function() {
    this.user = { username: 'user', password: 'password' };
    this.req = {};
    this.res = {};
    this.req.auth = {
      user: {},
      db: { user: {} },
      token: 'AB83212'
    };
    this.res.setHeader = sinon.spy();
    this.results = {};
    this.results.removeToken = true;
    sinon.stub(this.admit._adapter.users, 'removeToken',
      function() { return this.results.removeToken; }.bind(this));
  });

  afterEach(function() {
    this.admit._adapter.users.removeToken.restore();
  });

  describe('invalidate', function() {
    it('only works when already authorized', function(done) {
      this.req.auth = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'not authorized (auth)' });
        expect(this.admit._adapter.users.removeToken).to.not.been.called;
        done();
      }.bind(this);
      this.admit.invalidate(this.req, this.res, null);
    });

    it('fails if authorization is missing user', function(done) {
      this.req.auth.user = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'not authorized (auth[user])' });
        expect(this.admit._adapter.users.removeToken).to.not.been.called;
        done();
      }.bind(this);
      this.admit.invalidate(this.req, this.res, null);
    });

    it('fails if authorization is missing db user', function(done) {
      this.req.auth.db.user = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'not authorized (auth[db][user])' });
        expect(this.admit._adapter.users.removeToken).to.not.been.called;
        done();
      }.bind(this);
      this.admit.invalidate(this.req, this.res, null);
    });

    it('fails if authorization is missing token', function(done) {
      this.req.auth.token = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'not authorized (auth[token])' });
        expect(this.admit._adapter.users.removeToken).to.not.been.called;
        done();
      }.bind(this);
      this.admit.invalidate(this.req, this.res, null);
    });

    it('fails if token removal fails', function(done) {
      this.results.removeToken = false;
      this.res.json = function(code, json) {
        expect(code).to.eql(500);
        expect(json).to.eql({ error: 'server error (failed to remove token)' });
        expect(this.admit._adapter.users.removeToken).to.have.been.called;
        done();
      }.bind(this);
      this.admit.invalidate(this.req, this.res, null);
    });

    it('invalidates sessions', function(done) {
      this.admit.invalidate(this.req, this.res, function() {
        expect(this.res.setHeader).to.have.been.calledOnce;
        expect(this.res.setHeader).to.have.been.calledWith('Authorization', 'Invalidated');
        expect(this.req.auth.user).to.not.exist;
        expect(this.req.auth.db.user).to.not.exist;;
        expect(this.req.auth.token).to.not.exist;
        expect(this.admit._adapter.users.removeToken).to.have.been.called;
        done();
      }.bind(this));

    });
  });
});
