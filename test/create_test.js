'use strict';

require('./helpers');

var sinon = require('sinon');
var expect = require('chai').expect;

var admit = require('..');
var path = require('path');
var bluebird = require('bluebird'), Promise = bluebird;

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
    this.res.setHeader = sinon.spy();
    this.results = {};
    this.results.find = this.user;
    sinon.stub(this.admit._adapter.users, 'find',
      function() { return this.results.find; }.bind(this));
    sinon.stub(this.admit._adapter.users, 'create',
      function() { return this.results.create; }.bind(this));
  });
  afterEach(function() {
    this.admit._adapter.users.find.restore();
    this.admit._adapter.users.create.restore();
  });

  describe('create', function() {
    it('requires body', function(done) {
      this.res.json = function(code, json) {
        expect(code).to.eql(400);
        expect(json).to.eql({ error: 'missing body' });
        done();
      };
      this.admit.create(this.req, this.res, null);
    });

    it('requires username', function(done) {
      this.req.body = { user: { password: 'hello' } };
      this.res.json = function(code, json) {
        expect(code).to.eql(400);
        expect(json).to.eql({ error: 'missing parameter user[username]' });
        done();
      };
      this.admit.create(this.req, this.res, null);
    });

    it('requires password', function(done) {
      this.req.body = { user: { username: 'hello' } };
      this.res.json = function(code, json) {
        expect(code).to.eql(400);
        expect(json).to.eql({ error: 'missing parameter user[password]' });
        done();
      };
      this.admit.create(this.req, this.res, null);
    });

    it('fails when user already exists', function(done) {
      this.req.body = { user: this.user };
      this.res.json = function(code, json) {
        expect(code).to.eql(422);
        expect(json).to.eql({ error: 'username taken' });
        done();
      };
      this.admit.create(this.req, this.res, null);
    });

    it('creates users', function(done) {
      this.req.body = { user: this.user };
      this.results.find = null;
      this.results.create = { special: 'user' };
      this.admit.create(this.req, this.res, function() {
        expect(this.res.setHeader).to.have.been.calledOnce;
        expect(this.res.setHeader).to.have.been.calledWith('Authorization', 'Token 7a4d3e2073a542549a174900bb2ed824');
        expect(this.req.auth.user).to.eql({ special: 'user' });
        expect(this.req.auth.token).to.eql('7a4d3e2073a542549a174900bb2ed824');
        done();
      }.bind(this));
    });
  });
});
