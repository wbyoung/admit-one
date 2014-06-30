'use strict';

var sinon = require('sinon');
var chai = require('chai');
var expect = chai.expect;
chai.use(require('sinon-chai'));

var admit = require('..');
var path = require('path');
var bluebird = require('bluebird'), Promise = bluebird;

describe('admit-one', function() {
  before(function() {
    sinon.stub(admit.__uuid, 'v4').returns('7a4d3e20-73a5-4254-9a17-4900bb2ed824');
    this.admit = admit(path.join(__dirname, './fixtures/admit-one-fake'));
  });
  after(function() {
    admit.__uuid.v4.restore();
  });

  beforeEach(function() {
    var digest = '$2a$04$7XP/cI3x8zmvsRuv5ODUWevSjALzmu8KjSerpXVPaT8EfJPR69Zrm';
    this.user = { username: 'user', passwordDigest: digest };
    this.session = { username: 'user', password: 'password' };
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

  describe('authenticate', function() {
    it('requires body', function(done) {
      this.res.json = function(code, json) {
        expect(code).to.eql(400);
        expect(json).to.eql({ error: 'missing body' });
        done();
      };
      this.admit.authenticate(this.req, this.res, null);
    });

    it('requires username', function(done) {
      this.req.body = { session: { password: 'hello' } };
      this.res.json = function(code, json) {
        expect(code).to.eql(400);
        expect(json).to.eql({ error: 'missing parameter session[username]' });
        done();
      };
      this.admit.authenticate(this.req, this.res, null);
    });

    it('requires password', function(done) {
      this.req.body = { session: { username: 'hello' } };
      this.res.json = function(code, json) {
        expect(code).to.eql(400);
        expect(json).to.eql({ error: 'missing parameter session[password]' });
        done();
      };
      this.admit.authenticate(this.req, this.res, null);
    });

    it('fails for missing users', function(done) {
      this.req.body = { session: this.session };
      this.results.find = undefined;
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'invalid credentials (username)' });
        done();
      };
      this.admit.authenticate(this.req, this.res, null);
    });

    it('fails for wrong passwords', function(done) {
      this.req.body = { session: { username: 'user', password: 'invalid' } };
      this.res.json = function(code, json) {
        expect(code).to.eql(401);
        expect(json).to.eql({ error: 'invalid credentials (password)' });
        done();
      };
      this.admit.authenticate(this.req, this.res, null);
    });

    it('authenticates users', function(done) {
      this.req.body = { session: this.session };
      this.admit.authenticate(this.req, this.res, function() {
        expect(this.res.setHeader).to.have.been.calledOnce;
        expect(this.res.setHeader).to.have.been.calledWith('Authorization', 'Token 7a4d3e2073a542549a174900bb2ed824');
        expect(this.req.auth.user).to.eql({ username: 'user' });
        expect(this.req.auth.db.user).to.eql(this.user);
        expect(this.req.auth.token).to.eql('7a4d3e2073a542549a174900bb2ed824');
        done();
      }.bind(this));
    });
  });
});
