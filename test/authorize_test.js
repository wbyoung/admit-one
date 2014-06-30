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

  describe('authorize', function() {
    it('ignores requests without authorization header');
    it('authorizes when token is valid');
    it('restricts access when token is invalid valid');
  });
});