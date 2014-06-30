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
    this.req.auth = {
      user: {},
      db: { user: {} },
      token: ''
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

    it('invalidates sessions');
    it('fails if token removal fails');
  });
});
