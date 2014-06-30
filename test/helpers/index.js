var path = require('path');
var chai = require('chai');
var bluebird = require('bluebird');

process.env.NODE_PATH = path.resolve(path.join(__dirname, '../fixtures'));
require('module')._initPaths();

chai.use(require('sinon-chai'));

bluebird.longStackTraces();
