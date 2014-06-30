var path = require('path');

process.env.NODE_PATH = path.resolve(path.join(__dirname, 'fixtures'));
require('module')._initPaths();
