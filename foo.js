var logger = require('./index.js').set('thetag', 'user', 'error', 'unix', '/dev/log');

logger.warn("this is a warning, shouldn't be logged!");
logger.error("this is an ERROR, should be logged!");
