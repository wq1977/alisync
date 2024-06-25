module.exports = function getLog(name) {
  var bunyan = require("bunyan");
  var log = bunyan.createLogger({ name, serializers: bunyan.stdSerializers });
  return log;
};
