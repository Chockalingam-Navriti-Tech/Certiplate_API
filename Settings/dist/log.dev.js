"use strict";

var log4js = require("log4js");

var moment = require("moment");

var dotenv = require("dotenv");

var filename = "Log_" + moment().format("DDMMMYYYY");
dotenv.config(); // Logger configuration

log4js.configure({
  appenders: {
    fileAppender: {
      type: "file",
      filename: "".concat(process.env.base_url, "Logs/").concat(filename, ".txt")
    }
  },
  categories: {
    "default": {
      appenders: ["fileAppender"],
      level: "info"
    }
  }
});
var logger = log4js.getLogger();

function log_info(type, API_Name) {
  var UserId = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : null;
  var missing = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : null;

  if (type == "Started") {
    if (UserId) logger.info("API CALL STARTED (API NAME: ".concat(API_Name, ", User Id: ").concat(UserId, ")\n"));else logger.info("API CALL STARTED (API NAME: ".concat(API_Name, ")\n"));
  } else if (type == "Ended") {
    if (UserId) logger.info("API CALL ENDED (API NAME: ".concat(API_Name, ", User Id: ").concat(UserId, ")\n"));else logger.info("API CALL ENDED (API NAME: ".concat(API_Name, ")\n"));
  } else if (type == "Missing") {
    if (UserId) logger.info("Missing/Invalid ".concat(missing, " (API NAME: ").concat(API_Name, ", User Id: ").concat(UserId, ")\n"));else logger.info("Missing/Invalid ".concat(missing, " (API NAME: ").concat(API_Name, ")\n"));
  } else if (type == "Unauthorized") logger.info("Unauthorized API Request! (API NAME: ".concat(API_Name, ", User Id: ").concat(UserId, ")\n"));
}

function log_error(API_Name, err) {
  logger.error("Error while calling API ".concat(API_Name, "\n").concat(err.stack, "\n "));
}

module.exports = {
  log_info: log_info,
  log_error: log_error
};