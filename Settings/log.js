const log4js = require("log4js");
const moment = require("moment");
const dotenv = require("dotenv");
var filename = "Log_" + moment().format("DDMMMYYYY");

dotenv.config();

// Logger configuration
log4js.configure({
    appenders: {
        fileAppender: {
            type: "file",
            filename: `${process.env.base_url}Logs/${filename}.txt`,
        },
    },
    categories: { default: { appenders: ["fileAppender"], level: "info" } },
});
const logger = log4js.getLogger();

function log_info(type, API_Name, UserId = null, missing = null) {
    if (type == "Started") {
        if (UserId)
            logger.info(
                `API CALL STARTED (API NAME: ${API_Name}, User Id: ${UserId})\n`
            );
        else logger.info(`API CALL STARTED (API NAME: ${API_Name})\n`);
    } else if (type == "Ended") {
        if (UserId)
            logger.info(
                `API CALL ENDED (API NAME: ${API_Name}, User Id: ${UserId})\n`
            );
        else logger.info(`API CALL ENDED (API NAME: ${API_Name})\n`);
    } else if (type == "Missing") {
        if (UserId)
            logger.info(
                `Missing/Invalid ${missing} (API NAME: ${API_Name}, User Id: ${UserId})\n`
            );
        else logger.info(`Missing/Invalid ${missing} (API NAME: ${API_Name})\n`);
    } else if (type == "Unauthorized")
        logger.info(
            `Unauthorized API Request! (API NAME: ${API_Name}, User Id: ${UserId})\n`
        );
}

function log_error(API_Name, err) {
    logger.error(`Error while calling API ${API_Name}\n${err.stack}\n `);
}

module.exports = { log_info, log_error };