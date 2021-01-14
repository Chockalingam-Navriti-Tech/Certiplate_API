const express = require("express");
const router = express.Router();
const dotenv = require("dotenv");
const bodyparser = require("body-parser");
const multer = require("multer");
const db = require("../DB_Connection/pg_connect");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const { log_info, log_error } = require("../Settings/log");
const upload = multer();
const cookieparser = require("cookie-parser");
const fs = require("fs");

var reqData;
dotenv.config();

router.use(bodyparser.json());
router.use(bodyparser.urlencoded({ extended: false }));
router.use(upload.array());
router.use(cookieparser());

var opts = {};
opts.jwtFromRequest = (req) => {
    var token = null;
    if (req && req.cookies) {
        token = req.cookies["jwt"];
    }
    return token;
};
opts.secretOrKey = fs.readFileSync("./RSA/rsa.public");

router.use(function(req, res, next) {
    reqData = Object.keys(req.query).length !== 0 ? req.query : req.body;
    next();
});

passport.use(
    new JwtStrategy(opts, async function(payload, done) {
        console.log("JWT based authentication");
        if (payload.data.AuthenticationResponseData.UserId) {
            return done(null, payload);
        } else {
            return done(new Error("Unauthorized"), null);
        }
    })
);

router.use(passport.initialize());

router.post("/GetAuthenticationResponseDataRequest", function(req, res) {
    var apikey = "'" + process.env.apikey + "'";
    var response = {
        AuthenticationResponseData: {
            StatusId: 0,
            Message: null,
            UserId: 0,
            UserName: "",
            Email: "",
            AccountStatus: 0,
            EmailActivationStatus: 0,
            UserRoleId: 0,
            UserRoleName: "",
            SessionId: "",
        },
    };
    if (!reqData.ApiKey || reqData.ApiKey != apikey) {
        log_info("Started", "GetAuthenticationResponseDataRequest", reqData.UserId);
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message = "Unauthorized API Request!";
        log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
        log_info(
            "Unauthorized",
            "GetAuthenticationResponseDataRequest",
            reqData.UserId
        );
        res.status(401).send(response);
        return;
    }

    if (!reqData.UserId || reqData.UserId < 0) {
        log_info("Started", "GetAuthenticationResponseDataRequest", reqData.UserId);
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message = "Missing/Invalid UserId";
        log_info(
            "Missing",
            "GetAuthenticationResponseDataRequest",
            reqData.UserId,
            "UserId"
        );
        log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
        res.send(response);
        return;
    }
    if (!reqData.Password) {
        log_info("Started", "GetAuthenticationResponseDataRequest", reqData.UserId);
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message = "Missing/Invalid Password";
        log_info(
            "Missing",
            "GetAuthenticationResponseDataRequest",
            reqData.UserId,
            "Password"
        );
        log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
        res.send(response);
        return;
    }
    if (!reqData.ClientIpAddress) {
        log_info("Started", "GetAuthenticationResponseDataRequest", reqData.UserId);
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message =
            "Missing/Invalid ClientIpAddress";
        log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
        log_info(
            "Missing",
            "GetAuthenticationResponseDataRequest",
            reqData.UserId,
            "ClientIpAddress"
        );
        res.send(response);
        return;
    }
    if (!reqData.ClientBrowser) {
        log_info("Started", "GetAuthenticationResponseDataRequest", reqData.UserId);
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message =
            "Missing/Invalid ClientBrowser";
        log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
        log_info(
            "Missing",
            "GetAuthenticationResponseDataRequest",
            reqData.UserId,
            "ClientBrowser"
        );
        res.send(response);
        return;
    }
    try {
        log_info("Started", "GetAuthenticationResponseDataRequest", reqData.UserId);
        //throw new Error('error');
        const connection = new db();
        const query = `SELECT * from users.fn_get_authentication_response_data(${reqData.UserId},${reqData.Password},${reqData.ClientIpAddress},${reqData.ClientBrowser})`;
        connection.Query_Function(query, function(varlistData) {
            response.AuthenticationResponseData.StatusId =
                varlistData[0]["status_id"];
            response.AuthenticationResponseData.Message = varlistData[0]["message"];
            response.AuthenticationResponseData.UserId = varlistData[0]["user_id"];
            response.AuthenticationResponseData.UserName =
                varlistData[0]["user_name"];
            response.AuthenticationResponseData.Email = varlistData[0]["email"];
            response.AuthenticationResponseData.AccountStatus =
                varlistData[0]["account_status"];
            response.AuthenticationResponseData.EmailActivationStatus =
                varlistData[0]["email_active_status"];
            response.AuthenticationResponseData.UserRoleId =
                varlistData[0]["user_role_id"];
            response.AuthenticationResponseData.UserRoleName =
                varlistData[0]["user_role_name"];
            response.AuthenticationResponseData.SessionId =
                varlistData[0]["session_id"];
            if (varlistData[0]["message"] == "User authentication success") {
                const token = jwt.sign({ data: response },
                    fs.readFileSync("./RSA/rsa.private"), {
                        algorithm: 'RS256',
                        expiresIn: "1h",
                    }
                );
                res.cookie("jwt", token);
            }
            log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
            res.send(response);
        });
    } catch (err) {
        log_error("GetAuthenticationResponseDataRequest", err);
        log_info("Ended", "GetAuthenticationResponseDataRequest", reqData.UserId);
        res.status(500).send('Error');
    }
});

router.post(
    "/",
    passport.authenticate("jwt", { session: false }),
    function(req, res) {
        if (req.user.data.AuthenticationResponseData.UserId == reqData.UserId) {
            res.send("hi");
        } else {
            res.status(401).send("Unauthorized");
        }
    }
);
module.exports = router;