const express = require("express");
const router = express.Router();
const dotenv = require("dotenv");
const bodyparser = require("body-parser");
const multer = require("multer");
const db = require("../DB_Connection/pg_connect");
const schemas = require("../Schemas/assessor_api_schemas");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
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
opts.secretOrKey = fs.readFileSync('./HMAC/secretKey.key', 'utf-8');

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
    var response = schemas.authentication_response;
    if (!reqData.ApiKey || reqData.ApiKey != apikey) {
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message = "Unauthorized API Request!";
        res.status(401).send(response);
        return;
    }

    if (!reqData.UserId || reqData.UserId < 0) {
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message = "Missing/Invalid UserId";
        res.send(response);
        return;
    }
    if (!reqData.Password) {
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message = "Missing/Invalid Password";
        res.send(response);
        return;
    }
    if (!reqData.ClientIpAddress) {
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message =
            "Missing/Invalid ClientIpAddress";
        res.send(response);
        return;
    }
    if (!reqData.ClientBrowser) {
        response.AuthenticationResponseData.StatusId = -1;
        response.AuthenticationResponseData.Message =
            "Missing/Invalid ClientBrowser";
        res.send(response);
        return;
    }
    try {
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
                    fs.readFileSync("./HMAC/secretKey.key", 'utf-8'), {
                        expiresIn: "1h",
                    }
                );
                res.cookie("jwt", token);
            }
            res.send(response);
        });
    } catch (err) {
        console.log(err);
    }
});

router.post(
    "/",
    passport.authenticate("jwt", { session: false }),
    function(req, res) {
        res.send("hi");
    }
);
module.exports = router;