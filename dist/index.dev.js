"use strict";

var express = require('express');

var app = express(); //const https = require('https');

var fs = require('fs'); //Import Routes


var assessors = require('./Router/assessor');

var api_docs = require('./Router/api-docs');
/*const httpsServerOption = {
    'key': fs.readFileSync('./https/privatekey.pem'),
    'cert': fs.readFileSync('./https/certificate.pem')
};*/
//App level Middleware


app.use('/api', api_docs);
app.use('/api/assessor', assessors); //Start the server
//var httpsServer = https.createServer(httpsServerOption, app);

app.listen('3000', function () {
  return console.log('Server up and running');
});