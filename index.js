const express = require('express');
const app = express();
//const https = require('https');
const fs = require('fs');

//Import Routes
const assessors = require('./Router/assessor');
//const api_docs = require('./Router/api_docs');

/*const httpsServerOption = {
    'key': fs.readFileSync('./https/privatekey.pem'),
    'cert': fs.readFileSync('./https/certificate.pem')
};*/

//App level Middleware
//app.use('/api', api_docs);
app.use('/api/assessor', assessors);


//Start the server
//var httpsServer = https.createServer(httpsServerOption, app);

app.listen('3000', () => console.log('Server up and running'));