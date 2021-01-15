"use strict";

var express = require('express');

var router = express();

var swaggerJsDoc = require('swagger-jsdoc');

var swaggerUi = require('swagger-ui-express');

var swaggerOptions = {
  swaggerDefinition: {
    info: {
      title: "Assessor API's",
      description: "List of Assessor API's Description",
      servers: ['http://localhost:3000']
    }
  },
  apis: ['./Router/*.js']
};
var swaggerDocs = swaggerJsDoc(swaggerOptions);
var options = {
  customCss: '.swagger-ui .topbar { display : none } .swagger-ui .scheme-container { display : none }',
  customSiteTitle: 'Certiplate API',
  customfavIcon: './assets/favicon.ico'
};
router.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, options));
module.exports = router;