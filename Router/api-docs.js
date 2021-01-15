const express = require('express');
const router = express();
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
    swaggerDefinition: {
        info: {
            title: "Assessor API's",
            description: "List of Assessor API's Description",
            servers: ['http://localhost:3000']
        }
    },
    apis: ['./Router/*.js']
}

const swaggerDocs = swaggerJsDoc(swaggerOptions);
var options = {
    customCss: '.swagger-ui .topbar { display : none } .swagger-ui .scheme-container { display : none }',
    customSiteTitle: 'Certiplate API',
    customfavIcon: './assets/favicon.ico'
}
router.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, options));

module.exports = router;