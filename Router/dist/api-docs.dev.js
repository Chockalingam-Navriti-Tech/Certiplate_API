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
/**
 * @swagger
 * /api/assessor/GetAuthenticationResponseDataRequest:
 *      post:
 *          summary: Get a login response using your User Id
 *          description: Used to Login a User
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Authentication Related API's
 *          parameters:
 *              - in: formData
 *                name: ApiKey
 *                required: true
 *                description: Enter API Key
 *                type: string
 *                format: password
 *              - in: formData
 *                name: UserId
 *                required: true
 *                description: Enter your User Id
 *                type: string
 *              - in: formData
 *                name: Password
 *                required: true
 *                description: Enter your password
 *                type: string
 *                format: password
 *              - in: formData
 *                name: ClientIpAddress
 *                required: true
 *                description: Enter your Client Ip Address
 *                type: string
 *              - in: formData
 *                name: ClientBrowser
 *                required: true
 *                description: Enter your Client Browser
 *                type: string
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  AuthenticationResponseData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *                                          UserId:
 *                                              type: integer
 *                                              description: Returns User Id
 *                                          UserName:
 *                                              type: string
 *                                              description: Returns User Name
 *                                          Email:
 *                                              type: string
 *                                              description: Returns email address
 *                                          UserRoleId:
 *                                              type: integer
 *                                              description: Returns User Role Id
 *                                          UserRoleName:
 *                                              type: string
 *                                              description: Returns User Role Name
 *                                          AccountStatus:
 *                                              type: integer
 *                                              description: Returns Account Status
 *                                          EmailActivationStatus:
 *                                              type: integer
 *                                              description: Returns Email Activation Status
 *                                          SessionId:
 *                                              type: integer
 *                                              description: Returns Session Id
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/GetLogoutResponseDataRequest:
 *        post:
 *          summary: Get a logout response using your User Id
 *          description: Used to Logout a User
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Authentication Related API's
 *          parameters:
 *              - in: formData
 *                name: ApiKey
 *                required: true
 *                description: Enter API Key
 *                type: string
 *                format: password
 *              - in: formData
 *                name: UserId
 *                required: true
 *                description: Enter your User Id
 *                type: integer
 *              - in: formData
 *                name: SessionId
 *                required: true
 *                description: Enter your SessionId
 *                type: string
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  LogoutResponseData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/ChangeUserPasswordRequest:
 *      post:
 *          summary: Get a Change Password Response Data using your User Id
 *          description: Used to change the password of an User
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Authentication Related API's
 *          parameters:
 *              - in: formData
 *                name: ApiKey
 *                required: true
 *                description: Enter API Key
 *                type: string
 *                format: password
 *              - in: formData
 *                name: UserId
 *                required: true
 *                description: Enter your User Id
 *                type: integer
 *              - in: formData
 *                name: OldPassword
 *                required: true
 *                description: Enter your Old Password
 *                type: string
 *                format: password
 *              - in: formData
 *                name: NewPassword
 *                required: true
 *                description: Enter your New Password
 *                type: string
 *                format: password
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  ChangeUserPasswordData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/GetResetPasswordResponseDataRequest:
 *      post:
 *          summary: Get a Reset Password Response Data using your User Id
 *          description: Used to reset the password for an User
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Authentication Related API's
 *          parameters:
 *              - in: formData
 *                name: ApiKey
 *                required: true
 *                description: Enter API Key
 *                type: string
 *                format: password
 *              - in: formData
 *                name: UserId
 *                required: true
 *                description: Enter your User Id
 *                type: integer
 *              - in: formData
 *                name: Password
 *                required: true
 *                description: Enter the new password that has to be reset
 *                type: string
 *                format: password
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  ResetPasswordResponseData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/SendMailRequest:
 *      post:
 *          summary: Get a mail response using your Mail Id
 *          description: Used to send email to a registered User
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Utility API's
 *          parameters:
 *              - in: formData
 *                name: ApiKey
 *                required: true
 *                description: Enter API Key
 *                type: string
 *                format: password
 *              - in: formData
 *                name: Email
 *                required: true
 *                description: Enter your Email
 *                type: string
 *              - in: formData
 *                name: from
 *                required: true
 *                description: Enter "From" email address
 *                type: string
 *              - in: formData
 *                name: subject
 *                required: true
 *                description: Enter the subject of the mail
 *                type: string
 *              - in: formData
 *                name: type
 *                required: true
 *                description: Enter the type of e-mail to be sent
 *                type: string
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  SendForgotPasswordMailData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 *      
 */

router.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, options));
module.exports = router;