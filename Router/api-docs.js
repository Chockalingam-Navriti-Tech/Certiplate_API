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
 * 
 * /api/assessor/GetSectorwiseAssessorCertificationStatusCountDataRequest:
 *      post:
 *          summary: Get a sectorwise assessor detailed response using User Id
 *          description: Used to get sectorwise assessor details
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Assessor Dashboard Related API's
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
 *                description: Enter User Id
 *                type: integer
 *              - in: formData
 *                name: UserRoleId
 *                required: true
 *                description: Enter User Role Id
 *                type: integer
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  SectorwiseAssessorCertificationStatusCountData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *                                          CertificationStatusData:
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      SectorId:
 *                                                          type: integer
 *                                                      SectorName:
 *                                                          type: string
 *                                                      GovernmentLeadCount:
 *                                                          type: integer
 *                                                      GovernmentApprovedCount:
 *                                                          type: integer
 *                                                      GovernmentCertifiedCount:
 *                                                          type: integer
 *                                                      GovernmentExpiredCount:
 *                                                          type: integer
 *                                                      GovernmentTotalCount:
 *                                                          type: integer
 *                                                      GovernmentDistinctTotalCount:
 *                                                          type: integer
 *                                                      InstitutionLeadCount:
 *                                                          type: integer
 *                                                      InstitutionApprovedCount:
 *                                                          type: integer
 *                                                      InstitutionCertifiedCount:
 *                                                          type: integer
 *                                                      InstitutionTotalCount:
 *                                                          type: integer
 *                                                      InstitutionDistinctTotalCount:
 *                                                          type: integer
 *                                                      TotalCount:
 *                                                          type: integer
 *                                                      DistinctTotalCount:
 *                                                          type: integer                         
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/GetStatewiseAssessorCountDataRequest:
 *      post:
 *          summary: Get a statewise assessor detailed response using User Id
 *          description: Used to get statewise assessor details
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Assessor Dashboard Related API's
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
 *                description: Enter User Id
 *                type: integer
 *              - in: formData
 *                name: UserRoleId
 *                required: true
 *                description: Enter User Role Id
 *                type: integer
 *              - in: formData
 *                name: SectorId
 *                required: true
 *                description: Enter Sector Id
 *                type: integer
 *              - in: formData
 *                name: QualificationPackId
 *                required: false
 *                description: Enter Qualification Pack Id
 *                type: integer
 *              - in: formData
 *                name: SearchType
 *                required: true
 *                description: Enter Search Type
 *                type: string
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  StatewiseAssessorCountData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *                                          StatewiseAssessorData:
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      StateId:
 *                                                          type: integer
 *                                                      StateName:
 *                                                          type: string
 *                                                      AssessorCount:
 *                                                          type: integer                      
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * 
 * /api/assessor/GetQPwiseAssessorCertificationStatusCountDataRequest:
 *      post:
 *          summary: Get a qpwise assessor detailed response using User Id
 *          description: Used to get qpwise assessor details
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Assessor Dashboard Related API's
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
 *                description: Enter User Id
 *                type: integer
 *              - in: formData
 *                name: UserRoleId
 *                required: true
 *                description: Enter User Role Id
 *                type: integer
 *              - in: formData
 *                name: SectorId
 *                required: true
 *                description: Enter Sector Id
 *                type: integer
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  QPwiseAssessorCertificationStatusCountData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *                                          CertificationStatusData:
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      SectorId:
 *                                                          type: integer
 *                                                      SectorName:
 *                                                          type: string
 *                                                      QualificationPackId:
 *                                                          type: integer
 *                                                      QualificationPackCode:
 *                                                          type: integer
 *                                                      QualificationPackName:
 *                                                          type: integer
 *                                                      GovernmentLeadCount:
 *                                                          type: integer
 *                                                      GovernmentApprovedCount:
 *                                                          type: integer
 *                                                      GovernmentCertifiedCount:
 *                                                          type: integer
 *                                                      GovernmentExpiredCount:
 *                                                          type: integer
 *                                                      GovernmentTotalCount:
 *                                                          type: integer
 *                                                      GovernmentDistinctTotalCount:
 *                                                          type: integer
 *                                                      InstitutionLeadCount:
 *                                                          type: integer
 *                                                      InstitutionApprovedCount:
 *                                                          type: integer
 *                                                      InstitutionCertifiedCount:
 *                                                          type: integer
 *                                                      InstitutionTotalCount:
 *                                                          type: integer
 *                                                      InstitutionDistinctTotalCount:
 *                                                          type: integer
 *                                                      TotalCount:
 *                                                          type: integer
 *                                                      DistinctTotalCount:
 *                                                          type: integer                         
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/GetAssessorCertificationDetailedDataRequest:
 *      post:
 *          summary: Get assessor certificate detailed response using User Id
 *          description: Used to get assessor certification details
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Assessor Dashboard Related API's
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
 *                description: Enter User Id
 *                type: integer
 *              - in: formData
 *                name: UserRoleId
 *                required: true
 *                description: Enter User Role Id
 *                type: integer
 *              - in: formData
 *                name: SectorId
 *                required: true
 *                description: Enter Sector Id
 *                type: integer
 *              - in: formData
 *                name: QualificationPackId
 *                required: false
 *                description: Enter Qualification Pack Id
 *                type: integer
 *              - in: formData
 *                name: SearchType
 *                required: true
 *                description: Enter Search Type
 *                type: string
 *              - in: formData
 *                name: StateId
 *                required: true
 *                description: Enter State Id
 *                type: integer
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  AssessorCertificationDetailedData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *                                          AssessorData:
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      AssessorId:
 *                                                          type: integer
 *                                                      AssessorName:
 *                                                          type: string
 *                                                      AssessorEmail:
 *                                                          type: string
 *                                                      AssessorPhone:
 *                                                          type: string
 *                                                      AssessorAlternatePhone:
 *                                                          type: string
 *                                                      AllocationType:
 *                                                          type: string
 *                                                      DateOfUpload:
 *                                                          type: string
 *                                                      District:
 *                                                          type: string
 *                                                      State:
 *                                                          type: string
 *                                                      AadhaarNumber:
 *                                                          type: string
 *                                                      PanCardNumber:
 *                                                          type: string
 *                                                      AssessorStatus:
 *                                                          type: string
 *                                                      Sector:
 *                                                          type: string
 *                                                      QualificationPacks:
 *                                                          type: string
 *                                                      SscCertificationIssuedBy:
 *                                                          type: string
 *                                                      SscCertificateFileName:
 *                                                          type: string
 *                                                      SscCertificationIssuedDate:
 *                                                          type: string
 *                                                      SscCertificationExpiryDate:
 *                                                          type: string
 *                                                      LanguagesKnown:
 *                                                          type: string
 *                                                      AssessorSource:
 *                                                          type: string
 *                                                      SourcedByUserName:
 *                                                          type: string
 *                                                      BankName:
 *                                                          type: string
 *                                                      BankAccountNumber:
 *                                                          type: string
 *                                                      IFSC:
 *                                                          type: string
 *                                                      ChequeFileName:
 *                                                          type: string
 *                                                      MouFileName:
 *                                                          type: string
 *                                                      AssessorImageFileName:
 *                                                          type: string
 *                                                      ResumeFileName:
 *                                                          type: string
 *                                                      EducationCertificateFileName:
 *                                                          type: string
 *                                                      ExperienceCertificateFileName:
 *                                                          type: string                       
 *              400:
 *                  description: Error in Connection
 *              401:
 *                  description: Unauthorized
 *              403:
 *                  description: Forbidden from access
 *              404:
 *                  description: Not Found
 * 
 * /api/assessor/GetAssessmentCandidateDataRequest:
 *      post:
 *          summary: Get candidate assessment data detailed response
 *          description: Used to get candidate assessment data
 *          consumes:
 *              - multipart/form-data
 *          tags:
 *              - Batch Related API's
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
 *                description: Enter User Id
 *                type: integer
 *              - in: formData
 *                name: RequestId
 *                required: true
 *                description: Enter Request Id
 *                type: integer
 *          responses:
 *              200:
 *                  description: A successful response
 *                  schema:
 *                              type: object
 *                              properties:
 *                                  AssessmentCandidateData:
 *                                      type: object
 *                                      properties:
 *                                          StatusId:
 *                                              type: integer
 *                                              description: Return 1 if success else -1
 *                                          Message:
 *                                              type: string
 *                                              description: Returns the message related to the request
 *                                          RequestId:
 *                                              type: integer
 *                                              description: Return Request Id
 *                                          SDMSBatchId:
 *                                              type: string
 *                                              description: Return Sdms Batch Id
 *                                          Candidates:
 *                                              type: array
 *                                              items:
 *                                                  type: object
 *                                                  properties:
 *                                                      CandidateId:
 *                                                          type: integer
 *                                                      CandidateName:
 *                                                          type: string
 *                                                      RegistrationId:
 *                                                          type: string
 *                                                      ContactNumber:
 *                                                          type: string
 *                                                      Gender:
 *                                                          type: string
 *                                                      GuardianName:
 *                                                          type: string
 *                                                      Assessments:
 *                                                          type: array
 *                                                          items:
 *                                                              type: object
 *                                                              properties:
 *                                                                  ScheduleId:
 *                                                                      type: integer
 *                                                                  AssessmentId:
 *                                                                      type: integer
 *                                                                  AssessmentCategory:
 *                                                                      type: string
 *                                                                  AssessmentStatus:
 *                                                                      type: string
 *                                                                  ExamMode:
 *                                                                      type: integer                                                                                      
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