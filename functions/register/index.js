/*
 * Register User
 *
 * Add user to DynamoDB, and generate a cognito id.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /register
 * @method: POST
 * @params:
 *      - username: username to register [string]
 *      - password: raw password data to hash [string]
 *      - email: email address of user [string]
 *      - service: service to register user [string]
 * @returns:
 *      - username: username to register [string]
 *      - email: email address of user [string]
 *      - service: service to register user [string]
 *      - identityId: cognito identity id [string]
 *      - token: cognito token for jwt [string]
 *
 * @deploy: apex deploy
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');
const bcrypt = require('bcrypt');
const saltRounds = 10;


exports.handle = function handler(event, context) {
  /*
   * Check required request parameters.
   */
  if (!event.username) {
    context.fail('Bad Request: Missing username parameter in request.');
    return;
  }

  if (!event.password) {
    context.fail('Bad Request: Missing password parameter in request.');
    return;
  }

  if (!event.email) {
    context.fail('Bad Request: Missing email parameter in request.');
    return;
  }

  if (!event.service) {
    context.fail('Bad Request: Missing service parameter in request.');
    return;
  }
  // Hash the received password to store in DynamoDB.
  const hash = bcrypt.hashSync(event.password, saltRounds);
  /*
   * Parameters for adding data to users table in DynamoDB.
   */
  const userParams = {
    TableName: 'users',
    Item: {
      username: event.username,
      password: hash,
      email: event.email,
      service: event.service,
    },
  };
  /*
   * Parameters for creating identity in cognito identity pool loginns.
   * If IdentityId is null, then one is created.
   */
  const tokenParams = {
    IdentityId: null,
    IdentityPoolId: settings.identityPoolId,
    Logins: {
      'login.loginns': event.username,
    },
  };
  cognito.getOpenIdTokenForDeveloperIdentity(tokenParams, (tokenErr, tokenData) => {
    if (tokenErr) {
      context.fail('Internal Error: Failed to add cognito identity');
      return;
    }
    /*
     * Add new user data to DynamoDB.
     */
    dynamo.put(userParams, (err) => {
      if (err) {
        context.fail('Internal Error: Failed to add user.');
        return;
      }
      context.succeed({
        username: event.username,
        email: event.email,
        service: event.service,
        identityId: tokenData.IdentityId,
        token: tokenData.Token,
      });
    });
  });
};
