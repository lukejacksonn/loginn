/*
 * Verify Email
 *
 * Checks verification token, if successful then add cognito identity
 * then remove token from DynamoDB.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /verify
 * @method: GET
 * @query:
 *      - username [string]
 *      - token: verification token [string]
 * @returns:
 *      - redirect to service
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');


exports.handle = function handler(event, context) {
  if (!event.username) {
    context.fail('Bad Request: Missing username parameter.');
    return;
  }
  if (!event.token) {
    context.fail('Bad Request: Missing token parameter.');
    return;
  }
  /*
   * Get verificationToken token from DynamoDB.
   */
  const userParams = {
    TableName: 'users',
    KeyConditionExpression: 'username = :usr',
    ExpressionAttributeValues: {
      ':usr': event.username,
    },
  };
  dynamo.query(userParams, (userErr, userData) => {
    if (userErr) {
      context.fail('Internal Error: Failed to get user data.');
      return;
    }
    if (userData.Count === 0) {
      context.fail('Unprocessable Entity: User not found.');
      return;
    }
    const tokens = userData.Items.filter(function (items) {
      return items.verificationToken;
    }).map(function (items) {
      return items.verificationToken;
    });
    /*
     * Check token matches that in one of the users
     * registered services.
     */
    const idx = tokens.indexOf(event.token);
    if (idx === -1) {
      context.fail('Unprocessable Entity: Invalid token.');
      return;
    }
    const service = userData.Items[idx].service;
    /*
     * Parameters for creating identity in cognito identity pool loginns.
     * If IdentityId is null, then one is created.
     */
    const tokenParams = {
      IdentityPoolId: settings.identityPoolId,
      Logins: {
        'login.loginns': event.username,
      },
    };
    cognito.getOpenIdTokenForDeveloperIdentity(tokenParams, (tokenErr) => {
      if (tokenErr) {
        context.fail('Internal Error: Failed to add cognito identity');
        return;
      }
      const updateParams = {
        TableName: 'users',
        Key: {
          service,
          username: event.username,
        },
        UpdateExpression: 'REMOVE verificationToken',
      };
      dynamo.update(updateParams, (updateErr) => {
        if (updateErr) {
          context.fail('Internal Error: Failed to update DynamoDB.');
          return;
        }
        /*
         * Redirect to service.
         */
        context.succeed({ location: service });
      });
    });
  });
};
