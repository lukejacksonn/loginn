/*
 * Validate Token
 *
 * Checks that a user is still authenticated. Tokens expire
 * every 15 minutes, so authenticate should be called to update.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /validate/{username}/{token}
 * @method: POST
 * @params:
 *      - username [string]
 *      - token: jwt token from cognito [string]
 * @returns:
 *      - username [string]
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');
const jwt = require('jsonwebtoken');


exports.handle = function handler(event, context) {
  if (!event.username) {
    context.fail('Bad Request: Missing username parameter.');
    return;
  }
  if (!event.service) {
    context.fail('Bad Request: Missing service parameter');
    return;
  }
  if (!event.token) {
    context.fail('Bad Request: Missing token parameter.');
    return;
  }
  const userParams = {
    TableName: 'users',
    KeyConditionExpression: 'username = :usr',
    ExpressionAttributeValues: {
      ':usr': event.username,
    },
  };
  /*
   * Query user table to check user is registered for service.
   */
  dynamo.query(userParams, (userErr, userData) => {
    if (userErr) {
      context.fail('Internal Error: Failed to query database.');
      return;
    }
    if (userData.Count > 0) {
      const services = userData.Items.map(function(items) {
        return items.service;
      });
      if (services.indexOf(event.service) === -1) {
        context.fail(`Unprocessable Entity: User not registered for ${event.service}`);
      }
      /*
       * Check JWT for authentication.
       */
      const timestamp = (new Date()).getTime();
      const decoded = jwt.decode(event.token);
      if (decoded && decoded.hasOwnProperty('exp') &&
          decoded.hasOwnProperty('sub')) {
        const idParams = {
          IdentityPoolId: settings.identityPoolId,
          DeveloperUserIdentifier: event.username,
          MaxResults: 1,
        };
        /*
         * Check developer authenticated user exists in
         * the identity pool. If so, check the identity
         * id matches that in the token.
         */
        cognito.lookupDeveloperIdentity(idParams, (idError, idData) => {
          if (idError) {
            context.fail(`Unprocessable Entity: ${event.username} not registered.`);
            return;
          }
          if (!idData.IdentityId) {
            context.fail('Internal Error: Failed to get identity id');
            return;
          }
          if (idData.IdentityId !== decoded.sub) {
            context.fail('Unauthorized: User identity/token mismatch.');
            return;
          }
          if (decoded.exp <= timestamp / 1000.0) {
            context.fail('Unauthorized: Token has expired.');
            return;
          }
          context.succeed({ username: event.username });
        });
      } else {
        context.fail('Unprocessable Entity: Failed to parse token.');
        return;
      }
    } else {
      context.fail(`Unprocessable Entity: ${event.username} is not registered.`);
      return;
    }
  });
};
