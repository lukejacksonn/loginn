/*
 * Refresh Token
 *
 * Validates current token and generates a new one.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /refresh
 * @method: POST
 * @params:
 *      - username [string]
 *      - token: jwt token from cognito [string]
 *      - service: website [string]
 * @returns:
 *      - username [string]
 *      - service: website [string]
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
      const idx = services.indexOf(event.service);
      if (idx === -1) {
        context.fail(`Unprocessable Entity: User not registered for ${event.service}`);
        return;
      }
      const cognitoId = userData.Items[idx].cognitoId;
      /*
       * Check JWT for authentication.
       */
      const decoded = jwt.decode(event.token);
      if (decoded && decoded.hasOwnProperty('exp') &&
          decoded.hasOwnProperty('sub')) {
        const idParams = {
          IdentityPoolId: settings.identityPoolId,
          DeveloperUserIdentifier: `${event.username}_${cognitoId}`,
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
          const tokenParams = {
            IdentityPoolId: settings.identityPoolId,
            Logins: {
              'login.loginns': `${event.username}_${cognitoId}`,
            },
          };
          cognito.getOpenIdTokenForDeveloperIdentity(tokenParams, (tokenErr, tokenData) => {
            if (tokenErr) {
              context.fail('Internal Error: Failed to get cognito identity');
              return;
            }
            context.succeed({
              username: event.username,
              service: event.service,
              token: tokenData.Token,
            });
          });
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
