/*
 * Delete User
 *
 * Delete a user account associated with a service in DynamoDB.
 * If there are no other services requiring the cognito identity,
 * then also delete it from the pool.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /{username}
 * @method: DELETE
 * @params:
 *      - username/email [string]
 *      - password [string]
 *      - service [string]
 * @returns:
 *      - username [string]
 *      - service [string]
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');
const bcrypt = require('bcrypt');


exports.handle = function handler(event, context) {
  if (!event.username && !event.email) {
    context.fail('Bad Request: Missing username/email parameter in request.');
    return;
  }
  if (!event.password) {
    context.fail('Bad Request: Missing password parameter.');
    return;
  }
  if (!event.service) {
    context.fail('Bad Request: Missing service parameter.');
    return;
  }

  const filter = event.username ?
                 'username = :val AND service = :srv' :
                 'email = :val AND service = :srv';
  const userParams = {
    TableName: 'users',
    FilterExpression: filter,
    ExpressionAttributeValues: {
      ':val': event.username || event.email,
      ':srv': event.service,
    },
  };

  dynamo.scan(userParams, (userErr, userData) => {
    if (userErr) {
      context.fail('Internal Error: Failed to scan database.');
      return;
    }
    // No entries found in DynamoDB for user.
    if (userData.Count === 0) {
      context.fail('Not Found: No user registered');
      return;
    }
    // Select entry corresponding to service.
    const services = userData.Items.map(function(items) {
      return items.service;
    });
    const idx = services.indexOf(event.service);
    if (idx === -1) {
      context.fail(`Not Found: No user registered for ${event.service}`);
      return;
    }
    const username = userData.Items[idx].username;
    // Check password
    if (bcrypt.compareSync(event.password, userData.Items[idx].password)) {
      const delParams = {
        TableName: 'users',
        Key: {
          username,
          service: event.service,
        },
      };
      dynamo.delete(delParams, (delErr) => {
        if (delErr) {
          context.fail('Internal Error: Failed to delete user from database.');
          return;
        }
        if (userData.Count === 1) {
          // Only registered for this service so we can remove the
          // identity from cognito pool.
          const tokenParams = {
            IdentityPoolId: settings.identityPoolId,
            Logins: {
              'login.loginns': username,
            },
          };
          cognito.getOpenIdTokenForDeveloperIdentity(tokenParams, (tokenErr, tokenData) => {
            if (tokenErr) {
              context.fail('Internal Error: Failed to get open ID token.');
              return;
            }
            const cogParams = {
              IdentityIdsToDelete: [
                tokenData.IdentityId,
              ],
            };
            cognito.deleteIdentities(cogParams, (cogErr) => {
              if (cogErr) {
                context.fail('Internal Error: Failed to delete user identity.');
                return;
              }
              context.succeed({
                username,
                service: event.service,
              });
            });
          });
        }
        context.succeed({
          username,
          service: event.service,
        });
      });
    } else {
      context.fail('Unprocessable Entity: Incorrect password.');
      return;
    }
  });
};
