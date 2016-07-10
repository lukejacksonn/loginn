/*
 * Authenticate User
 *
 * Find username in DynamoDB, validate password, and
 * return cognito credentials for jwt authentication.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /authenticate
 * @method: POST
 * @params:
 *      - username/email: username or email to authenticate [string]
 *      - password: raw password data to validate [string]
 *      - service: service name to authenticate [string]
 * @returns:
 *      - token: authentication token [string]
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
    context.fail('Bad Request: Missing password parameter in request.');
    return;
  }
  if (!event.service) {
    context.fail('Bad Request: Missing service parameter in request.');
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
      context.fail('Not Found: User not registered');
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
    // Check password and return cognito identity.
    if (bcrypt.compareSync(event.password, userData.Items[idx].password)) {
      /*
       * Parameters to get identity from cognito, if one
       * doesn't exist, one is created for this user in the
       * loginss identity pool.
       */
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
        context.succeed({
          username,
          token: tokenData.Token,
        });
      });
    } else {
      context.fail('Unprocessable Entity: Incorrect password.');
      return;
    }
  });
};
