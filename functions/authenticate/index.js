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
  /*
   * Parameters to get identity from cognito, if one
   * doesn't exist, one is created for this user in the
   * loginss identity pool.
   */
  const tokenParams = {
    IdentityPoolId: settings.identityPoolId,
    Logins: {
      'login.loginns': event.username || event.email,
    },
  };

  dynamo.scan(userParams, (err, data) => {
    if (err) {
      context.fail('Internal Error: Failed to scan database.');
      return;
    }
    // No entries found in DynamoDB for user.
    if (data.Count === 0) {
      context.fail(`Not Found: No user registered for ${event.service}.`);
      return;
    }
    // Check password and return cognito identity.
    // -- Use first result for now.
    if (bcrypt.compareSync(event.password, data.Items[0].password)) {
      cognito.getOpenIdTokenForDeveloperIdentity(tokenParams, (tokenErr, tokenData) => {
        if (tokenErr) {
          context.fail('Internal Error: Failed to get open ID token.');
          return;
        }
        context.succeed({
          token: tokenData.Token,
        });
      });
    } else {
      context.fail('Unprocessable Entity: Incorrect password.');
      return;
    }
  });
};
