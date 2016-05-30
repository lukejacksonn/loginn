/*
 * Loginn Authenticate
 * Find username in DynamoDB, validate password, and
 * return cognito credentials for jwt.
 * Note: Build external node modules with
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
// Latest cognito must be configured in Virginia.
aws.config.region = 'us-east-1';
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');
const bcrypt = require('bcrypt');
const saltRounds = 10;


exports.handle = function newOne(event, context) {
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

  const userParams = {
    TableName: 'users',
    KeyConditionExpression: 'username = :val',
    ExpressionAttributeValues: {
      ':val': event.username,
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
      'login.loginns': event.username,
    },
  };
  // Hash the received password to validate
  const hash = bcrypt.hashSync(event.password, saltRounds);

  dynamo.query(userParams, (err, data) => {
    if (err) {
      context.fail('Internal Error: Failed to find user.');
    }
    // No entries found in DynamoDB for user.
    if (data.Count === 0) {
      context.fail('Not Found: Failed to find user.');
    }
    // Check password and return cognito identity.
    if (bcrypt.compareSync(data.Items[0].password, hash)) {
      cognito.getOpenIdTokenForDeveloperIdentity(tokenParams, (tokenErr, tokenData) => {
        if (tokenErr) {
          context.fail('Internal Error: Failed to get open ID token');
        }
        context.succeed({
          identity_id: tokenData.IdentityId,
          token: tokenData.Token,
        });
      });
    }
  });
};
