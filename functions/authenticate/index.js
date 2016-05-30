const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
aws.config.region = 'us-east-1';
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');


exports.handle = function handler(event, context) {
  if (!event.username && !event.email) {
    context.fail('Bad Request: Missing username/email parameter in request.');
    return;
  }

  if (!event.password) {
    context.fail('Bad Request: Missing password parameter in request.');
    return;
  }

  const filter = event.username ? 'username = :val' : 'email = :val';
  const value = event.username || event.email;
  const userParams = {
    TableName: 'users',
    KeyConditionExpression: filter,
    ExpressionAttributeValues: {
      ':val': value,
    },
  };
  const tokenParams = {
    IdentityId: settings.IdentityId,
    IdentityPoolId: settings.identityPoolId,
    Logins: {
      'login.loginns': event.username,
    },
  };

  dynamo.query(userParams, (err, data) => {
    if (err) {
      context.fail('Internal Error: Failed to find user.');
    }
    if (data.Count === 0) {
      context.fail('Not Found: Failed to find user.');
    }
    // Check password
    if (data.Items[0].password === event.password) {
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
