const aws = require('aws-sdk');
aws.config.update({ region: 'eu-west-1' });
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
aws.config.region = 'us-east-1';
const cognito = new aws.CognitoIdentity();
const settings = require('./settings.json');

exports.handle = function handler(event, context) {
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

  const userParams = {
    TableName: 'users',
    Item: {
      username: event.username,
      password: event.password,
      email: event.email,
      service: event.service,
    },
  };
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
    }
    dynamo.put(userParams, (err) => {
      if (err) {
        context.fail('Internal Error: Failed to add user.');
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
