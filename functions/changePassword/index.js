/*
 * Change Password
 *
 * Verify password token, then update password hash in DynamoDB
 * and remove password token.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /password/change
 * @method: POST
 * @params:
 *      - username [string]
 *      - password: raw password data to update [string]
 *      - token: password token [string]
 * @returns:
 *      - username [string]
 *      - service [string]
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const bcrypt = require('bcrypt');
const saltRounds = 10;


exports.handle = function handler(event, context) {
  if (!event.username) {
    context.fail('Bad Request: Missing username parameter.');
    return;
  }
  if (!event.password) {
    context.fail('Bad Request: Missing password parameter.');
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

  dynamo.query(userParams, (userErr, userData) => {
    if (userErr) {
      context.fail('Internal Error: Failed to get user info.');
      return;
    }
    if (userData.Count > 0) {
      const tokens = userData.Items.filter(function (items) {
        return items.passwordToken;
      }).map(function (items) {
        return items.passwordToken;
      });
      /*
       * Check token matches that in one of the users
       * registered services.
       */
      const idx = tokens.indexOf(event.token);
      if (idx === -1) {
        context.fail('Unprocessable Entity: No token found.');
        return;
      }
      if (userData.Items[idx].passwordToken !== event.token) {
        context.fail('Unprocessable Entity: Invalid token');
        return;
      }
      const service = userData.Items[idx].service;
      const hash = bcrypt.hashSync(event.password, saltRounds);
      const updateParams = {
        TableName: 'users',
        Key: {
          service,
          username: event.username,
        },
        UpdateExpression: 'SET password = :pwd REMOVE passwordToken',
        ExpressionAttributeValues: {
          ':pwd': hash,
        },
      };
      dynamo.update(updateParams, (updateErr) => {
        if (updateErr) {
          context.fail('Internal Error: Failed to update data.');
          return;
        }
        context.succeed({
          username: event.username,
          service,
        });
      });
    } else {
      context.fail('Unprocessable Entity: Invalid username.');
      return;
    }
  });
};
