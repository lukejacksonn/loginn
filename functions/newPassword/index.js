/*
 * New Password
 *
 * Request a new password, this creates a token in DynamoDB, then sends
 * out an email with that token so that only legitimate users can change
 * passwords.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /password/new
 * @method: POST
 * @params:
 *      - username [string]
 *      - service [string]
 * @returns:
 *      - username [string]
 *      - service [string]
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const crypto = require('crypto');
const ses = new aws.SES();


exports.handle = function handler(event, context) {
  if (!event.username) {
    context.fail('Bad Request: Missing username parameter.');
    return;
  }
  if (!event.service) {
    context.fail('Bad Request: Missing service parameter.');
    return;
  }

  const pwdToken = crypto.randomBytes(32).toString('hex');
  const updateParams = {
    TableName: 'users',
    Key: {
      service: event.service,
      username: event.username,
    },
    UpdateExpression: 'SET passwordToken = :pwd',
    ExpressionAttributeValues: {
      ':pwd': pwdToken,
    },
  };
  const userParams = {
    TableName: 'users',
    Key: {
      service: event.service,
      username: event.username,
    },
  };

  dynamo.get(userParams, (userErr, userData) => {
    if (userErr) {
      context.fail('Internal Error: Failed to get user info.');
      return;
    }
    dynamo.update(updateParams, (updateErr) => {
      if (updateErr) {
        context.fail('Internal Error: Failed to update database.');
        return;
      }
      const emailParams = {
        Source: 'joe0robot@gmail.com',
        Destination: {
          ToAddresses: [userData.Item.email],
        },
        Message: {
          Body: {
            Html: {
              Data: `
      <p>${event.username},</p>

      <p>To change your password for ${event.service}, click the link below.</p>

      <a href="loginn.s3-eu-west-1.amazonaws.com/change_password.html?username=${event.username}&token=${pwdToken}">
      Change Password
      </a>

      <p><small>Brought to you by Loginn</small></p>
              `,
              Charset: 'UTF-8',
            },
          },
          Subject: {
            Data: `Change password for ${event.username}.`,
            Charset: 'UTF-8',
          },
        },
      };
      ses.sendEmail(emailParams, (emailErr) => {
        if (emailErr) {
          context.fail('Internal Error: Failed to send change password email');
          return;
        }
        context.succeed({
          username: event.username,
          service: event.service,
        });
      });
    });
  });
};
