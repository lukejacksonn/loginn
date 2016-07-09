/*
 * Register User
 *
 * Add user to DynamoDB, and generate a cognito id.
 *
 * @url: https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta
 * @resource: /register
 * @method: POST
 * @params:
 *      - username: username to register [string]
 *      - password: raw password data to hash [string]
 *      - email: email address of user [string]
 *      - service: service to register user [string]
 * @returns:
 *      - username: username to register [string]
 *      - email: email address of user [string]
 *      - service: service to register user [string]
 *
 * @deploy: npm run deploy
 * @test: npm test
 */
const aws = require('aws-sdk');
aws.config.region = 'eu-west-1';
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });
const ses = new aws.SES();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const url = 'https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta';

var validateEmail = function (email) {
  var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(email);
};

exports.handle = function handler(event, context) {
  /*
   * Check required request parameters.
   */
  if (!event.username) {
    context.fail('Bad Request: Missing username parameter.');
    return;
  }
  if (!event.password) {
    context.fail('Bad Request: Missing password parameter.');
    return;
  }
  if (!event.email) {
    context.fail('Bad Request: Missing email parameter.');
    return;
  }
  if (!event.service) {
    context.fail('Bad Request: Missing service parameter.');
    return;
  }
  if (!validateEmail(event.email)) {
    context.fail('Bad Request: Invalid email address');
    return;
  }
  /*
   * Check user doesn't already exist.
   */
  const existParams = {
    TableName: 'users',
    KeyConditionExpression: 'username = :usr',
    ExpressionAttributeValues: {
      ':usr': event.username,
    },
  };
  dynamo.query(existParams, (existErr, existData) => {
    if (existErr) {
      context.fail('Internal Error: Failed to query database.');
      return;
    }
    if (existData.Count > 0) {
      context.fail('Unprocessable Entity: Username already taken');
      return;
    }
    /*
     * An Error means that the user is not in the identity
     * pool, therefore it is not already registered.
     * Hash the received password to store in DynamoDB.
     */
    const hash = bcrypt.hashSync(event.password, saltRounds);
    /*
     * Add new user data to DynamoDB.
     */
    const userParams = {
      TableName: 'users',
      Item: {
        username: event.username,
        password: hash,
        email: event.email,
        service: event.service,
        validation: crypto.randomBytes(32).toString('hex'),
      },
    };
    dynamo.put(userParams, (userErr) => {
      if (userErr) {
        context.fail('Internal Error: Failed to add user.');
        return;
      }
      const emailParams = {
        Source: 'joe0robot@gmail.com',
        Destination: {
          ToAddresses: [event.email],
        },
        Message: {
          Body: {
            Html: {
              Data: `
<p>${event.username},</p>

<p>Thanks for registering to use ${event.service}.</p>
<p>To complete registration you must verify your email address by clicking the link below.</p>

<a href="${url}/verify/${event.username}/${userParams.Item.validation}">Verify Email Address</a>

<p><small>Brought to you by Loginn</small></p>
              `,
              Charset: 'UTF-8',
            },
          },
          Subject: {
            Data: `Verification for ${event.username}.`,
            Charset: 'UTF-8',
          },
        },
      };
      ses.sendEmail(emailParams, (emailErr) => {
        if (emailErr) {
          context.fail('Internal Error: Failed to send verification email');
          return;
        }
        context.succeed({
          username: event.username,
          email: event.email,
          service: event.service,
        });
      });
    });
  });
};
