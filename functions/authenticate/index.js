const aws = require('aws-sdk');
aws.config.update({ region: 'eu-west-1' });
const dynamo = new aws.DynamoDB.DocumentClient({ region: 'eu-west-1' });

exports.handle = function (event, context) {
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
  const params = {
    TableName: 'users',
    FilterExpression: filter,
    ExpressionAttributeValues: {
      ':val': value,
    },
  };

  dynamo.scan(params, function(err, data) {
    context.succeed({'err': err, 'data': data});
    if (err) {
      context.fail('Internal Error: Failed to find user.');
    }
    if (data.Count === 0) {
      context.fail('Not Found: Failed to find user.');
    }
    // Check password
    if (data.Item[0].password === event.password) {
      context.succeed('Success: User exists');
    }
    context.succeed(data);
  });
};
