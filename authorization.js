'use strict';
const jwt = require('jsonwebtoken'); // https://github.com/auth0/node-jsonwebtoken
const { SECRET_KEY } = process.env;

module.exports.register = (event, context, callback) => {
    const token = jwt.sign(event.body, SECRET_KEY);

    callback(null, {
        statusCode: 200,
        body: JSON.stringify({ token })
    });
};

const verifyToken = (token, key) => {
    try {
        return jwt.verify(token, key);
    } catch (error) {
        return null;
    }
}

const generatePolicy = (token, methodArn) => {
    const isAuthorized = verifyToken(token, SECRET_KEY);

    if (isAuthorized && methodArn) {
        const principalId = 'user';

        const policyDocument = {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: 'Allow',
                    Resource: methodArn,
                }
            ],
        }

        return { principalId, policyDocument };
    } else {
      throw new Error('Unauthorized');
    }
};

module.exports.authorize = (event, context, callback) => {
    try {
        const policy = generatePolicy(event.authorizationToken, event.methodArn);
        callback(null, policy);
    } catch (error) {
        callback(error.message);
    }
};
