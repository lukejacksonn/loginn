/*
 * apitests.js
 *
 * AWS API Gateway Test Suite for Loginn.
 */
const should = require('should');
const assert = require('assert');
const request = require('supertest');
const sleep = require('sleep');

const baseURL = 'https://7ibd5w7y69.execute-api.eu-west-1.amazonaws.com/beta';
const postmarkURL = 'https://api.postmarkapp.com/';
const email = 'f949e60f1f125e56596f9f4299b279c5@inbound.postmarkapp.com'
const postmarkToken = '14b8a15b-a365-4fbf-9b4f-682fc9534d86';

describe('loginn', function() {
  const username = 'testuser';
  const password = 'salted_hash';
  const service = 'https://somesite.com';
  var token = '';
  var verificationToken = '';
  var passwordToken = '';
  /*
   * Register a test user before running tests.
   */
  before(function(done) {
    const params = { username, password, service, email };
    request(baseURL)
    .post('/register')
    .send(params)
    .end((err, res) => {
      if (err) {
        throw err;
      }
      res.status.should.be.equal(200);
      res.body.should.be.instanceof(Object);
      res.body.should.have.property('username');
      res.body.should.have.property('service');
      res.body.should.have.property('email');
      console.log('    Waiting for registration email..');
      sleep.sleep(20);  // wait until email arrives
      request(postmarkURL)
      .get('/messages/inbound?count=1&offset=0')
      .set('Accept', 'application/json')
      .set('X-Postmark-Server-Token', postmarkToken)
      .end((searchErr, searchRes) => {
        if (searchErr) {
          throw searchErr;
        }
        if (searchRes.body.TotalCount === 0) {
          throw new Error('No registration email received');
        }
        var messageID = searchRes.body.InboundMessages[0].MessageID;
        request(postmarkURL)
        .get(`/messages/inbound/${messageID}/details`)
        .set('Accept', 'application/json')
        .set('X-Postmark-Server-Token', postmarkToken)
        .end((msgErr, msgRes) => {
          if (msgErr) {
            throw msgErr;
          }
          var idx = msgRes.body.HtmlBody.search('token=');
          verificationToken = msgRes.body.HtmlBody.substring(idx + 6, idx + 6 + 64);
          done();
        });
      });
    });
  });
  /*
   * Test that we can verify users email.
   */
  describe('verifyEmail', function() {
    describe('testVerifyEmail', function() {
      it('should return successfully with correct parameters', function(done) {
        request(baseURL)
        .get(`/verify?username=${username}&token=${verificationToken}`)
        .end((err, res) => {
          if (err) {
            throw err;
          }
          res.status.should.be.equal(303);
          res.body.should.be.instanceof(Object);
          res.body.should.have.property('location');
          done();
        });
      });
    });
  });
  /*
   * Test that we can authenticate the new user.
   */
  describe('authenticateUser', function() {
    describe('testAuthenticateUser', function() {
      it('should return successfully with correct parameters', function(done) {
        const params = { username, password, service };
        request(baseURL)
        .post('/authenticate')
        .send(params)
        .end((err, res) => {
          if (err) {
            throw err;
          }
          res.status.should.be.equal(200);
          res.body.should.be.instanceof(Object);
          res.body.should.have.property('username');
          res.body.should.have.property('token');
          res.body.should.have.property('service');
          token = res.body.token;
          done();
        });
      });
    });
  });
  /*
   * Test that we can validate the authenticated user.
   */
  describe('validateUser', function() {
    describe('testValidateUser', function() {
      it('should return successfully with correct parameters', function(done) {
        const params = { username, token, service };
        token.should.not.be.equal('');
        request(baseURL)
        .post('/validate')
        .send(params)
        .end((err, res) => {
          if (err) {
            throw err;
          }
          res.status.should.be.equal(200);
          res.body.should.be.instanceof(Object);
          res.body.should.have.property('username');
          res.body.should.have.property('service');
          done();
        });
      });
    });
  });
  /*
   * Test that we can request a new password.
   */
  describe('newPassword', function() {
    describe('testNewPassword', function() {
      it('should return successfully with correct parameters', function(done) {
        const params = { username, service };
        request(baseURL)
        .post('/password/new')
        .send(params)
        .end((err, res) => {
          if (err) {
            throw err;
          }
          res.status.should.be.equal(200);
          res.body.should.be.instanceof(Object);
          res.body.should.have.property('username');
          res.body.should.have.property('service');
          done();
        });
      });
    });
  });
  /*
   * Test that we can change a users password.
   */
  describe('changePassword', function() {
    describe('testChangePassword', function() {
      it('should return successfully with correct parameters', function(done) {
        console.log('    Waiting for change password email..');
        sleep.sleep(20);  // wait for email to arrive
        request(postmarkURL)
        .get('/messages/inbound?count=1&offset=0')
        .set('Accept', 'application/json')
        .set('X-Postmark-Server-Token', postmarkToken)
        .end((searchErr, searchRes) => {
          if (searchErr) {
            throw searchErr;
          }
          if (searchRes.body.TotalCount === 0) {
            throw new Error('No change password email received');
          }
          var messageID = searchRes.body.InboundMessages[0].MessageID;
          request(postmarkURL)
          .get(`/messages/inbound/${messageID}/details`)
          .set('Accept', 'application/json')
          .set('X-Postmark-Server-Token', postmarkToken)
          .end((msgErr, msgRes) => {
            if (msgErr) {
              throw msgErr;
            }
            var idx = msgRes.body.HtmlBody.search('token=');
            passwordToken = msgRes.body.HtmlBody.substring(idx + 6, idx + 6 + 64);

            const params = { username, password, token: passwordToken };
            request(baseURL)
            .post('/password/change')
            .send(params)
            .end((err, res) => {
              if (err) {
                throw err;
              }
              res.status.should.be.equal(200);
              res.body.should.be.instanceof(Object);
              res.body.should.have.property('username');
              res.body.should.have.property('service');
              done();
            });
          });
        });
      });
    });
  });
  /*
   * Test that we can refresh a token
   */
  describe('refreshToken', function() {
    describe('testRefreshToken', function() {
      it('should return successfully with correct parameters', function(done) {
        const params = { username, token, service };
        token.should.not.be.equal('');
        request(baseURL)
        .post('/refresh')
        .send(params)
        .end((err, res) => {
          if (err) {
            throw err;
          }
          res.status.should.be.equal(200);
          res.body.should.be.instanceof(Object);
          res.body.should.have.property('username');
          res.body.should.have.property('service');
          res.body.should.have.property('token');
          done();
        });
      });
    });
  });
  /*
   * Delete test user after tests complete.
   */
  after(function(done) {
    const params = { username, password, service };
    request(baseURL)
    .delete('/user')
    .send(params)
    .end((err, res) => {
      if (err) {
        throw err;
      }
      res.status.should.be.equal(200);
      res.body.should.be.instanceof(Object);
      res.body.should.have.property('username');
      res.body.should.have.property('service');
      done();
    });
  });
});
