const argon2 = require('argon2');
const axios = require('axios');

const BASE_HOST = 'airk.ai';
const BASE_PATH = '/v1';
const BASE_URL = `https://${BASE_HOST + BASE_PATH}`;

const net = axios.create({ baseURL: BASE_URL });

const isFunction = x => typeof x === 'function';

const checkCredentialHelper = ({ username, password, callback, resolve, reject }) => {
  const isPromise = !isFunction(callback);
  argon2
    .hash(password, {
      hashLength: 64,
      memoryCost: 64,
      parallelism: 8,
      raw: true,
      salt: Buffer.from(username, 'utf8'),
      timeCost: 1,
      type: argon2.argon2id,
    })
    .then((hash) => {
      net
        .post('/credhash', hash, {
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': Buffer.byteLength(hash),
          },
        })
        .then((res) => {
          const { compromised } = res.data;
          if (isPromise) {
            resolve(compromised);
            return;
          }
          callback(null, compromised);
        })
        .catch((err) => {
          if (isPromise) {
            reject(err);
            return;
          }
          callback(err, null);
        });
    })
    .catch((err) => {
      if (isPromise) {
        reject(err);
        return;
      }
      callback(err, null);
    });
};

/**
 * Checks if a credential (username + password)
 * has been compromised. In the argon2id hash,
 * the username is the salt.
 */
const checkCredential = (username, password, callback) => {
  if (isFunction(callback)) {
    checkCredentialHelper({ username, password, callback });
    return;
  }
  return new Promise((resolve, reject) => {
    checkCredentialHelper({ username, password, resolve, reject });
  });
};

module.exports = {
  checkCredential,
};
