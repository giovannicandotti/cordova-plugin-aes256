var exec = require('cordova/exec');

exports.encrypt = function(plaintext, password, success, error) {
    exec(success, error, "AES256", "encrypt", [plaintext, password]);
};

exports.decrypt = function(ciphertext, password, success, error) {
    exec(success, error, "AES256", "decrypt", [ciphertext, password]);
};

module.exports = exports;
