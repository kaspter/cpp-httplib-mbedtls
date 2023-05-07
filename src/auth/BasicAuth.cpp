
#include "BasicAuth.h"
BasicAuth::BasicAuth(string username, string password)
    : username(username), password(password) {}

string BasicAuth::getHeaderValue() {
    string secret = this->username + ":" + this->password;
    return "Basic " + base64_encode(secret);
}