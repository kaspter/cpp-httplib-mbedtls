#ifndef BASIC_AUTH_H
#define BASIC_AUTH_H

#include "../utils/base64.h"
#include "Auth.h"

class BasicAuth : public Auth {
  public:
    BasicAuth(string, string);
    string getHeaderValue();
    ~BasicAuth() {}

  private:
    string username;
    string password;
};

#endif