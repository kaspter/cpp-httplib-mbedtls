#ifndef AUTH_H
#define AUTH_H

#include <string>
using std::string;

class Auth {
  public:
    Auth(){};
    virtual string getHeaderValue() = 0;
    ~Auth() {}
};
#endif