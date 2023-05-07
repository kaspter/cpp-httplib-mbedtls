#ifndef DIGESTAUTH_H
#define DIGESTAUTH_H

#include "../utils/hashing.h"
#include "Auth.h"
#include <map>
#include <vector>

using std::map;
using std::pair;
using std::string;
using std::vector;
using DigestAuthParams = map<string, string>;
enum class ErrorCode {
    missing_params_value,
    empty_params,
    invalid_algorithm,
    error,
    ok
};

class DigestAuth : public Auth {
  public:
    DigestAuth(DigestAuthParams *params = nullptr);
    string getHeaderValue();
    pair<string, ErrorCode> getA1Hash();
    pair<string, ErrorCode> getA2Hash();
    ~DigestAuth() {}

  private:
    DigestAuthParams params;
    bool isParamsEmpty;
    string getItemFromListStr(string, string);
    bool isInParams(string);
    string getHashUsingAlgo(string);
    string generateHeaderValue(string, string, string);
    vector<string> nonSessionAlgorithms;
    vector<string> SessionAlgorithms;
    bool isAlgorithmConfirmed;
    int nonce_cnt;
};

#endif
