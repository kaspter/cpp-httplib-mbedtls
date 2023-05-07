#include "DigestAuth.h"
#include "../utils/utils.h"
#include <sstream>
#include <utility>

using std::make_pair;

DigestAuth::DigestAuth(DigestAuthParams *params) {
    if (params) {
        this->params = *params;
        this->isParamsEmpty = false;
    } else {
        this->isParamsEmpty = true;
    }
    this->nonce_cnt = 0;
    this->isAlgorithmConfirmed = false;
    this->nonSessionAlgorithms.push_back("MD5");
    this->nonSessionAlgorithms.push_back("SHA-256");
    this->nonSessionAlgorithms.push_back("SHA-512-256");
    for (string algo : this->nonSessionAlgorithms) {
        this->SessionAlgorithms.push_back(algo + "-sess");
    }
    if (this->isInParams("qop") != false) {
        this->params["qop"] =
            this->getItemFromListStr(this->params["qop"], ",");
    }
}

string DigestAuth::getHeaderValue() {
    this->nonce_cnt++;
    string a1;
    ErrorCode err;
    std::tie(a1, err) = this->getA1Hash();
    if (err != ErrorCode::ok)
        return "";
    string a2;
    std::tie(a2, err) = this->getA2Hash();
    if (err != ErrorCode::ok)
        return "";
    if (this->isAlgorithmConfirmed == false)
        return "";
    if (this->isInParams("nonce") == false)
        return "";
    if (this->isInParams("qop") == false)
        return "";
    string nonce = this->params["nonce"];
    string qop = this->params["qop"];
    string cnonce = getHashUsingAlgo(nonce);
    std::stringstream ss;
    ss << std::hex << nonce_cnt;
    string nc(ss.str());
    string src =
        a1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + a2;
    string resp = this->getHashUsingAlgo(src);
    string header = this->generateHeaderValue(resp, nc, cnonce);
    return header;
}

pair<string, ErrorCode> DigestAuth::getA1Hash() {
    if (isParamsEmpty)
        return make_pair("No params provided", ErrorCode::empty_params);
    if (this->isInParams("algorithm") == false)
        return make_pair("Algorithm missing", ErrorCode::missing_params_value);
    string algorithm = this->params["algorithm"];
    if (httplib::Contains(this->nonSessionAlgorithms, algorithm) == false) {
        if (httplib::Contains(this->SessionAlgorithms, algorithm) == false)
            return make_pair("Algorithm not supported",
                             ErrorCode::invalid_algorithm);
    }
    this->isAlgorithmConfirmed = true;
    if (this->isInParams("username") == false ||
        this->isInParams("password") == false)
        return make_pair("Username/Password missing",
                         ErrorCode::missing_params_value);
    if (this->isInParams("realm") == false)
        return make_pair("Realm missing", ErrorCode::missing_params_value);
    string src;
    if (httplib::Contains(this->nonSessionAlgorithms, algorithm) == true) {
        src = this->params["username"] + ":" + this->params["realm"] + ":" +
              this->params["password"];
    } else {
        // TODO: add sessioned src using nonce and cnonce
    }
    string digest = this->getHashUsingAlgo(src);
    return make_pair(digest, ErrorCode::ok);
}

pair<string, ErrorCode> DigestAuth::getA2Hash() {
    if (this->isInParams("method") == false)
        return make_pair("method missing", ErrorCode::missing_params_value);
    if (this->isInParams("uri") == false)
        return make_pair("request-uri missing",
                         ErrorCode::missing_params_value);
    if (this->isAlgorithmConfirmed == false) {
        return make_pair("Algorithm not supported",
                         ErrorCode::invalid_algorithm);
    }
    if (this->isInParams("qop") == false)
        return make_pair("qop missing", ErrorCode::missing_params_value);
    string src;
    if (this->params["qop"] == "auth") {
        src = this->params["method"] + ":" + this->params["uri"];
    } else if (this->params["qop"] == "auth-int") {
        // TODO: use entity body, how? src = ?
    }
    string digest = this->getHashUsingAlgo(src);
    return make_pair(digest, ErrorCode::ok);
}
string DigestAuth::getItemFromListStr(string data, string token) {
    size_t tokenPos = data.find(token);
    if (tokenPos == string::npos) {
        return data;
    } else {
        return data.substr(0, tokenPos);
    }
}

bool DigestAuth::isInParams(string key) {
    if (this->params.find(key) == this->params.end())
        return false;
    return true;
}

string DigestAuth::getHashUsingAlgo(string src) {
    string digest;
    string algorithm = this->params["algorithm"];
    if (httplib::Contains(this->nonSessionAlgorithms, algorithm) == true) {
        if (algorithm == "MD5")
            digest = getMD5Hash(src);
        else if (algorithm == "SHA-256" or algorithm == "SHA-512-256")
            digest = getSHA256Hash(src);
    } else {
        // TODO: add sessioned algorithm
    }
    return digest;
}

string DigestAuth::generateHeaderValue(string resp, string nc, string cnonce) {
    string src = "Digest username=" + this->params["username"] + "," +
                 "realm=" + this->params["realm"] + "," +
                 "nonce=" + this->params["nonce"] + "," +
                 "uri=" + this->params["uri"] + "," +
                 "qop=" + this->params["qop"] + "," + "nc=" + nc + "," +
                 "cnonce=" + cnonce + "," + "response=" + resp + "," +
                 "opaque=" + this->params["opaque"];
    return src;
}
