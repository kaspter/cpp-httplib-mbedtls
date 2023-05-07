//
//  client.cc
//
//  MIT License
//

#include "yhirose/httplib.h"
#include <iostream>

#define CA_CERT_FILE "./ca-bundle.crt"

using namespace std;
using namespace httplib;

using SecurityParams = std::multimap<std::string, std::string>;

#define CONTENT_TYPE "application/VIID+JSON;charset=UTF-8"

static Headers get_common_req_header(const string& deviceId) {
    Headers headers = {
        { "Accept", "application/json,application/*+json" },
        { "Content-Type", CONTENT_TYPE },
        { "User-Identify", deviceId },
        { "User-Agent", "nan-gat1400/1.0" }
    };
    return headers;
}

std::string hex_string(const std::string& input) {
    std::string output;
    char buffer[3];
    for (unsigned char c : input) {
        std::snprintf(buffer, 3, "%02x", c);
        output += buffer;
    }
    return output;
}

#if CPPHTTPLIB_USE_MBEDTLS
std::string aes256_ecb(const std::string& plain, const std::string& key) {
    // Set up the key
#define AES_BLOCK_SIZE 16
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    unsigned char aes_key[32];
    memcpy(aes_key, key.c_str(), 32);

    mbedtls_aes_setkey_enc(&ctx, aes_key, 256);

    // Set up the output buffer
    std::string output;
    output.resize(plain.size() + AES_BLOCK_SIZE);

    // Add PKCS#7 padding to the plaintext
    int padding_len = AES_BLOCK_SIZE - (plain.size() % AES_BLOCK_SIZE);
    std::string padded_plain = plain + std::string(padding_len, (char) padding_len);

    // Encrypt the padded data
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (const unsigned char*)padded_plain.c_str(), (unsigned char*)output.data());

    // Clean up
    mbedtls_aes_free(&ctx);

    // Resize the output to the actual size of the encrypted data
    output.resize(plain.size() + padding_len);

    // Return the encrypted data
    return output;
}
#elif CPPHTTPLIB_USE_OPENSSL

std::string aes256_ecb(const std::string& plain, const std::string& key) {
#define AES_BLOCK_SIZE 16
    // Initialize the library
    OpenSSL_add_all_algorithms();

    // Set up the key
    unsigned char aes_key[32];
    memcpy(aes_key, key.c_str(), 32);

    // Set up the cipher context
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Initialize the cipher
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);

    // Set up the output buffer
    std::string output;
    output.resize(plain.size() + AES_BLOCK_SIZE);

    // Encrypt the data
    int len;
    EVP_EncryptUpdate(ctx, (unsigned char*)output.data(), &len, (unsigned char*)plain.c_str(), plain.size());

    // Finalize the encryption
    int final_len;
    EVP_EncryptFinal_ex(ctx, (unsigned char*)(output.data() + len), &final_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize the output to the actual size of the encrypted data
    output.resize(len + final_len);

    // Return the encrypted data
    return output;
}

#else

std::string aes256_ecb(const std::string& plain, const std::string& key) {
    return {};
}

#endif

int main(void) {

  // httplib::SSLClient cli(ip, port);
  // httplib::SSLClient cli("google.com");
  // httplib::SSLClient cli("www.youtube.com");
  // cli.set_ca_cert_path(CA_CERT_FILE);
  // cli.enable_server_certificate_verification(true);

    if (0) {
        auto host = "baidu.com";
        httplib::Client cli(host);
        if (auto res = cli.Get("/")) {
            cout << res->status << endl;
            cout << res->get_header_value("Content-Type") << endl;
            cout << res->body << endl;
        } else {
            cout << "error code: " << res.error() << std::endl;
        }
    }

    if (1) {
      auto host = "jsonplaceholder.typicode.com";
#ifdef CPPHTTPLIB_HTTPS_SUPPORT
      httplib::SSLClient cli(host);
      cli.enable_server_certificate_verification(true);
#else
      httplib::Client cli(host);
#endif
      cli.set_connection_timeout(std::chrono::seconds(2));
      if (auto res = cli.Get("/todos/1")) {
        cout << res->status << endl;
        cout << res->get_header_value("Content-Type") << endl;
        cout << res->body << endl;
      } else {
        cout << "error code: " << res.error() << std::endl;
      }
    }

#ifdef CPPHTTPLIB_HTTPS_SUPPORT
    if (1) {
        auto host = "https://vis.komect.com:8886";
        auto deviceId = "3824112000000009";
        auto username = "3824112000000009";
        auto password = "1DssK9w8";
        auto realm = "aiplatform";
        auto uri = "/gateway/config/clientConfig/get";

        auto A1 = std::string(username) + ":" + std::string(realm) + ":" + std::string(password);
        auto aesKey = detail::MD5(A1);
        // std::string nonce = "helloworld";
        std::string nonce = detail::random_string(10);
        std::string sign = hex_string(aes256_ecb(nonce, aesKey));

        cout << nonce << endl;
        cout << sign << endl;

        SecurityParams params = {
            {"deviceId", deviceId},
            {"nonce", nonce},
            {"sign", sign}
        };

        string url(uri);
        if (!params.empty()) {
            url += "?";
            url += detail::params_to_query_str(params);
        }

        Headers headers = get_common_req_header(deviceId);

        httplib::Client cli(host);
        cli.set_keep_alive(true);
        cli.set_connection_timeout(std::chrono::seconds(2));
        if (auto res = cli.Get(url.c_str(), headers)) {
            cout << res->status << endl;
            cout << res->get_header_value("Content-Type") << endl;
            cout << res->body << endl;
        } else {
            cout << "error code: " << res.error() << std::endl;
        }
    }
#endif

    if (1) {
        std::string qop = "auth"; // "auth-int"
        std::string user = "hello";
        std::string password = "world";
        auto uri = "/digest-auth/" + qop + "/" + user + "/" + password;

#ifdef CPPHTTPLIB_HTTPS_SUPPORT
        auto host = "https://httpbin.org";
        httplib::Client cli(host);
        cli.set_digest_auth(user, password);
#else
        auto host = "httpbin.org";
        httplib::Client cli(host, 80);
#endif
        if (auto res = cli.Get(uri.c_str())) {
            cout << res->status << endl;
            cout << res->get_header_value("Content-Type") << endl;
            cout << res->body << endl;
        } else {
            cout << "error code: " << res.error() << std::endl;
        }
    }
    return 0;
}
