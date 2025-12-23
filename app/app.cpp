#include "crow_all.h"

// g++ -Iasio-1.36.0/include/ app.cpp -lssl -lcrypto -o app.exe

#include <string>
#include <vector>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

//
// -------------------- CORS MIDDLEWARE --------------------
//
struct Cors
{
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context&)
    {
        if (req.method == crow::HTTPMethod::Options)
        {
            res.code = 204;
            res.end();
        }
    }

    void after_handle(crow::request&, crow::response& res, context&)
    {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
    }
};

struct LoggerMiddleware
{
    struct context {};

    void before_handle(crow::request& req, crow::response&, context&)
    {
        CROW_LOG_INFO << "=== REQUEST HEADERS ===";
        for (const auto& h : req.headers)
            CROW_LOG_INFO << h.first << ": " << h.second;
    }

    void after_handle(crow::request&, crow::response& res, context&)
    {
        CROW_LOG_INFO << "=== RESPONSE HEADERS ===";
        for (const auto& h : res.headers)
            CROW_LOG_INFO << h.first << ": " << h.second;
    }
};


//
// -------------------- BASE64 DECODE --------------------
//
std::vector<unsigned char> base64_decode(const std::string& input)
{
    BIO* bio = BIO_new_mem_buf(input.data(), input.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> buffer(input.size());
    int len = BIO_read(bio, buffer.data(), buffer.size());
    buffer.resize(len > 0 ? len : 0);

    BIO_free_all(bio);
    return buffer;
}

//
// -------------------- RSA OAEP DECRYPT --------------------
//
std::string rsa_oaep_decrypt(
    EVP_PKEY* private_key,
    const std::vector<unsigned char>& encrypted
) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) return "";

    if (EVP_PKEY_decrypt_init(ctx) <= 0) return "";

    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &out_len,
                         encrypted.data(), encrypted.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> out(out_len);

    if (EVP_PKEY_decrypt(ctx, out.data(), &out_len,
                         encrypted.data(), encrypted.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);

    // ✅ CRITICAL FIX
    return std::string(reinterpret_cast<char*>(out.data()), out_len);
}

//
// -------------------- KEY GENERATION --------------------
//
EVP_PKEY* generate_rsa_key(int bits)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return nullptr;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

//
// -------------------- PUBLIC KEY → PEM (BUFFER) --------------------
//
std::string public_key_to_pem(EVP_PKEY* pkey)
{
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return "";
    }

    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    std::string pem(mem->data, mem->length);

    BIO_free(bio);
    return pem;
}

//
// -------------------- MAIN --------------------
//
int main()
{
   // crow::logger::setLogLevel(crow::LogLevel::Debug);

    crow::App<LoggerMiddleware,Cors> app;

    EVP_PKEY* key = generate_rsa_key(2048);
    if (!key) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // GET /login-params
    CROW_ROUTE(app, "/login-params")
    ([&](){
        crow::json::wvalue json;
        json["algorithm"] = "RSA-OAEP";
        json["public_key"] = public_key_to_pem(key);
        return json;
    });

    // POST /login
    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::Post)
    ([&](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body)
            return crow::response(400, "Invalid JSON");

        std::string encrypted_b64 = body["password"].s();

        auto encrypted = base64_decode(encrypted_b64);
        std::string password = rsa_oaep_decrypt(key, encrypted);

        if (password.empty())
            return crow::response(401, "Decryption failed");


        crow::json::wvalue res;
        res["password"] = password;
        return crow::response{res};
    });

    app.port(18080).multithreaded().run();

    EVP_PKEY_free(key);
}
