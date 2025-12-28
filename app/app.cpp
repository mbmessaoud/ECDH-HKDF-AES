#include "crow_all.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>

#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

//
// ===================== RAII WRAPPERS =====================
//
struct BIODeleter {
    void operator()(BIO* bio) const { BIO_free_all(bio); }
};

struct EVPKeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};

struct EVPKeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

using BIOPtr = std::unique_ptr<BIO, BIODeleter>;
using EVPKeyPtr = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;
using EVPKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EVPKeyCtxDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

//
// ===================== CORS MIDDLEWARE =====================
//
struct Cors {
    struct context {};
    
    void before_handle(crow::request& req, crow::response& res, context&) {
        if (req.method == crow::HTTPMethod::Options) {
            res.code = 204;
            res.end();
        }
    }
    
    void after_handle(crow::request&, crow::response& res, context&) {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
    }
};

//
// ===================== BASE64 UTILITIES =====================
//
namespace Base64 {
    std::vector<unsigned char> decode(const std::string& in) {
        BIOPtr bio(BIO_new_mem_buf(in.data(), in.size()));
        BIOPtr b64(BIO_new(BIO_f_base64()));
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64.get(), bio.release());

        std::vector<unsigned char> out(in.size());
        int len = BIO_read(b64.get(), out.data(), out.size());
        out.resize(std::max(0, len));
        
        return out;
    }

    std::string encode(const std::vector<unsigned char>& in) {
        BIOPtr bio(BIO_new(BIO_s_mem()));
        BIOPtr b64(BIO_new(BIO_f_base64()));
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64.get(), bio.release());

        BIO_write(b64.get(), in.data(), in.size());
        BIO_flush(b64.get());

        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(b64.get(), &mem);
        
        return std::string(mem->data, mem->length);
    }
}

//
// ===================== ECDH UTILITIES =====================
//
namespace ECDH {
    EVPKeyPtr generateServerKey() {
        EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ctx) throw std::runtime_error("Failed to create PKEY context");

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init keygen");
        
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0)
            throw std::runtime_error("Failed to set curve");

        EVP_PKEY* key = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &key) <= 0)
            throw std::runtime_error("Failed to generate key");

        return EVPKeyPtr(key);
    }

    EVPKeyPtr importRawClientPublicKey(const std::vector<unsigned char>& raw) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0),
            OSSL_PARAM_construct_octet_string("pub", (unsigned char*)raw.data(), raw.size()),
            OSSL_PARAM_construct_end()
        };

        EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!ctx) throw std::runtime_error("Failed to create EC context");

        if (EVP_PKEY_fromdata_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init fromdata");

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
            throw std::runtime_error("Failed to import public key");

        return EVPKeyPtr(pkey);
    }

    std::vector<unsigned char> deriveSecret(EVP_PKEY* server, EVP_PKEY* client) {
        EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new(server, nullptr));
        if (!ctx) throw std::runtime_error("Failed to create derive context");

        if (EVP_PKEY_derive_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init derive");
        
        if (EVP_PKEY_derive_set_peer(ctx.get(), client) <= 0)
            throw std::runtime_error("Failed to set peer");

        size_t len;
        if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0)
            throw std::runtime_error("Failed to get secret length");

        std::vector<unsigned char> secret(len);
        if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) <= 0)
            throw std::runtime_error("Failed to derive secret");

        return secret;
    }

    std::string publicKeyToPEM(EVP_PKEY* pkey) {
        BIOPtr bio(BIO_new(BIO_s_mem()));
        if (!bio) throw std::runtime_error("Failed to create BIO");

        if (!PEM_write_bio_PUBKEY(bio.get(), pkey))
            throw std::runtime_error("Failed to write PEM");

        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio.get(), &mem);

        return std::string(mem->data, mem->length);
    }
}

//
// ===================== HKDF =====================
//
std::vector<unsigned char> deriveKey(
    const std::vector<unsigned char>& secret,
    const std::string& username
) {
    std::vector<unsigned char> key(32);

    EVPKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) throw std::runtime_error("Failed to create HKDF context");

    if (EVP_PKEY_derive_init(ctx.get()) <= 0)
        throw std::runtime_error("Failed to init HKDF");

    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("Failed to set HKDF hash");

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(), secret.size()) <= 0)
        throw std::runtime_error("Failed to set HKDF key");

    const std::string info = "login:" + username;
    if (EVP_PKEY_CTX_add1_hkdf_info(
        ctx.get(),
        reinterpret_cast<const unsigned char*>(info.data()),
        info.size()
    ) <= 0)
        throw std::runtime_error("Failed to add HKDF info");

    size_t len = key.size();
    if (EVP_PKEY_derive(ctx.get(), key.data(), &len) <= 0)
        throw std::runtime_error("Failed to derive key");

    return key;
}

//
// ===================== AES-GCM =====================
//
namespace AES {
    struct EncryptedData {
        std::vector<unsigned char> iv;
        std::vector<unsigned char> cipher;
        std::vector<unsigned char> tag;
    };

    std::string decrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& cipher,
        const std::vector<unsigned char>& tag
    ) {
        CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
            throw std::runtime_error("Failed to init decrypt");

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) <= 0)
            throw std::runtime_error("Failed to set IV length");

        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) <= 0)
            throw std::runtime_error("Failed to set key and IV");

        std::vector<unsigned char> out(cipher.size());
        int len;
        if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, cipher.data(), cipher.size()) <= 0)
            throw std::runtime_error("Failed to decrypt");

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data()) <= 0)
            throw std::runtime_error("Failed to set tag");

        if (EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &len) <= 0)
            return ""; // Authentication failed

        return std::string(out.begin(), out.end());
    }

    EncryptedData encrypt(
        const std::vector<unsigned char>& key,
        const std::string& plaintext
    ) {
        EncryptedData result;
        result.iv.resize(12);
        
        if (!RAND_bytes(result.iv.data(), result.iv.size()))
            throw std::runtime_error("Failed to generate IV");

        CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0)
            throw std::runtime_error("Failed to init encrypt");

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, result.iv.size(), nullptr) <= 0)
            throw std::runtime_error("Failed to set IV length");

        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.iv.data()) <= 0)
            throw std::runtime_error("Failed to set key and IV");

        result.cipher.resize(plaintext.size());
        int len;
        if (EVP_EncryptUpdate(
            ctx.get(),
            result.cipher.data(),
            &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size()
        ) <= 0)
            throw std::runtime_error("Failed to encrypt");

        if (EVP_EncryptFinal_ex(ctx.get(), result.cipher.data() + len, &len) <= 0)
            throw std::runtime_error("Failed to finalize encrypt");

        result.tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, result.tag.size(), result.tag.data()) <= 0)
            throw std::runtime_error("Failed to get tag");

        return result;
    }
}

//
// ===================== MAIN =====================
//
int main() {
    try {
        crow::App<Cors> app;
        
        // Generate server key once at startup
        auto server_key = ECDH::generateServerKey();

        // Login parameters endpoint
        CROW_ROUTE(app, "/login-params")
        ([&server_key]() {
            crow::json::wvalue json;
            json["curve"] = "P-256";
            json["server_pub"] = ECDH::publicKeyToPEM(server_key.get());
            return crow::response(json);
        });

        // Login endpoint
        CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::Post)
        ([&server_key](const crow::request& req) {
            try {
                auto body = crow::json::load(req.body);
                if (!body) return crow::response(400, "Invalid JSON");

                // Extract and decode request data
                const std::string username = body["username"].s();
                auto client_raw = Base64::decode(body["client_pub"].s());
                auto iv = Base64::decode(body["iv"].s());
                auto cipher = Base64::decode(body["cipher"].s());
                auto tag = Base64::decode(body["tag"].s());

                // Import client public key and derive shared secret
                auto client_pub = ECDH::importRawClientPublicKey(client_raw);
                auto secret = ECDH::deriveSecret(server_key.get(), client_pub.get());

                // Derive AES key from shared secret
                auto aeskey = deriveKey(secret, username);

                // Decrypt password
                std::string password = AES::decrypt(aeskey, iv, cipher, tag);
                if (password.empty())
                    return crow::response(401, "Authentication failed");

                // Encrypt response data with shared key
                auto encrypted_password = AES::encrypt(aeskey, password);
                auto encrypted_hello = AES::encrypt(aeskey, "hello");

                // Build JSON response
                crow::json::wvalue res;
                res["encrypted_password"]["iv"] = Base64::encode(encrypted_password.iv);
                res["encrypted_password"]["cipher"] = Base64::encode(encrypted_password.cipher);
                res["encrypted_password"]["tag"] = Base64::encode(encrypted_password.tag);
                
                res["encrypted_hello"]["iv"] = Base64::encode(encrypted_hello.iv);
                res["encrypted_hello"]["cipher"] = Base64::encode(encrypted_hello.cipher);
                res["encrypted_hello"]["tag"] = Base64::encode(encrypted_hello.tag);

                return crow::response(res);

            } catch (const std::exception& e) {
                CROW_LOG_ERROR << "Login error: " << e.what();
                return crow::response(500, "Internal server error");
            }
        });

        app.port(18080).run();

    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Fatal error: " << e.what();
        return 1;
    }

    return 0;
}