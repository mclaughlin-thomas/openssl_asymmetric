#include "Caller.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

// Constructor initializing the RSA keys to nullptr
Caller::Caller() {
    this->privateKey = nullptr;
    this->publicKey = nullptr;
    this->message = "";
}

// Destructor to free RSA key structures
Caller::~Caller() {
    if (privateKey) RSA_free(privateKey);
    if (publicKey) RSA_free(publicKey);
}

// Generate RSA key pair
void Caller::GenerateRSAKeyPair(int keyLength) {
    RSA* rsa = RSA_generate_key(keyLength, RSA_F4, nullptr, nullptr);
    this->privateKey = RSAPrivateKey_dup(rsa);  // Store private key
    this->publicKey = RSAPublicKey_dup(rsa);    // Store public key
    RSA_free(rsa); // Free temporary RSA struct
}

// Getters
RSA* Caller::GetPrivateKey() {
    return this->privateKey;
}

RSA* Caller::GetPublicKey() {
    return this->publicKey;
}

std::string Caller::GetMessage() {
    return this->message;
}

// Setters
void Caller::SetMessage(const std::string& nMessage) {
    this->message = nMessage;
}

// Encrypt message using receiver's public key and return encrypted string
std::string Caller::SendMessage(Caller& receiver, const std::string& message) {
    int rsaLen = RSA_size(receiver.GetPublicKey());
    unsigned char* encrypted = new unsigned char[rsaLen];

    int encryptedLen = RSA_public_encrypt(message.size(),
                                          (unsigned char*)message.c_str(),
                                          encrypted, receiver.GetPublicKey(), RSA_PKCS1_OAEP_PADDING);

    if (encryptedLen == -1) {
        std::cerr << "Error encrypting: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        delete[] encrypted;
        return "";
    }

    std::string ciphertext((char*)encrypted, encryptedLen);
    delete[] encrypted;
    return ciphertext;
}

// Decrypt the message using own private key
std::string Caller::ReceiveMessage(const std::string& encryptedMessage) {
    int rsaLen = RSA_size(this->privateKey);
    unsigned char* decrypted = new unsigned char[rsaLen];

    int decryptedLen = RSA_private_decrypt(encryptedMessage.size(),
                                           (unsigned char*)encryptedMessage.c_str(),
                                           decrypted, this->privateKey, RSA_PKCS1_OAEP_PADDING);

    if (decryptedLen == -1) {
        std::cerr << "Error decrypting: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        delete[] decrypted;
        return "";
    }

    std::string recoveredText((char*)decrypted, decryptedLen);
    delete[] decrypted;
    return recoveredText;
}
