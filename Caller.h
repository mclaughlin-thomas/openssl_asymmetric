#pragma once
#include <string>
#include <openssl/rsa.h>

class Caller {

private:
    RSA* privateKey;  // RSA private key
    RSA* publicKey;   // RSA public key
    std::string message; // Message storage for the caller

public:
    Caller();
    ~Caller();
    RSA* GetPrivateKey(void);
    RSA* GetPublicKey(void);
    std::string GetMessage(void);
    void SetMessage(const std::string& nMessage);
    // Generate RSA Key Pair
    void GenerateRSAKeyPair(int keyLength);
    // Send a message to another Caller (Encrypt using receiver's public key)
    std::string SendMessage(Caller& receiver, const std::string& message);
    // Receive a message (Decrypt using own private key)
    std::string ReceiveMessage(const std::string& encryptedMessage);
};
