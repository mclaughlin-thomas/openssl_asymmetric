#include <iostream>
#include "Caller.h"

int main() {
    const int keyLength = 2048;

    // Create two Caller objects
    Caller caller1;
    Caller caller2;

    // Generate RSA key pairs for both objects
    caller1.GenerateRSAKeyPair(keyLength);
    caller2.GenerateRSAKeyPair(keyLength);

    // Message to be sent from caller1 to caller2
    std::string message = "Hello, this is caller1 sending a secret message!";

    // caller1 sends an encrypted message to caller2
    std::string encryptedMessage = caller1.SendMessage(caller2, message);

    if (!encryptedMessage.empty()) {
        std::cout << "Encrypted message sent by caller1 to caller2: " << encryptedMessage << std::endl;
    }

    // caller2 receives and decrypts the message
    std::string decryptedMessage = caller2.ReceiveMessage(encryptedMessage);

    if (!decryptedMessage.empty()) {
        std::cout << "Caller2 decrypted message: " << decryptedMessage << std::endl;
    }

    return 0;
}
