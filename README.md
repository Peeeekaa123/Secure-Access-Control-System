# Secure Access Control System  

This system provides secure user management and data transmission using a combination of basic encoding methods (ROT13 and Atbash) and robust SSL/TLS encryption for network security.  

---

## Summary  

This system is composed of three main components:  
1. **Admin**: Manages user accounts and selects encoding methods.  
2. **Employee**: Gains system access by verifying credentials.  
3. **Server**: Manages authentication, user data, and secure communication.  

The system employs basic encoding (ROT13/Atbash) for internal password handling and SSL/TLS for network-level encryption.  

---

## System Components  

### **Admin (`admin.c`)**  
- Adds users to the system by entering their name, email, and password.  
- Scrambles (hashes) passwords for secure storage.  
- Chooses the encoding method (ROT13 or Atbash) for employee-server communication.  

### **Employee (`employee.c`)**  
- Gains access by encoding their password with the selected method before sending it to the server.  
- The server verifies the encoded password against its database.  

### **Server (`server.c`)**  
- Manages user data, encoding method selection, and access attempts.  
- Stores scrambled passwords for secure authentication.  
- Uses SSL/TLS to secure all data exchanges, preventing eavesdropping or tampering.  

---

## Secure Communication with SSL/TLS  

### **How It Works**  
1. **Handshake Process:**  
   - The server sends its SSL/TLS certificate to the client.  
   - The client verifies the certificate’s authenticity through a trusted Certificate Authority (CA).  
   - Once verified, the client and server agree on a "session key" for encryption.  

2. **Encrypted Data Exchange:**  
   - All communication between the client and server is encrypted using the session key.  

### **PEM Passphrase**  
- The server’s private key is protected by a PEM passphrase, adding an extra layer of security.  
- The admin must input the passphrase (`mohamed`) to enable SSL/TLS encryption.

---

## ROT13/Atbash vs. SSL/TLS  

1. **ROT13/Atbash (Basic Encoding):**  
   - Simple methods that transform passwords into unreadable text.  
   - Serve as an additional layer of obfuscation but are not secure for network-level protection.  

2. **SSL/TLS (Robust Encryption):**  
   - Ensures all data transmitted between the client and server is encrypted.  
   - Protects against eavesdropping, data alteration, and unauthorized access.  
   - A standard protocol for secure online communication.  

---

## Installation and Usage  

### **Install Required Tools on Kali Linux**  
```bash
sudo apt update  
sudo apt install build-essential -y  
sudo apt install libssl-dev -y  
sudo apt install libc6-dev
```
### **Compile the C Program (Replace program.c with the name of your C file and output with the desired output file name.)** 
```bash
gcc program.c -o output -lssl -lcrypto  
```
### **Run the Program** 
```bash
./output   
```
### **Input the PEM Passphrase**
Enter the PEM passphrase mohamed when prompted to initialize SSL/TLS.
