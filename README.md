### Summary  
This file explains the roles of the admin, employee, and server in this secure access control system. It highlights how passwords are handled securely, the use of ROT13 and Atbash for simple encryption, and the importance of SSL/TLS for network-level security. Additionally, it clarifies the difference between these encryption methods and their purposes.

---

### Simplified Explanation  

**Admin (admin.c):**  
- Adds users to the system by entering their name, email, and password.  
- Passwords are scrambled (hashed) and stored securely.  
- Chooses the encryption method (ROT13 or Atbash) for communication between employees and the server.  

**Employee (employee.c):**  
- Logs in by using the selected encryption method to scramble their password before sending it to the server.  
- The server checks the scrambled password against its database to confirm their identity.  

**Server (server.c):**  
- Manages adding users, choosing the encryption method, and handling login attempts.  
- Keeps a database with scrambled passwords for security.  
- Supports ROT13 and Atbash encryption for added password safety.  
- Uses SSL/TLS for secure communication to ensure all data sent between employees/admin and the server stays private.  

---

### How SSL/TLS Works  
SSL/TLS is a tool that keeps data safe while it moves between the client (employee or admin) and the server. Here's how it works:  
1. **Handshake Process:**  
   - The server shares its SSL/TLS certificate (with its public key) with the client.  
   - The client checks if the certificate is real by comparing it with trusted sources (Certificate Authorities or CAs).  
   - If valid, the client and server agree on a special "session key" for encryption.  

2. **Encrypted Communication:**  
   - From then on, all messages between the client and server are scrambled using the session key, keeping them safe from prying eyes.  

**PEM Passphrase:**  
- The server's private key, needed for SSL/TLS, is locked with a PEM passphrase for extra security.  
- The admin must enter the passphrase to unlock the key and let SSL/TLS work.  
- Without it, the server cannot secure connections.  

---

### ROT13/Atbash vs. SSL/TLS  

1. **ROT13/Atbash Encryption (Simple Security):**  
   - These are basic tools that change passwords into unreadable forms before sending them to the server.  
   - They only protect the password and are not strong enough to secure data over the network.  

2. **SSL/TLS Encryption (Strong Network Security):**  
   - SSL/TLS scrambles all data sent between the client and server to keep it private and untampered.  
   - It prevents spying, hacking, and data alteration during transmission.  
   - SSL/TLS is a reliable and widely used standard for online security.  

**In Summary:**  
- ROT13 and Atbash hide passwords within the app.  
- SSL/TLS protects all communication over the internet.

# Update and install essential build tools
sudo apt update
sudo apt install build-essential -y

# Install OpenSSL development libraries
sudo apt install libssl-dev -y

# Compile the C program
# Replace 'program.c' with the name of your C file and 'output' with the desired output file name
gcc program.c -o output -lssl -lcrypto

# Run the compiled program
./output
