#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080  // Port number for the server
#define DATABASE_FILE "employees_database.txt"  // Path to the employee database file
#define ENCRYPTION_METHOD_FILE "encryption_method.txt"  // Path to the file storing the encryption method

char encryption_method[10] = "";  // Holds the current encryption method (e.g., "ROT13", "Atbash")

// Function for the Atbash cipher (reverse of alphabet)
void atbash_cipher(char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        // Handle lowercase letters
        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = 'z' - (text[i] - 'a');
        }
        // Handle uppercase letters
        else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = 'Z' - (text[i] - 'A');
        }
    }
}

// Function for the ROT13 cipher (shifts letters by 13 places)
void rot13_cipher(char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        // Handle lowercase letters
        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = ((text[i] - 'a' + 13) % 26) + 'a';
        }
        // Handle uppercase letters
        else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = ((text[i] - 'A' + 13) % 26) + 'A';
        }
    }
}

// Function to load the encryption method from the file
void load_encryption_method() {
    FILE *file = fopen(ENCRYPTION_METHOD_FILE, "r");
    if (file) {
        fgets(encryption_method, sizeof(encryption_method), file);  // Read method
        encryption_method[strcspn(encryption_method, "\n")] = '\0'; // Remove newline character
        fclose(file);
    }
}

// Function to hash a password using SHA-256
void hash_password(const char *password, char *hashed_password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];  // SHA-256 output size
    SHA256((unsigned char *)password, strlen(password), hash);  // Compute the hash

    // Convert the hash to a hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashed_password + (i * 2), "%02x", hash[i]);
    }
    hashed_password[SHA256_DIGEST_LENGTH * 2] = '\0';  // Null-terminate the string
}

// Function to save employee data (name, email, hashed password) to the database
void save_to_database(const char *name, const char *email, const char *hashed_password) {
    FILE *file = fopen(DATABASE_FILE, "a");  // Open the file in append mode
    if (file == NULL) {
        perror("Could not open database file");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s,%s,%s\n", name, email, hashed_password);  // Write employee data to the file
    fclose(file);
}

// Function to save the encryption method to a file
void save_encryption_method(const char *method) {
    FILE *file = fopen(ENCRYPTION_METHOD_FILE, "w");  // Open the file in write mode
    if (file) {
        fprintf(file, "%s", method);  // Write the method to the file
        fclose(file);
    } else {
        perror("Could not open encryption method file");
    }
}

// Function to verify employee credentials by comparing the hashed password with the database
int verify_employee_credentials(const char *password_hash) {
    FILE *file = fopen(DATABASE_FILE, "r");  // Open the database file in read mode
    if (!file) {
        printf("Error opening employee data file!\n");
        return 0;
    }

    char line[265];  // Buffer to read each line from the file
    while (fgets(line, sizeof(line), file)) {
        char stored_name[100], stored_email[100], stored_hash[65];  // Variables for each employee's data

        // Parse the stored data from the file (name, email, and hashed password)
        sscanf(line, "%99[^,],%99[^,],%64[^,]", stored_name, stored_email, stored_hash);

        // Compare the password hash with the stored hash
        if (strcmp(stored_hash, password_hash) == 0) {
            fclose(file);
            return 1;  // Credentials verified
        }
    }

    fclose(file);
    return 0;  // Credentials not found
}

// Function to initialize OpenSSL (required for SSL operations)
void initialize_openssl() {
    SSL_load_error_strings();   // Load error strings for OpenSSL
    OpenSSL_add_ssl_algorithms();  // Add SSL/TLS algorithms
}

// Function to clean up OpenSSL (called at the end of the program)
void cleanup_openssl() {
    EVP_cleanup();  // Clean up OpenSSL algorithms
}

// Function to create and configure the SSL context
SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();  // Use TLS server method
    SSL_CTX *ctx = SSL_CTX_new(method);  // Create new SSL context
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);  // Print any OpenSSL errors
        exit(EXIT_FAILURE);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to load certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to load private key");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the certificate");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to check the password in the database (for demonstration)
int check_password_in_database(const char *hashed_password) {
    // For simplicity, compare the hashed password with a stored value
    const char *stored_hash = "expected_hash";  // Replace with actual database hash comparison
    return strcmp(hashed_password, stored_hash) == 0;  // Return if the password matches
}

// Main function to handle the server logic
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    char buffer[1024] = {0};  // Buffer to hold data received from the client
    load_encryption_method();  // Load the encryption method from file
    printf("Encryption method: %s\n", encryption_method);

    // Initialize OpenSSL
    initialize_openssl();

    // Create and configure the SSL context
    SSL_CTX *ctx = create_context();

    // Create a socket for communication
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the specified port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    while (1) {
        // Accept new connections from clients
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        // Create SSL object and associate it with the socket
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            perror("SSL accept failed");
            ERR_print_errors_fp(stderr);
            close(new_socket);
            continue;
        }

        // Read the data sent by the client
        memset(buffer, 0, sizeof(buffer));  // Clear the buffer
        if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) {
            perror("SSL read failed");
            close(new_socket);
            continue;
        }

        // Handle different commands sent by the client
        if (strncmp(buffer, "SET_ENCRYPTION:", 15) == 0) {
            char new_method[10];
            sscanf(buffer + 15, "%s", new_method);  // Read new encryption method
            strncpy(encryption_method, new_method, sizeof(encryption_method));  // Update the encryption method
            save_encryption_method(encryption_method);  // Save method to file
            printf("Encryption method updated to: %s\n", encryption_method);
            SSL_write(ssl, "Encryption method updated successfully!", 40);
        } 
        else if (strncmp(buffer, "GET_ENCRYPTION_METHOD", 21) == 0) {
            // Send the current encryption method to the client
            SSL_write(ssl, encryption_method, strlen(encryption_method));
        } 
        else if (strncmp(buffer, "LOGIN:", 6) == 0) {
            char encrypted_password[100];
            char decrypted_password[100];
            sscanf(buffer + 6, "%s", encrypted_password);  // Get the encrypted password from the client

            // Decrypt the password using the chosen method
            if (strcmp(encryption_method, "ROT13") == 0) {
                rot13_cipher(encrypted_password);
                strcpy(decrypted_password, encrypted_password);
            }
            else if (strcmp(encryption_method, "Atbash") == 0) {
                atbash_cipher(encrypted_password);
                strcpy(decrypted_password, encrypted_password);
            } else {
                printf("No decryption method matched!\n");
                strcpy(decrypted_password, encrypted_password);
            }

            // Hash the decrypted password and verify the credentials
            char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];
            hash_password(decrypted_password, hashed_password);

            if (verify_employee_credentials(hashed_password) == 1) {
                SSL_write(ssl, "Access permitted!", 17);  // Send success response
            } else {
                SSL_write(ssl, "Access denied!", 14);  // Send failure response
            }
        } 
        else {
            // Parse employee data (name, email, password) and save to the database
            char name[100], email[100], password[100];
            sscanf(buffer, "%[^,],%[^,],%s", name, email, password);

            // Hash the password before saving it
            char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];
            hash_password(password, hashed_password);

            // Save the employee to the database
            save_to_database(name, email, hashed_password);

            printf("employee '%s' added successfully.\n", name);

            // Send success response to the admin
            char *response = "employee added successfully!";
            SSL_write(ssl, response, strlen(response));
        }

        // Close the SSL connection and the socket
        SSL_shutdown(ssl);
        close(new_socket);
        SSL_free(ssl);
    }

    // Cleanup OpenSSL and SSL context
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
