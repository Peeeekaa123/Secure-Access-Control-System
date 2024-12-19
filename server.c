#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define DATABASE_FILE "users_database.txt"
#define ENCRYPTION_METHOD_FILE "encryption_method.txt"

char encryption_method[10] = ""; 

void atbash_cipher(char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = 'z' - (text[i] - 'a');
        } else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = 'Z' - (text[i] - 'A');
        }
    }
}

// Function for ROT13 cipher
void rot13_cipher(char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if ('a' <= text[i] && text[i] <= 'z') {
            text[i] = ((text[i] - 'a' + 13) % 26) + 'a';
        } else if ('A' <= text[i] && text[i] <= 'Z') {
            text[i] = ((text[i] - 'A' + 13) % 26) + 'A';
        }
    }
}
// Function to load the encryption method from the file
void load_encryption_method() {
    FILE *file = fopen(ENCRYPTION_METHOD_FILE, "r");
    if (file) {
        fgets(encryption_method, sizeof(encryption_method), file);
        encryption_method[strcspn(encryption_method, "\n")] = '\0'; // Remove newline
        fclose(file);
    }
}

// Function to hash a password using SHA-256
void hash_password(const char *password, char *hashed_password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashed_password + (i * 2), "%02x", hash[i]);
    }
    hashed_password[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Function to save the user to the database
void save_to_database(const char *name, const char *email, const char *hashed_password) {
    FILE *file = fopen(DATABASE_FILE, "a");
    if (file == NULL) {
        perror("Could not open database file");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s,%s,%s\n", name, email, hashed_password);
    fclose(file);
}

// Function to save the encryption method to a file
void save_encryption_method(const char *method) {
    FILE *file = fopen(ENCRYPTION_METHOD_FILE, "w");
    if (file) {
        fprintf(file, "%s", method);
        fclose(file);
    } else {
        perror("Could not open encryption method file");
    }
}
int verify_employee_credentials(const char *password_hash)
{
    FILE *file = fopen("users_database.txt", "r");
    if (!file)
    {
        printf("Error opening employee data file!\n");
        return 0;
    }

    char line[265];
    while (fgets(line, sizeof(line), file))
    {
        char stored_name[100], stored_email[100], stored_hash[65];

        sscanf(line, "%99[^,],%99[^,],%64[^,]",
               stored_name, stored_email, stored_hash);

            if (strcmp(stored_hash, password_hash) == 0)
            {
                fclose(file);
                return 1;
            }
            else
            {
                fclose(file);
                return 0;
            }
        
    }

    fclose(file);
    return 0;
}
// Function to initialize OpenSSL
void initialize_openssl() {
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Function to create and configure the SSL context
SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method(); // Using TLS server method
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
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

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the certificate");
        exit(EXIT_FAILURE);
    }

    return ctx;
}
int check_password_in_database(const char *hashed_password) {
    // You need to implement database access here.
    // For simplicity, let's assume you're just comparing it with a stored value.
    const char *stored_hash = "expected_hash";  // Replace with actual database hash comparison.
    return strcmp(hashed_password, stored_hash) == 0;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    char buffer[1024] = {0};
    load_encryption_method();
    printf("Encryption method: %s\n", encryption_method);

    // Initialize OpenSSL
    initialize_openssl();

    // Create and configure the SSL context
    SSL_CTX *ctx = create_context();

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    while (1) {
        // Accept new connections
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        // Create SSL object and associate with the socket
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        // Perform the SSL handshake
        if (SSL_accept(ssl) <= 0) {
            perror("SSL accept failed");
            ERR_print_errors_fp(stderr);
            close(new_socket);
            continue;
        }

        // Read the data sent by the client (admin in this case)
        memset(buffer, 0, sizeof(buffer)); // Clear the buffer before reuse
        if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) {
            perror("SSL read failed");
            close(new_socket);
            continue;
        }
        printf("Received data: %s\n", buffer);

        if (strncmp(buffer, "SET_ENCRYPTION:", 15) == 0) {
            char new_method[10];
            sscanf(buffer + 15, "%s", new_method);
            strncpy(encryption_method, new_method, sizeof(encryption_method));
            save_encryption_method(encryption_method);
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
            sscanf(buffer + 6,"%s",encrypted_password);
            printf("Recieved password : %s\n",encrypted_password);
            printf("Enc method %s\n",encryption_method);
            if(strcmp(encryption_method,"ROT13") == 0){
            rot13_cipher(encrypted_password);
            strcpy(decrypted_password,encrypted_password);
            }
            else if(strcmp(encryption_method,"Atbash") == 0){
            atbash_cipher(encrypted_password);
            strcpy(decrypted_password,encrypted_password);
            }
            else{
                printf("No decryption method matched!\n");
                strcpy(decrypted_password,encrypted_password);
            }
            printf("dec password :%s\n",decrypted_password);
            char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];
            hash_password(decrypted_password, hashed_password);
            printf("Hash password : %s\n",hashed_password);
            if(verify_employee_credentials(hashed_password) == 1){
               
            SSL_write(ssl, "Login successful!", 17);
            }
            else{
            SSL_write(ssl, "Login failed!", 13);
            }
        }
        else {
            // Parse the data
            char name[100], email[100], password[100];
            sscanf(buffer, "%[^,],%[^,],%s", name, email, password);

            // Hash the password
            char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];
            hash_password(password, hashed_password);

            // Save to the database
            save_to_database(name, email, hashed_password);

            printf("User '%s' added successfully.\n", name);

            // Send a response to the admin
            char *response = "User added successfully!";
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
