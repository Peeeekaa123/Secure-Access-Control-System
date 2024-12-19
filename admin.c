#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080

// Function to add a user
void add_user() {
    SSL *ssl;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    char name[100], email[100], password[100];

    // Create the socket for this transaction
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert address to binary and connect to the server
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }

    // Initialize OpenSSL and SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        close(sock);
        return;
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL connect failed");
        ERR_print_errors_fp(stderr);
        close(sock);
        return;
    }

    // Get user details from the admin
    printf("Enter user's name: ");
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = 0; // Remove newline character

    printf("Enter user's email: ");
    fgets(email, sizeof(email), stdin);
    email[strcspn(email, "\n")] = 0;

    printf("Enter user's password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    // Format the details into a single string
    sprintf(buffer, "%s,%s,%s", name, email, password);

    // Send the details to the server using SSL_write
    if (SSL_write(ssl, buffer, strlen(buffer)) < 0) {
        perror("Failed to send data to server");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }

    // Receive the server's response using SSL_read
    memset(buffer, 0, sizeof(buffer)); // Clear the buffer
    if (SSL_read(ssl, buffer, sizeof(buffer)) < 0) {
        perror("Failed to read server response");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }
    printf("Server response: %s\n", buffer);

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock); // Close the socket after the request
}

// Function to set the encryption method
void set_encryption_method() {
    SSL *ssl;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    char method[10];

    // Create the socket for this transaction
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert address to binary and connect to the server
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }

    // Initialize OpenSSL and SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        close(sock);
        return;
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL connect failed");
        ERR_print_errors_fp(stderr);
        close(sock);
        return;
    }

    // Get the new encryption method from the admin
    printf("Enter encryption method (ROT13/Atbash ): ");
    fgets(method, sizeof(method), stdin);
    method[strcspn(method, "\n")] = 0; // Remove newline character

    // Format the command to set encryption
    sprintf(buffer, "SET_ENCRYPTION:%s", method);

    // Send the command to the server using SSL_write
    if (SSL_write(ssl, buffer, strlen(buffer)) < 0) {
        perror("Failed to send data to server");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }

    // Receive the server's response using SSL_read
    memset(buffer, 0, sizeof(buffer)); // Clear the buffer
    if (SSL_read(ssl, buffer, sizeof(buffer)) < 0) {
        perror("Failed to read server response");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }
    printf("Server response: %s\n", buffer);

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock); // Close the socket after the request
}

int main() {
    int choice;

    // Menu loop
    while (1) {
        printf("\nAdmin Menu:\n");
        printf("1. Add a user\n");
        printf("2. Set encryption method\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar(); // Consume the newline character left by scanf

        switch (choice) {
            case 1:
                add_user(); // Call the add_user function
                break;
            case 2:
                set_encryption_method(); // Call the set_encryption_method function
                break;
            case 3:
                printf("Exiting the program.\n");
                return 0; // Exit the program
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}
