#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080

// generate a password for the created employee
void generatePassword(char password[100]) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int length = sizeof(charset) - 1;

    // Seed the random number generator
    srand(time(NULL));

    // Generate a 12-character password
    for (int i = 0; i < 12; i++) {
        password[i] = charset[rand() % length];
    }

    // Null-terminate the password string
    password[12] = '\0';
    
    /*
    // Future improvement: Implement a process to send the generated password to the employee,
    // either via email or SMS, depending on the preferred method of communication.
    */

    printf("generated password : %s \n", password);
}
// Function to add an employee
void add_employee() {
    SSL *ssl;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0}; // Buffer to store data to be sent/received
    char name[100], email[100], password[100];

    // Create the socket for the connection
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error"); // Error creating socket
        return;
    }

    serv_addr.sin_family = AF_INET;  // Set address family to AF_INET (IPv4)
    serv_addr.sin_port = htons(PORT); // Set port number

    // Convert address to binary and connect to the server
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        return;
    }

    // Establish the connection with the server
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
    SSL_load_error_strings(); // Load OpenSSL error strings
    OpenSSL_add_ssl_algorithms(); // Add SSL algorithms

    ssl = SSL_new(ctx); // Create a new SSL object
    SSL_set_fd(ssl, sock); // Associate the SSL object with the socket

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL connect failed");
        ERR_print_errors_fp(stderr); // Print SSL errors if handshake fails
        close(sock);
        return;
    }

    // Get employee details from the admin
    printf("Enter employee's name: ");
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = 0; // Remove newline character from input

    printf("Enter employee's email: ");
    fgets(email, sizeof(email), stdin);
    email[strcspn(email, "\n")] = 0; // Remove newline character from input

    generatePassword(password);

    // Format the details into a single string to send to the server
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
    memset(buffer, 0, sizeof(buffer)); // Clear the buffer before reading response
    if (SSL_read(ssl, buffer, sizeof(buffer)) < 0) {
        perror("Failed to read server response");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }
    printf("Server response: %s\n", buffer); // Print server's response

    // Clean up
    SSL_free(ssl); // Free SSL object
    SSL_CTX_free(ctx); // Free SSL context
    close(sock); // Close the socket after the transaction
}

// Function to set the encryption method
void set_encryption_method() {
    SSL *ssl;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0}; // Buffer to store data to be sent/received
    char method[10]; // Variable to store the encryption method

    // Create the socket for the connection
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error"); // Error creating socket
        return;
    }

    serv_addr.sin_family = AF_INET;  // Set address family to AF_INET (IPv4)
    serv_addr.sin_port = htons(PORT); // Set port number

    // Convert address to binary and connect to the server
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        return;
    }

    // Establish the connection with the server
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
    SSL_load_error_strings(); // Load OpenSSL error strings
    OpenSSL_add_ssl_algorithms(); // Add SSL algorithms

    ssl = SSL_new(ctx); // Create a new SSL object
    SSL_set_fd(ssl, sock); // Associate the SSL object with the socket

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL connect failed");
        ERR_print_errors_fp(stderr); // Print SSL errors if handshake fails
        close(sock);
        return;
    }

    // Get the new encryption method from the admin
    printf("Enter encryption method (ROT13/Atbash ): ");
    fgets(method, sizeof(method), stdin);
    method[strcspn(method, "\n")] = 0; // Remove newline character from input

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
    memset(buffer, 0, sizeof(buffer)); // Clear the buffer before reading response
    if (SSL_read(ssl, buffer, sizeof(buffer)) < 0) {
        perror("Failed to read server response");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return;
    }
    printf("Server response: %s\n", buffer); // Print server's response

    // Clean up
    SSL_free(ssl); // Free SSL object
    SSL_CTX_free(ctx); // Free SSL context
    close(sock); // Close the socket after the transaction
}

int main() {
    int choice;

    // Menu loop
    while (1) {
        printf("\nAdmin Menu:\n");
        printf("1. Add an employee\n");
        printf("2. Set encryption method\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar(); // Consume the newline character left by scanf

        // Handle the employee's choice
        switch (choice) {
            case 1:
                add_employee(); // Call the add_employee function
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
