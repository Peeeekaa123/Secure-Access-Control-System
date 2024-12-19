#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Define the server address and port
#define SERVER_ADDRESS "127.0.0.1"
#define PORT 8080

char encryption_method[10] = "";
// Function to perform XOR encryption
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
// Function to read encryption method from the server
void get_encryption_method(SSL *ssl, char *encryption_method) {
    char buffer[1024];
    // Send request to the server for the encryption method
    SSL_write(ssl, "GET_ENCRYPTION_METHOD", 21);
    memset(buffer, 0, sizeof(buffer));
    SSL_read(ssl, buffer, sizeof(buffer));
    strncpy(encryption_method, buffer, 10);
}
void send_login_request(char *password) {
    SSL *ssl;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    printf("password %s\n",password);
    printf("enc method : %s\n",encryption_method);
   if (strcmp(encryption_method, "ROT13") == 0) {
    printf("ROT13\n");
    rot13_cipher(password);
} else if (strcmp(encryption_method, "Atbash") == 0) {
    printf("Atbash\n");
    atbash_cipher(password);
} else {
    printf("No matched encryption method!\n");
}

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
    password[strcspn(password, "\n")] = 0;
    sprintf(buffer, "LOGIN:%s", password);
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

}

// Function to initialize OpenSSL and create SSL context
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[1024];
    char password[100]="";

    // Initialize OpenSSL
    initialize_openssl();

    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_ADDRESS, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Start SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL connect failed");
        ERR_print_errors_fp(stderr);
        close(sock);
        return -1;
    }

    // Get the encryption method from the server
    get_encryption_method(ssl, encryption_method);
    printf("Encryption method from server: %s\n", encryption_method);
    printf("Enter your password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';
    send_login_request(password);

    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
