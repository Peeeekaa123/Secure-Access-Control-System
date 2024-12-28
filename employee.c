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

typedef struct Node {
    char data;
    struct Node* next;
} Node;

// Function to create a new node
Node* createNode(char data) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

// Function to insert a character at the end of the list
Node* stringToList(const char* str) {
    Node* head = NULL;
    Node* temp = NULL;

    for (int i = 0; str[i] != '\0'; i++) {
        Node* newNode = createNode(str[i]);
        if (head == NULL) {
            head = newNode;
        } else {
            temp->next = newNode;
        }
        temp = newNode;
    }
    return head;
}
// Function to free the linked list's memory
void freeList(Node* head) {
    Node* temp = head;
    while (temp != NULL) {
        Node* nextNode = temp->next;
        free(temp);  // Free the current node
        temp = nextNode;
    }
}
// Function to copy the linked list back into the string
void listToString(Node* head, char* str) {
    Node* temp = head;
    int i = 0;
    while (temp != NULL) {
        str[i++] = temp->data;
        temp = temp->next;
    }
    str[i] = '\0';  // Null-terminate the string
}

// Function to perform Atbash cipher encryption
void atbash_cipher(char* str) {
    // Convert string to linked list
    Node* list = stringToList(str);

    Node* temp = list;
    while (temp != NULL) {
        if (temp->data >= 'A' && temp->data <= 'Z') {
            // Atbash for uppercase letters
            temp->data = 'Z' - (temp->data - 'A');
        } else if (temp->data >= 'a' && temp->data <= 'z') {
            // Atbash for lowercase letters
            temp->data = 'z' - (temp->data - 'a');
        }
        temp = temp->next;
    }

    // Convert modified linked list back to string
    listToString(list, str);
    freeList(list);

}

// Function for ROT13 cipher encryption
void rot13_cipher(char* str) {
    // Convert string to linked list
    Node* list = stringToList(str);

    Node* temp = list;
    while (temp != NULL) {
        if (temp->data >= 'A' && temp->data <= 'Z') {
            // ROT13 for uppercase letters
            if (temp->data + 13 > 'Z') {
                temp->data -= 13;
            } else {
                temp->data += 13;
            }
        } else if (temp->data >= 'a' && temp->data <= 'z') {
            // ROT13 for lowercase letters
            if (temp->data + 13 > 'z') {
                temp->data -= 13;
            } else {
                temp->data += 13;
            }
        }
        temp = temp->next;
    }

    // Convert modified linked list back to string
    listToString(list, str);
    freeList(list);

}
// Function to get the encryption method from the server
void get_encryption_method(SSL *ssl, char *encryption_method) {
    char buffer[1024];
    // Send request to the server for the encryption method
    SSL_write(ssl, "GET_ENCRYPTION_METHOD", 21);
    memset(buffer, 0, sizeof(buffer));
    // Read the encryption method from the server response
    SSL_read(ssl, buffer, sizeof(buffer));
    strncpy(encryption_method, buffer, 10); // Copy method to the global variable
}

// Function to send access request to the server with password
void send_access_request(char *password) {
    SSL *ssl;
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    // Check the encryption method and apply corresponding cipher
    if (strcmp(encryption_method, "ROT13") == 0) {
        rot13_cipher(password);  // Apply ROT13 if matched
    } else if (strcmp(encryption_method, "Atbash") == 0) {
        atbash_cipher(password);  // Apply Atbash cipher if matched
    } else {
        printf("No matched encryption method!\n");
    }

    // Create socket for communication with the server
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

    password[strcspn(password, "\n")] = 0; // Remove newline character from input
    sprintf(buffer, "ACCESS:%s", password); // Format the access request
    // Send the access request to the server using SSL_write
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
    printf("Server response: %s\n", buffer); // Display server's response
}

// Function to initialize OpenSSL library
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL resources
void cleanup_openssl() {
    EVP_cleanup();
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[1024];
    char password[100] = "";

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

    // Create socket for communication with the server
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convert server address to binary format
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

    // Prompt employee for password input
    printf("Enter your password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0'; // Remove newline character

    // Send the access request to the server
    send_access_request(password);

    // Close SSL connection and clean up
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
