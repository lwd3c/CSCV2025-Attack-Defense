#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#define MAX_PATH 256
#define KEY_SIZE 16 // TODO: Only update after BA meeting. Currently operating on pure hope
#define MAX_PASSWORD 64
typedef struct {
    char *username;
    char *password;
    int logged_in;
    char current_dir[MAX_PATH];
} Account;

Account current_account = {NULL, NULL, 0, ""};
char managed_path[MAX_PATH] = {0};
const char *protected_filename[] = {
    "password.txt",
    "key.txt",
    NULL
};
const char *protected_keywords[] = {
    NULL
};
void timeout_handler(int signum) {
    printf("Time's up! See you again.\n");
    exit(0);
}
char* get_managed_path() {
    strcpy(managed_path, "files");
    return managed_path;
}
void get_user_path(const char *username, char *out_path) {
    snprintf(out_path, MAX_PATH, "%s/%s", get_managed_path(), username);
}
void xor_encrypt(unsigned char *data, int len, unsigned char *key, int keylen) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

void generate_key(unsigned char *key, int len) {
    const char charset[] = "abcdef0123456789";
    srand(time(NULL));
    for (int i = 0; i < len; i++) {
        key[i] = charset[rand() % (sizeof(charset) - 1)];
    }
}
unsigned char* get_master_key() {
    static unsigned char master_key[KEY_SIZE];
    char *env_key = getenv("MASTER_KEY");
    if (env_key) {
        strncpy((char*)master_key, env_key, KEY_SIZE);
    }
    return master_key;
}
int get_current_user_key(unsigned char *user_key_out) {
    if (!current_account.logged_in || !current_account.username) {
        return 0;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char key_file[MAX_PATH];
    snprintf(key_file, MAX_PATH, "%s/key.txt", user_path);
    FILE *kf = fopen(key_file, "rb");
    if (!kf) {
        return 0;
    }
    unsigned char encrypted_key[KEY_SIZE];
    size_t read_bytes = fread(encrypted_key, 1, KEY_SIZE, kf);
    fclose(kf);
    if (read_bytes != KEY_SIZE) {
        return 0;
    }
    memcpy(user_key_out, encrypted_key, KEY_SIZE);
    xor_encrypt(user_key_out, KEY_SIZE, get_master_key(), KEY_SIZE);
    return 1;
}
int ensure_dir(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        return mkdir(path, 0755);
    }
    return 0;
}
void cmd_ls() {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char full_path[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(full_path, MAX_PATH, "%s/%s", user_path, current_account.current_dir);
    } else {
        snprintf(full_path, MAX_PATH, "%s", user_path);
    }
    DIR *dir = opendir(full_path);
    if (!dir) {
        printf("Cannot open directory\n");
        return;
    }
    struct dirent *entry;
    int in_root = (strlen(current_account.current_dir) == 0);
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            if (in_root && (strcmp(entry->d_name, "key.txt") == 0 || 
                           strcmp(entry->d_name, "password.txt") == 0)) {
                continue;
            }
            
            struct stat st;
            char item_path[MAX_PATH];
            snprintf(item_path, MAX_PATH, "%s/%s", full_path, entry->d_name);
            if (stat(item_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                printf("%s/\n", entry->d_name);
            } else {
                printf("%s\n", entry->d_name);
            }
        }
    }
    closedir(dir);
}
void cmd_pwd() {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (strlen(current_account.current_dir) > 0) {
        printf("~/%s\n", current_account.current_dir);
    } else {
        printf("~\n");
    }
}
void cmd_cd(const char *path) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!path || strlen(path) == 0 || strcmp(path, "~") == 0) {
        current_account.current_dir[0] = '\0';
        return;
    }
    if (strcmp(path, ".") == 0) {
        return;
    }
    if (strcmp(path, "..") == 0) {
        char *last_slash = strrchr(current_account.current_dir, '/');
        if (last_slash) {
            *last_slash = '\0';
        } else {
            current_account.current_dir[0] = '\0';
        }
        return;
    }
    char new_path[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(new_path, MAX_PATH, "%s/%s", current_account.current_dir, path);
    } else {
        snprintf(new_path, MAX_PATH, "%s", path);
    }
    if (strstr(new_path, "..")) {
        printf("Invalid path!\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char full_path[MAX_PATH];
    snprintf(full_path, MAX_PATH, "%s/%s", user_path, new_path);
    struct stat st;
    if (stat(full_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        printf("Directory not found\n");
        return;
    }
    strncpy(current_account.current_dir, new_path, MAX_PATH);
    current_account.current_dir[MAX_PATH - 1] = '\0';
}
int is_safe_path(const char *user_path, const char *relative_path, char *resolved_out, size_t out_size) {
    if (!user_path || !relative_path) return 0;
    char temp_path[MAX_PATH];
    char resolved_path[MAX_PATH];
    char resolved_user_path[MAX_PATH];
    if (relative_path[0] == '/') {
        return 0;
    }
    char *user_result = realpath(user_path, resolved_user_path);
    if (!user_result) {
        return 0;
    }
    snprintf(temp_path, MAX_PATH, "%s/%s", user_path, relative_path);
    char parent_path[MAX_PATH];
    char filename[MAX_PATH];
    char *last_slash = strrchr(temp_path, '/');
    if (!last_slash) {
        return 0;
    }
    size_t parent_len = last_slash - temp_path;
    if (parent_len == 0) parent_len = 1;
    strncpy(parent_path, temp_path, parent_len);
    parent_path[parent_len] = '\0';
    strncpy(filename, last_slash + 1, MAX_PATH - 1);
    filename[MAX_PATH - 1] = '\0';
    char resolved_parent[MAX_PATH];
    char *result = realpath(parent_path, resolved_parent);
    if (!result) {
        return 0;
    }
    snprintf(resolved_path, MAX_PATH, "%s/%s", resolved_parent, filename);
    size_t user_path_len = strlen(resolved_user_path);
    if (strncmp(resolved_path, resolved_user_path, user_path_len) != 0) {
        return 0;
    }
    if (resolved_path[user_path_len] != '/' && resolved_path[user_path_len] != '\0') {
        return 0;
    }
    if (resolved_out && out_size > 0) {
        strncpy(resolved_out, resolved_path, out_size - 1);
        resolved_out[out_size - 1] = '\0';
    }
    return 1;
}
void cmd_cp(const char *src, const char *dst) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!src || !dst) {
        printf("Usage: cp <source> <destination>\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char src_relative[MAX_PATH], dst_relative[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(src_relative, MAX_PATH, "%s/%s", current_account.current_dir, src);
        snprintf(dst_relative, MAX_PATH, "%s/%s", current_account.current_dir, dst);
    } else {
        strncpy(src_relative, src, MAX_PATH - 1);
        src_relative[MAX_PATH - 1] = '\0';
        strncpy(dst_relative, dst, MAX_PATH - 1);
        dst_relative[MAX_PATH - 1] = '\0';
    }
    char src_path[MAX_PATH], dst_path[MAX_PATH];
    if (!is_safe_path(user_path, src_relative, src_path, MAX_PATH)) {
        printf("Invalid source path! (Path must be within your directory)\n");
        return;
    }
    if (!is_safe_path(user_path, dst_relative, dst_path, MAX_PATH)) {
        printf("Invalid destination path! (Path must be within your directory)\n");
        return;
    }
    if (!is_valid_filename(src_path)) {
        printf("Invalid filename!\n");
        return;
    }
    if (!is_valid_filename(dst_path)) {
        printf("Invalid filename!\n");
        return;
    }
    FILE *fsrc = fopen(src_path, "rb");
    if (!fsrc) {
        printf("Cannot open source file\n");
        return;
    }
    FILE *fdst = fopen(dst_path, "wb");
    if (!fdst) {
        printf("Cannot create destination file\n");
        fclose(fsrc);
        return;
    }
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fsrc)) > 0) {
        fwrite(buffer, 1, bytes, fdst);
    }
    fclose(fsrc);
    fclose(fdst);
    printf("File copied\n");
}
void cmd_mv(const char *src, const char *dst) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!src || !dst) {
        printf("Usage: mv <source> <destination>\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char src_relative[MAX_PATH], dst_relative[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(src_relative, MAX_PATH, "%s/%s", current_account.current_dir, src);
        snprintf(dst_relative, MAX_PATH, "%s/%s", current_account.current_dir, dst);
    } else {
        strncpy(src_relative, src, MAX_PATH - 1);
        src_relative[MAX_PATH - 1] = '\0';
        strncpy(dst_relative, dst, MAX_PATH - 1);
        dst_relative[MAX_PATH - 1] = '\0';
    }
    char src_path[MAX_PATH], dst_path[MAX_PATH];
    if (!is_safe_path(user_path, src_relative, src_path, MAX_PATH)) {
        printf("Invalid source path! (Path must be within your directory)\n");
        return;
    }
    if (!is_safe_path(user_path, dst_relative, dst_path, MAX_PATH)) {
        printf("Invalid destination path! (Path must be within your directory)\n");
        return;
    }
    if (!is_valid_filename(src_path)) {
        printf("Invalid filename!\n");
        return;
    }
    if (!is_valid_filename(dst_path)) {
        printf("Invalid filename!\n");
        return;
    }
    if (rename(src_path, dst_path) == 0) {
        printf("File moved/renamed\n");
    } else {
        printf("Cannot move/rename file\n");
    }
}
int is_valid_filename(const char *filename) {
    for (int i = 0; protected_filename[i] != NULL; i++) {
        size_t fn_len = strlen(filename);
        size_t pf_len = strlen(protected_filename[i]);
        if (fn_len >= pf_len) {
            if (strcmp(filename + fn_len - pf_len, protected_filename[i]) == 0) {
                return 0; 
            }
        }
    }
    for (int i = 0; protected_keywords[i] != NULL; i++) {
        if (strstr(filename, protected_keywords[i]) != NULL) {
            return 0;
        }
    }
    return 1;
}
void cmd_cat(const char *filename) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!filename) {
        printf("Usage: cat <filename>\n");
        return;
    }
    if (strstr(filename, "..")) {
        printf("Invalid path!\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename!\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char filepath[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(filepath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, filename);
    } else {
        snprintf(filepath, MAX_PATH, "%s/%s", user_path, filename);
    }
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("Cannot open file\n");
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        printf(line);
    }
    puts("");
    fclose(f);
}
void cmd_read_file(const char *filename) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!filename) {
        printf("Usage: read <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename!\n");
        return;
    }
    char filepath[MAX_PATH];
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    if (strlen(current_account.current_dir) > 0) {
        snprintf(filepath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, filename);
    } else {
        snprintf(filepath, MAX_PATH, "%s/%s", user_path, filename);
    }
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("Cannot open file\n");
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }
    puts("");
    fclose(f);
}
void cmd_write_file(const char *filename) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!filename) {
        printf("Usage: write <filename>\n");
        return;
    }
    if (!is_valid_filename(filename)) {
        printf("Invalid filename!\n");
        return;
    }
    char filepath[MAX_PATH];
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    if (strlen(current_account.current_dir) > 0) {
        snprintf(filepath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, filename);
    } else {
        snprintf(filepath, MAX_PATH, "%s/%s", user_path, filename);
    }
    FILE *f = fopen(filepath, "wb");
    if (!f) {
        printf("Cannot create file\n");
        return;
    }
    printf("Enter content as hex string (e.g., 41424344 for ABCD): ");
    char hex_input[8193];
    if (!fgets(hex_input, sizeof(hex_input), stdin)) {
        printf("Failed to read input\n");
        fclose(f);
        return;
    }
    hex_input[strcspn(hex_input, "\n")] = 0;
    size_t hex_len = strlen(hex_input);
    if (hex_len % 2 != 0) {
        printf("Invalid hex string (odd length)\n");
        fclose(f);
        return;
    }
    size_t data_len = hex_len / 2;
    if (data_len > 4096) {
        printf("Content too large (max 4096 bytes)\n");
        fclose(f);
        return;
    }
    unsigned char buffer[4096];
    for (size_t i = 0; i < data_len; i++) {
        unsigned int byte;
        if (sscanf(hex_input + i*2, "%2x", &byte) != 1) {
            printf("Invalid hex character at position %zu\n", i*2);
            fclose(f);
            return;
        }
        buffer[i] = (unsigned char)byte;
    }
    fwrite(buffer, 1, data_len, f);
    fclose(f);
    printf("File written (%zu bytes)!\n", data_len);
}
int wildcard_match(const char *pattern, const char *text) {
    if (*pattern == '\0' && *text == '\0') return 1;
    if (*pattern == '*' && *(pattern + 1) != '\0' && *text == '\0') return 0;
    if (*pattern == '?' || *pattern == *text) {
        return wildcard_match(pattern + 1, text + 1);
    }
    if (*pattern == '*') {
        return wildcard_match(pattern + 1, text) || wildcard_match(pattern, text + 1);
    }
    return 0;
}
bool check_single_quote(const char *str) {
    if(strchr(str, '\''))
    {
        return true;
    }
    return false;
}
void cmd_find(const char *pattern) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!pattern) {
        printf("Usage: find <pattern>\n");
        return;
    }
    char command[512];
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    if (check_single_quote(pattern)) {
        puts("Invalid pattern!\n");
        return;
    }
    snprintf(command, sizeof(command), "find  %s  -name '%s' 2>/dev/null", user_path, pattern);
    system(command);
}
void cmd_rm(const char *path) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    char filepath[MAX_PATH];
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    
    if (strlen(current_account.current_dir) > 0) {
        snprintf(filepath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, path);
    } else {
        snprintf(filepath, MAX_PATH, "%s/%s", user_path, path);
    }
    if(!is_safe_path(user_path, path, NULL, 0)) {
        printf("Invalid path!\n");
        return;
    }
    
    if(!is_valid_filename(path)) {
        printf("Invalid filename!\n");
        return;
    }
    int result = unlink(filepath);
    if (result == 0) {
        printf("File deleted\n");
    } else if (result == -1 && errno == ENOENT) {
        printf("File not found\n");
    } else if (result == -1 && errno == EACCES) {
        printf("Permission denied\n");
    } else if (result == -1 && errno == EISDIR) {
        printf("Is a directory\n");
    } else {
        printf("Cannot delete file\n");
    }
}
void cmd_rmdir(const char *path){
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    char dirpath[MAX_PATH];
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    
    if (strlen(current_account.current_dir) > 0) {
        snprintf(dirpath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, path);
    } else {
        snprintf(dirpath, MAX_PATH, "%s/%s", user_path, path);
    }
    int result = rmdir(dirpath);
    if (result == 0) {
        printf("Directory deleted\n");
    }
    else if (result == -1 && errno == ENOENT) {
        printf("Directory not found\n");
    } else if (result == -1 && errno == ENOTEMPTY) {
        printf("Directory not empty\n");
    } else if (result == -1 && errno == EACCES) {
        printf("Permission denied\n");
    } else if (result == -1 && errno == ENOTDIR) {
        printf("Not a directory\n");
    } else {
        printf("Cannot delete directory\n");
    }
}
void cmd_mkdir(const char *dirname) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!dirname || strlen(dirname) == 0) {
        printf("Usage: mkdir <dirname>\n");
        return;
    }
    if (strstr(dirname, "..")) {
        printf("Invalid directory name!\n");
        return;
    }
    if (strchr(dirname, '/')) {
        printf("Invalid directory name! Use simple names only.\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    
    char full_path[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(full_path, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, dirname);
    } else {
        snprintf(full_path, MAX_PATH, "%s/%s", user_path, dirname);
    }
    if (mkdir(full_path, 0755) == 0) {
        printf("Directory created\n");
    } else {
        printf("Cannot create directory\n");
    }
}
void cmd_encrypt(const char *file) {
    char encoded_data[2048 + 4];
    unsigned char data[4096];
    long fsize;
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!file) {
        printf("Usage: encrypt <filename>\n");
        return;
    }
    if (!is_valid_filename(file)) {
        printf("Invalid filename!\n");
        return;
    }
    unsigned char user_key[KEY_SIZE];
    if (!get_current_user_key(user_key)) {
        printf("Failed to get user key\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char filepath[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(filepath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, file);
    } else {
        snprintf(filepath, MAX_PATH, "%s/%s", user_path, file);
    }
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        printf("Cannot open file\n");
        return;
    }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    
    if (fsize > sizeof(data)) {
        printf("File too large (max 4096 bytes)\n");
        fclose(f);
        return;
    }
    fread(data, 1, fsize, f);
    fclose(f);
    unsigned char checksum = 0;
    for (int i = 0; i < fsize; i++) {
        checksum ^= data[i];
    }
    xor_encrypt(data, fsize, user_key, KEY_SIZE);
    encoded_data[0] = 'E';
    encoded_data[1] = 'N';
    encoded_data[2] = 'C';
    encoded_data[3] = '\0';
    memcpy(encoded_data + 4, data, fsize);
    encoded_data[4 + fsize] = checksum ^ user_key[0];
    size_t encrypted_size = fsize + 1;
    char enc_filepath[MAX_PATH];
    snprintf(enc_filepath, MAX_PATH, "%s.enc", filepath);
    f = fopen(enc_filepath, "wb");
    if (!f) {
        printf("Cannot create encrypted file\n");
        return;
    }
    fwrite(encoded_data, 1, encrypted_size + 4, f);
    fclose(f);
    printf("File encrypted to %s.enc\n", file);
}
void cmd_decrypt(const char *file) {
    if (!current_account.logged_in) {
        printf("Not logged in!\n");
        return;
    }
    if (!file) {
        printf("Usage: decrypt <filename.enc>\n");
        return;
    }
    if (!is_valid_filename(file)) {
        printf("Invalid filename!\n");
        return;
    }
    unsigned char user_key[KEY_SIZE];
    if (!get_current_user_key(user_key)) {
        printf("Failed to get user key\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(current_account.username, user_path);
    char filepath[MAX_PATH];
    if (strlen(current_account.current_dir) > 0) {
        snprintf(filepath, MAX_PATH, "%s/%s/%s", user_path, current_account.current_dir, file);
    } else {
        snprintf(filepath, MAX_PATH, "%s/%s", user_path, file);
    }
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        printf("Cannot open file\n");
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 4) {
        printf("Invalid encrypted file\n");
        fclose(f);
        return;
    }
    char encoded_data[4096];
    if (fsize > sizeof(encoded_data)) {
        printf("Encrypted file too large\n");
        fclose(f);
        return;
    }
    fread(encoded_data, 1, fsize, f);
    fclose(f);
    if (encoded_data[0] != 'E' || encoded_data[1] != 'N' || encoded_data[2] != 'C' || encoded_data[3] != '\0') {
        printf("Not an encrypted file or corrupted\n");
        return;
    }
    size_t encrypted_len = fsize - 4;
    if (encrypted_len < 2) {
        printf("Invalid encrypted file\n");
        return;
    }
    unsigned char encrypted_checksum = encoded_data[fsize - 1];
    encrypted_len -= 1;
    unsigned char decoded_data[4096];
    if (encrypted_len > sizeof(decoded_data) - 1) {
        printf("Encrypted data too large\n");
        return;
    }
    memcpy(decoded_data, encoded_data + 4, encrypted_len);
    int decoded_len = encrypted_len;
    xor_encrypt(decoded_data, decoded_len, user_key, KEY_SIZE);
    unsigned char calc_checksum = 0;
    for (size_t i = 0; i < decoded_len; i++) {
        calc_checksum ^= decoded_data[i];
    }
    unsigned char expected_checksum = encrypted_checksum ^ user_key[0];
    if (calc_checksum != expected_checksum) {
        printf("Warning: Decrypted data may be corrupted (invalid checksum)\n");
    }
    char dec_filepath[MAX_PATH];
    strncpy(dec_filepath, filepath, MAX_PATH - 1);
    char *enc_ext = strstr(dec_filepath, ".enc");
    if (enc_ext && enc_ext == dec_filepath + strlen(dec_filepath) - 4) {
        strcpy(enc_ext, ".dec");
    } else {
        strncat(dec_filepath, ".dec", MAX_PATH - strlen(dec_filepath) - 1);
    }
    f = fopen(dec_filepath, "wb");
    if (!f) {
        printf("Cannot create decrypted file\n");
        return;
    }
    fwrite(decoded_data, 1, decoded_len, f);
    fclose(f);
    char *filename_only = strrchr(dec_filepath, '/');
    printf("File decrypted to %s\n", filename_only ? filename_only + 1 : dec_filepath);
}
void cmd_register() {
    char username[64];
    char password[MAX_PASSWORD];
    printf("Username: ");
    if (!fgets(username, sizeof(username), stdin)) {
        printf("Error reading input\n");
        return;
    }
    username[strcspn(username, "\n")] = 0;
    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin)) {
        printf("Error reading input\n");
        return;
    }
    password[strcspn(password, "\n")] = 0;
    if(check_single_quote(username)) {
        printf("Invalid username\n");
        return;
    }
    char user_path[MAX_PATH];
    get_user_path(username, user_path);
    struct stat st = {0};
    if (stat(user_path, &st) == 0) {
        printf("User already exists!\n");
        return;
    }
    ensure_dir(get_managed_path());
    if (mkdir(user_path, 0755) != 0) {
        printf("Failed to create user directory\n");
        return;
    }
    unsigned char user_key[KEY_SIZE];
    generate_key(user_key, KEY_SIZE);
    unsigned char encrypted_key[KEY_SIZE];
    memcpy(encrypted_key, user_key, KEY_SIZE);
    xor_encrypt(encrypted_key, KEY_SIZE, get_master_key(), KEY_SIZE);
    char key_file[MAX_PATH];
    snprintf(key_file, MAX_PATH, "%s/key.txt", user_path);
    FILE *kf = fopen(key_file, "wb");
    if (!kf) {
        printf("Failed to save key\n");
        return;
    }
    fwrite(encrypted_key, 1, KEY_SIZE, kf);
    fclose(kf);
    int pass_len = strlen(password);
    unsigned char encrypted_pass[MAX_PASSWORD + 1];
    encrypted_pass[0] = pass_len;
    memcpy(encrypted_pass + 1, password, pass_len);
    xor_encrypt(encrypted_pass + 1, pass_len, user_key, KEY_SIZE);
    char pass_file[MAX_PATH];
    snprintf(pass_file, MAX_PATH, "%s/password.txt", user_path);
    FILE *pf = fopen(pass_file, "wb");
    if (!pf) {
        printf("Failed to save password\n");
        return;
    }
    fwrite(encrypted_pass, 1, pass_len + 1, pf);
    fclose(pf);
    printf("Account created successfully!\n");
}
void cmd_login() {
    char username[64];
    char password[MAX_PASSWORD];
    printf("Username: ");
    if (!fgets(username, sizeof(username), stdin)) {
        printf("Error reading input\n");
        return;
    }
    username[strcspn(username, "\n")] = 0;
    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin)) {
        printf("Error reading input\n");
        return;
    }
    password[strcspn(password, "\n")] = 0;
    char user_path[MAX_PATH];
    get_user_path(username, user_path);
    struct stat st = {0};
    if (stat(user_path, &st) != 0) {
        printf("User not found!\n");
        return;
    }
    char key_file[MAX_PATH];
    snprintf(key_file, MAX_PATH, "%s/key.txt", user_path);
    FILE *kf = fopen(key_file, "rb");
    if (!kf) {
        printf("Key file not found!\n");
        return;
    }
    unsigned char encrypted_key[KEY_SIZE];
    fread(encrypted_key, 1, KEY_SIZE, kf);
    fclose(kf);
    unsigned char user_key[KEY_SIZE];
    memcpy(user_key, encrypted_key, KEY_SIZE);
    xor_encrypt(user_key, KEY_SIZE, get_master_key(), KEY_SIZE);
    char pass_file[MAX_PATH];
    snprintf(pass_file, MAX_PATH, "%s/password.txt", user_path);
    FILE *pf = fopen(pass_file, "rb");
    if (!pf) {
        printf("Password file not found!\n");
        return;
    }
    unsigned char encrypted_pass[MAX_PASSWORD + 1];
    fread(encrypted_pass, 1, MAX_PASSWORD + 1, pf);
    fclose(pf);
    int pass_len = encrypted_pass[0];
    unsigned char decrypted_pass[MAX_PASSWORD];
    memcpy(decrypted_pass, encrypted_pass + 1, pass_len);
    xor_encrypt(decrypted_pass, pass_len, user_key, KEY_SIZE);
    decrypted_pass[pass_len] = 0;
    if (memcmp(decrypted_pass, password, pass_len) != 0 || strlen(password) != pass_len) {
        printf("Invalid password!\n");
        return;
    }
    if( current_account.logged_in ) {
        free(current_account.username);
        free(current_account.password);
    }
    current_account.username = strdup(username);
    current_account.password = strdup(password);
    current_account.logged_in = 1;
    current_account.current_dir[0] = '\0';
    printf("Login successful! Welcome %s\n", username);
}
void cmd_logout() {
    free(current_account.username);
    free(current_account.password);
    current_account.username = NULL;
    current_account.password = NULL;
    current_account.logged_in = 0;
    current_account.current_dir[0] = '\0';
    printf("Logged out\n");
}
void cmd_admin() {
    printf("Enter MASTER_KEY: ");
    char input_key[KEY_SIZE + 2];  // +2 for newline + null
    if (!fgets(input_key, sizeof(input_key), stdin)) {
        printf("Error reading input\n");
        return;
    }
    input_key[strcspn(input_key, "\n")] = 0;
    
    unsigned char *master = get_master_key();
    if (memcmp(input_key, master, KEY_SIZE) != 0) {
        printf("Invalid MASTER_KEY!\n");
        return;
    }
    
    printf("Admin access granted!\n");
    printf("Enter system file path: ");
    char filepath[256];
    fgets(filepath, sizeof(filepath), stdin);
    filepath[strcspn(filepath, "\n")] = 0;
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("Cannot open file\n");
        return;
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }
    fclose(f);
}
void cmd_help() {
    printf("Available commands:\n");
    printf("  register                      - Create new account\n");
    printf("  login                         - Login to account\n");
    printf("  logout                        - Logout\n");
    printf("\nFile Management:\n");
    printf("  ls                            - List files\n");
    printf("  pwd                           - Print working directory\n");
    printf("  cd <dir>                      - Change directory\n");
    printf("  mkdir <dirname>               - Create directory\n");
    printf("  rmdir <dirname>               - Remove directory\n");
    printf("  cat <file>                    - Display file contents\n");
    printf("  read <filename>               - Read file\n");
    printf("  write <filename>              - Write file (input as hex)\n");
    printf("  cp <source> <dest>            - Copy file\n");
    printf("  mv <source> <dest>            - Move/rename file\n");
    printf("  rm <file>                     - Delete file\n");
    printf("  find <pattern>                - Find files by pattern\n");
    printf("\nEncryption:\n");
    printf("  encrypt <file>                - Encrypt file with user key\n");
    printf("  decrypt <file.enc>            - Decrypt file with user key\n");
    printf("\nAdmin:\n");
    printf("  admin                         - Admin access (requires MASTER_KEY)\n");
    printf("\nOther:\n");
    printf("  help                          - Show this help\n");
    printf("  exit                          - Exit program\n");
}
void handle_command(char *input) {
    input[strcspn(input, "\n")] = 0;
    if (strlen(input) == 0) return;
    char *cmd = strtok(input, " \t");
    if (!cmd) return;
    if (strcmp(cmd, "register") == 0) {
        cmd_register();
    }
    else if (strcmp(cmd, "login") == 0) {
        cmd_login();
    }
    else if (strcmp(cmd, "logout") == 0) {
        cmd_logout();
    }
    else if (strcmp(cmd, "ls") == 0) {
        cmd_ls();
    }
    else if (strcmp(cmd, "pwd") == 0) {
        cmd_pwd();
    }
    else if (strcmp(cmd, "cd") == 0) {
        char *arg = strtok(NULL, " \t");
        cmd_cd(arg);
    }
    else if (strcmp(cmd, "mkdir") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_mkdir(arg);
        else printf("Usage: mkdir <dirname>\n");
    }
    else if (strcmp(cmd, "rmdir") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_rmdir(arg);
        else printf("Usage: rmdir <dirname>\n");
    }
    else if (strcmp(cmd, "cat") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_cat(arg);
        else printf("Usage: cat <filename>\n");
    }
    else if (strcmp(cmd, "read") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_read_file(arg);
        else printf("Usage: read <filename>\n");
    }
    else if (strcmp(cmd, "write") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_write_file(arg);
        else printf("Usage: write <filename>\n");
    }
    else if (strcmp(cmd, "cp") == 0) {
        char *src = strtok(NULL, " \t");
        char *dst = strtok(NULL, " \t");
        if (src && dst) cmd_cp(src, dst);
        else printf("Usage: cp <source> <destination>\n");
    }
    else if (strcmp(cmd, "mv") == 0) {
        char *src = strtok(NULL, " \t");
        char *dst = strtok(NULL, " \t");
        if (src && dst) cmd_mv(src, dst);
        else printf("Usage: mv <source> <destination>\n");
    }
    else if (strcmp(cmd, "rm") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_rm(arg);
        else printf("Usage: rm <file>\n");
    }
    else if (strcmp(cmd, "find") == 0) {
        char *arg = strtok(NULL, " \t");
        if (arg) cmd_find(arg);
        else printf("Usage: find <pattern>\n");
    }
    else if (strcmp(cmd, "encrypt") == 0) {
        char *file = strtok(NULL, " \t");
        if (file) cmd_encrypt(file);
        else printf("Usage: encrypt <filename>\n");
    }
    else if (strcmp(cmd, "decrypt") == 0) {
        char *file = strtok(NULL, " \t");
        if (file) cmd_decrypt(file);
        else printf("Usage: decrypt <filename.enc>\n");
    }
    else if (strcmp(cmd, "admin") == 0) {
        cmd_admin();
    }
    else if (strcmp(cmd, "help") == 0) {
        cmd_help();
    }
    else if (strcmp(cmd, "exit") == 0) {
        printf("Bye!\n");
        exit(0);
    }
    else {
        printf("Unknown command: %s\n", cmd);
    }
}
int main() {
    char input[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    signal(SIGALRM, timeout_handler);
    printf("=== File Manager ===\n");
    printf("Type 'help' to see commands.\n\n");
    while (1) {
        alarm(60);
        printf("> ");
        if (!fgets(input, sizeof(input), stdin))
            break;
        handle_command(input);
    }
    return 0;
}
