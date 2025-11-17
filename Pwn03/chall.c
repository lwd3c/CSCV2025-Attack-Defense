#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define MAX_LINE 100
#define MAX_IMAGE_DATA 1024

const char *STORAGE_BASE = "/tmp/storage";
const char *INVALID_CHARS[] = {"token.txt", NULL};
char GLOBAL_KEY[65] = {0};

struct IMAGE {
    short width;
    short height;
    short data_size;
    char data[MAX_IMAGE_DATA];
};


void load_key_once(void) {
	if (GLOBAL_KEY[0] != '\x00') return;
	const char *env_key = getenv("KEY");
	if (!env_key) {
		printf("ERR KEY not found\n");
		exit(0);
	}	
	strncpy(GLOBAL_KEY, env_key, sizeof(GLOBAL_KEY) - 1);
	GLOBAL_KEY[sizeof(GLOBAL_KEY) - 1] = '\0';
}

int ensure_dir(const char *path) {
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) return 0;
		return -1;
	}
	if (mkdir(path, 0700) == 0) return 0;
	return -1;
}

int is_valid_image_name(const char *filename) {
	for(int i = 0; INVALID_CHARS[i] != NULL; i++) {
		if (strstr(filename, INVALID_CHARS[i]) != NULL) {
			return -1;
		}
	}
	return 1;
}

void hex_encode(const unsigned char *in, size_t n, char *out) {
	const char *hex = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[i * 2] = hex[(in[i] >> 4) & 0xF];
		out[i * 2 + 1] = hex[in[i] & 0xF];
	}
	out[n * 2] = 0;
}

void generate_token(const char *user, char *out) {
	load_key_once();
	unsigned char digest[SHA_DIGEST_LENGTH];
	char tmp[100];
	snprintf(tmp, sizeof(tmp), "%s:%s", user, GLOBAL_KEY);
	SHA1((unsigned char *)tmp, strlen(tmp), digest);
	hex_encode(digest, SHA_DIGEST_LENGTH, out);
}

int write_token_for_user(const char *user, const char *token) {
	char path[64];
	snprintf(path, sizeof(path), "%s/%s", STORAGE_BASE, user);
	if (ensure_dir(path) != 0) {
		printf("ERR Failed to create directory\n");
		return -1;
	}
	snprintf(path+strlen(path), sizeof(path)-strlen(path), "/token.txt");
	FILE *f = fopen(path, "wb");
	if (!f) {
		printf("ERR Failed to write token\n");
		return -1;
	}
	fprintf(f, "%s", token);
	fclose(f);
	return 0;
}

int read_token_for_user(const char *user, char *out, size_t outcap) {
	char tpath[64];
	snprintf(tpath, sizeof(tpath), "%s/%s/token.txt", STORAGE_BASE, user);
	FILE *f = fopen(tpath, "rb");
	if (!f) return -1;
	size_t n = fread(out, 1, outcap - 1, f);
	fclose(f);
	out[n] = '\x00';
	return 0;
}

void register_user(const char *user) {
	char token[41];
	if (read_token_for_user(user, token, sizeof(token)) == 0) {
		printf("ERR User already registered\n");
		return;
	}
	generate_token(user, token);
	if (write_token_for_user(user, token) != 0) {
		printf("ERR Failed to write token\n");
		return;
	}
	printf("%s", token);
	printf("\n");
}

int auth_user(const char *user, const char *token) {
	char stored[41] = {0};
	if (read_token_for_user(user, stored, sizeof(stored)) != 0) {
		printf("ERR Failed to read token\n");
		return 0;
	}
	if (strncmp(stored, token, strlen(token)) != 0) {
		printf("ERR Invalid token\n");
		return 0;
	}
	printf("OK\n");
	return 1;
}

void list_images(const char *user) {
	int flag;
	char udir[50];
	char files[50];
	snprintf(udir, sizeof(udir), "%s/%s", STORAGE_BASE, user);
	if (ensure_dir(udir) != 0) {
		return;
	}
	DIR *d = opendir(udir);
	if (!d) {
		return;
	}
	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, ".tmp") == 0 || strcmp(de->d_name, "..") == 0) {
			continue;
		}
		if (strcmp(de->d_name, "token.txt") == 0) {
			printf("HIDDEN\n");
			continue;
		}
		if (de->d_type != DT_DIR) {
			flag = 1;
		}
		sprintf(files, de->d_name);
		printf("%s\n", files);
	}
	closedir(d);
	return;
}

void upload_image(const char *user, const char *tmpname) {
	char fpath[100];
	struct IMAGE img;
	
	snprintf(fpath, sizeof(fpath), "%s/%s/%s", STORAGE_BASE, user, tmpname);
	if (access(fpath, F_OK) == 0) {
		printf("ERR Image already exists\n");
		return;
	}
	read(STDIN_FILENO, &img, sizeof(short)*3);
	if (img.width <= 0 || img.height <= 0 || img.data_size <= 0) {
		printf("ERR Invalid image\n");
		return;
	}
	if (img.data_size != img.width * img.height){
		printf("ERR Invalid image data size\n");
		return;
	}
	if (read(STDIN_FILENO, img.data, img.data_size) <= 0) {
		printf("ERR Invalid image data\n");
		return;
	}
	
	int fp = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fp < 0) {
		printf("ERR Failed to open image\n");
		return;
	}
	int total_size = sizeof(short)*3 + img.data_size;
	write(fp, &img, total_size);
	close(fp);
	printf("OK\n"); 
}

void download_image(const char *user, const char *fname) {
	char fpath[100];
	snprintf(fpath, sizeof(fpath), "%s/%s/%s", STORAGE_BASE, user, fname);
	if (is_valid_image_name(fname) == -1) {
		printf("ERR Forbidden image name\n");
		return;
	}
	int fd = open(fpath, O_RDONLY);
	if (fd < 0) {
		printf("ERR Failed to open image\n");
		return;
	}
	struct stat st;
	if (fstat(fd, &st) != 0) {
		close(fd);
		printf("ERR Failed to stat image\n");
		return;
	}
	char buf[st.st_size];
	if (read(fd, buf, st.st_size) <= 0) {
		close(fd);
		printf("ERR Failed to read image\n");
		return;
	}
	close(fd);
	write(STDOUT_FILENO, buf, st.st_size);
	printf("\nOK\n");
}
int handle_client(void) {
	char line[MAX_LINE];
	int authed = 0;
	char user[33] = {0};
	while (1) {
		int r = read(STDIN_FILENO, line, sizeof(line));
		if (r <= 0) {
			return -1;
		}
		line[r] = '\0';
		if (strncmp(line, "REGISTER ", 9) == 0) {
			sscanf(line + 9, "%32s", user);
			register_user(user);
		} else if (strncmp(line, "AUTH ", 5) == 0) {
			char token[41] = {0};
			if (sscanf(line + 5, "%32s %40s", user, token) != 2) {
				printf("ERR Invalid command\n");
				continue;
			}
			authed = auth_user(user, token);
		} else if (strncmp(line, "LIST", 4) == 0) {
			if (!authed) {
				printf("ERR Unauthorized\n");
				continue;
			}
			list_images(user);
		} else if (strncmp(line, "UPLOAD ", 7) == 0) {
			if (!authed) {
				printf("ERR Unauthorized\n");
				continue;
			}
			char tmpname[50] = {0};
			if (sscanf(line + 7, "%49s", tmpname) != 1) {
				printf("ERR Invalid image\n");
				continue;
			}
			upload_image(user, tmpname);
		} else if (strncmp(line, "DOWNLOAD ", 9) == 0) {
			if (!authed) {
				printf("ERR Unauthorized\n");
				continue;
			}
			char fname[50] = {0};
			if (sscanf(line + 9, "%49s", fname) != 1) {
				printf("ERR Invalid image\n");
				continue;
			}
			download_image(user, fname);
		} else {
			printf("ERR Invalid command\n");
		} 
	}
}

int main() {
	signal(SIGPIPE, SIG_IGN);
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	
	handle_client();
	return 0;
}
