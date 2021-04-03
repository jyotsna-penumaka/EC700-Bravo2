// REFERENCE : https://www.embedded.com/using-digital-signatures-for-data-integrity-checking-in-linux/ 

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#define MD5_STR_SIZE (MD5_DIGEST_LENGTH * 2 + 1)
#define SIGNATURE_SECTION_NAME ".sig"
#define FILE_PIECE (1024)
#define PWS_BUFFER (1024)
#define PATH_TO_CERTIFICATE "/.ssh/pub.crt"

void get_md5(char *m, size_t l, unsigned char *md5) {
    MD5_CTX mdContext = { 0 };
    MD5_Init(&mdContext);
    char *tmp = m;
    size_t bytes = l;
    // We cannot upload a big memory by one call of MD5_Update. Therefore, we
    // upload a whole file by pieces. The size of each piece is 1024 bytes,
    while (bytes > FILE_PIECE) {
        MD5_Update(&mdContext, tmp, FILE_PIECE);
        tmp = tmp + FILE_PIECE;
        bytes = bytes - FILE_PIECE;
    }
    // Upload last piece
    MD5_Update(&mdContext, tmp, bytes);
    // Calculate MD5
    MD5_Final(md5, &mdContext);
}

int calculate_md5(const char *const fname, unsigned char *md5) {
    struct stat st = {0};
    size_t size = 0;
    int fd = -1;
    int i = 0;
    int shnum = 0;
    const char *sh_strtab_p = NULL;
    char *p = NULL;
    char *m = NULL;
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Shdr *shdr = NULL;
    Elf64_Shdr *sh_strtab = NULL;
    // Get size of binary
    if (stat(fname, &st) != 0) {
        perror("stat");
        return 1;
    }
    size = st.st_size;
    // Open binary file for reading
    fd = open(fname, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    // Map binary file
    p = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    // Allocate memory to store mapped file
    m = (char *)calloc(size, sizeof(char));
    if (m == NULL) {
        perror("calloc");
        munmap(p, size);
        return 1;
    }
    // Copy mapped binary file to allocated memory
    memcpy(m, p, size);
    // Unmap mapped file
    munmap(p, size);
    // Get pointer to ELF header
    ehdr = (Elf64_Ehdr *)m;
    // Get pointer to section header table
    shdr = (Elf64_Shdr *)(m + ehdr->e_shoff);
    // Get number of section header table items
    shnum = ehdr->e_shnum;
    // Get pointer to section header string table
    sh_strtab = &shdr[ehdr->e_shstrndx];
    // Get base address of section header string table
    sh_strtab_p = m + sh_strtab->sh_offset;
    // For each section
    for (i = 0; i < shnum; ++i) {
        char *section_name = NULL;
        // Get section name
        section_name = (char *)(sh_strtab_p + shdr[i].sh_name);
        // If it is '.sig' section
        if (!strncmp(section_name, SIGNATURE_SECTION_NAME,strlen(SIGNATURE_SECTION_NAME))) {
            // Fill section content with zeros
            memset(m + shdr[i].sh_offset, 0, shdr[i].sh_size);
        }
    }
    // Calculate MD5 of memory
    get_md5(m, size, md5);
    // Free memory
    free(m);
    munmap(p, size);
    return 0;
}
int get_signature(const char *const fname, unsigned char *encrypted_md5) {
    Elf64_Ehdr *ehdr = NULL;
    Elf64_Shdr *shdr = NULL;
    Elf64_Shdr *sh_strtab = NULL;
    struct stat st = {0};
    size_t size = 0;
    int fd = -1;
    int i = 0;
    int shnum = 0;
    const char *sh_strtab_p = NULL;
    char *p = NULL;
    // Get size of binary
    if (stat(fname, &st) != 0) {
        perror("stat");
        return 1;
    }
    size = st.st_size;
    // Open binary file for reading
    fd = open(fname, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
}

// Map binary file
p = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
if (p == MAP_FAILED) {
    perror("mmap");
    return 1;
}
// Get pointer to ELF header
ehdr = (Elf64_Ehdr *)p;
// Get pointer to section header table
shdr = (Elf64_Shdr *)(p + ehdr->e_shoff);
// Get number of section header table items
shnum = ehdr->e_shnum;
// Get pointer to section header string table
sh_strtab = &shdr[ehdr->e_shstrndx];
// Get base address of section header string table
sh_strtab_p = p + sh_strtab->sh_offset;
// For each section
for (i = 0; i < shnum; ++i) {
    char *section_name = NULL;
    // Get section name
    section_name = (char *)(sh_strtab_p + shdr[i].sh_name);
    // If it is '.sig' section
    if (!strncmp(section_name, SIGNATURE_SECTION_NAME,strlen(SIGNATURE_SECTION_NAME))) {
        int section_size = 0;
        int section_offset = 0;
        // Get '.sig' section size
        section_size = shdr[i].sh_size;
        // Get '.sig' section offset from start of ELF binary file
        section_offset = shdr[i].sh_offset;
        // Copy content of '.sig' section to array
        memcpy(encrypted_md5, (char *)(p + section_offset), section_size);
    }
}

munmap(p, size);
return 0;
}

int check_integrity(const char * const binary) {
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY *sigkey = NULL;
    BIO *bio_cert = NULL;
    struct passwd *result = NULL;
    struct passwd pws = {0};
    char md5_string[MD5_STR_SIZE] = {0};
    char certificate[PATH_MAX] = {''};
    unsigned char encrypted_md5[512] = {0};
    unsigned char md5[MD5_DIGEST_LENGTH] = {0};
    char buff[PWS_BUFFER] = {0};
    char *p = NULL;
    int siglen = 0;
    int ret = -1;
    if ((binary == NULL) || (binary[0] == '')) {
        fprintf(stderr, "Binary file is not validn");
        goto cleanup;
    }
    // Get home directory. We call getpwuid_r() instead of getpwuid() because
    // getpwuid_r() is thread-safe. Also we call geteuid() instead of getuid()
    // to get effective user ID: only user who is owner of executable file
    // has to be able to run this file
    if (getpwuid_r(geteuid(), &pws, buff, sizeof(buff), &result) != 0) {
        fprintf(stderr, "Failed to get home directoryn");
        goto cleanup;
    }
    // Create absolute path for certificate
    strncpy(certificate, pws.pw_dir, strlen(pws.pw_dir));
    strncat(certificate, PATH_TO_CERTIFICATE, strlen(PATH_TO_CERTIFICATE));
    // Add all digest algorithms to the table
    OpenSSL_add_all_algorithms();
    // allocates and initializes a X509 object
    X509 *cert = X509_new();
    if (cert == NULL) {
        fprintf(stderr, "X509_new() failedn");
        goto cleanup;
    }
    // Create BIO object associated with certificate
    bio_cert = BIO_new_file(certificate, "rb");
    if (bio_cert == NULL) {
        fprintf(stderr, "BIO_new_file() failedn");
        goto cleanup;
    }
    // Read certificate in PEM format from BIO
    if (PEM_read_bio_X509(bio_cert, &cert, NULL, NULL) == NULL) {
        fprintf(stderr, "PEM_read_bio_X509 failedn");
        goto cleanup;
    }
    // Get public key from certificate
    sigkey = X509_get_pubkey(cert);
    if (bio_cert == NULL) {
        fprintf(stderr, "X509_get_pubkey() failedn");
        goto cleanup;
    }
    // Create message digest context
    mctx = EVP_MD_CTX_create();
    if (mctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_create() failedn");
        goto cleanup;
    }
    // Set up verification context mctx using public key
    if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, sigkey)) {
        fprintf(stderr, "EVP_DigestVerifyInit() failedn");
        goto cleanup;
    }
    // Get encrypted signature from ELF binary
    if (get_signature(binary, encrypted_md5)) {
        fprintf(stderr, "get_signature() failedn");
        goto cleanup;
    }
    // Get sigkey size295
    siglen = EVP_PKEY_size(sigkey);
    if (siglen <= 0) {
        fprintf(stderr, "Error reading signature filen");
        goto cleanup;
    }
    // Get original MD5 from ELF
    if (calculate_md5(binary, md5)) {
        fprintf(stderr, "get_signature() failedn");
        goto cleanup;
    }
    // Convert MD5 digital to human readable string
    p = md5_string;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(p, MD5_DIGEST_LENGTH, "%02x", md5[i]);
        // one step is two symbols
        p = p + 2;
    }
    // Last symbol is new line
    md5_string[MD5_STR_SIZE - 1] = 'n';
    // Add buffer (original MD5) to be compared to context
    EVP_DigestSignUpdate(mctx, md5_string, MD5_STR_SIZE);
    // Add encrypted buffer to context and perform verification
    ret = EVP_DigestVerifyFinal(mctx, encrypted_md5, (unsigned int)siglen);
    if (ret > 0) {
        fprintf(stderr, "Verified OKn");
        ret = 0;
    }
    else if (ret == 0) {
        fprintf(stderr, "Verification Failuren");
        ret = -1;     
    }
    else {
        fprintf(stderr, "Error Verifying Datan");
        ret = -1;
    }

    cleanup:
    // Release objects
    EVP_MD_CTX_destroy(mctx);
    X509_free(cert);
    EVP_PKEY_free(sigkey);
    BIO_free(bio_cert);
    EVP_cleanup();
    return ret;
}

int main(int argc, char **argv) {
    if (check_integrity(argv[0]) < 0) {
        fprintf(stderr, "Signature check failedn");
        return 1;
    }
    else{
        return 0;
    }
}