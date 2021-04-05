#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/string_helpers.h>
#include <linux/sysctl.h>
#include <linux/types.h>
#include <linux/xattr.h>

// Adapted from https://github.com/skx/linux-security-modules

// Check if program allowed to execute.
// Returns 0 if allowed, -EPERM if not allowed.
static int hashcheck_bprm_check_security(struct linux_binprm *bprm) {
  u8 *digest;
  int i, rc = 0;
  char *hash = NULL;
  char *buffer = NULL;
  // The current task & the UID it is running as.
  const struct task_struct *task = current;
  kuid_t uid = task->cred->uid;

  // Target binary for checking
  struct dentry *dentry = bprm->file->f_path.dentry;
  struct inode *inode = d_backing_inode(dentry);
  int size = 0;

  // Hash calculation
  struct crypto_hash *tfm;  // sha1 hashing helper
  struct shash_desc *desc;  // hash description
  char *rbuf;
  loff_t i_size, offset = 0;

  // Root can access everything. No need to check.
  if (uid.val == 0) return 0;

  // Allocate memory to hold SHA1 digest
  digest = (u8 *)kmalloc(SHA1_DIGEST_SIZE, GFP_KERNEL);
  if (!digest) {
    printk(KERN_INFO "failed to allocate storage for digest");
    return 0;
  }

  // Calculate the hash
  memset(digest, 0, SHA1_DIGEST_SIZE);
  tfm = crypto_alloc_shash("sha1", 0, 0);
  if (IS_ERR(tfm)) {
    rc = PTR_ERR(tfm);
    printk(KERN_INFO "Failed to setup hash helper\n");
    goto out;
  }

  // Allocate enough memory for hash operational state
  desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
  if (!desc) {
    printk(KERN_INFO "Failed to kmalloc desc");
    crypto_free_shash(tfm);
    goto out;
  }

  // Initialize the hash
  rc = crypto_shash_init(desc);
  if (rc) {
    printk(KERN_INFO "Failed to crypto_shash_init");
    kfree(desc);
    goto out;
  }

  // Allocate read buffer for target file contents
  rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
  if (!rbuf) {
    printk(KERN_INFO "Failed to kzalloc rbuf");
    rc = -ENOMEM;
    kfree(desc);
    goto out;
  }

  // Calculate size of target file
  i_size = i_size_read(inode);
  // Read file in page-sized chunks
  while (offset < i_size) {
    int rbuf_len;
    // TODO: offsets is last argument in later kernels
    rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
    if (rbuf_len < 0) {
      rc = rbuf_len;
      break;
    }
    if (rbuf_len == 0) break;
    offset += rbuf_len;
    rc = crypto_shash_update(desc, rbuf, rbuf_len);
    if (rc) break;
  }

  kfree(rbuf);  // No longer need read buffer

  // Result of SHA calculation
  if (!rc) rc = crypto_shash_final(desc, digest);

  kfree(desc);
  crypto_free_shash(tfm);

  // Allocate memory for human readable hash
  hash = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
  if (!hash) {
    printk(KERN_INFO "Failed to allocate memory for readable hash");
    rc = -ENOMEM;
    goto out;
  }

  // Create human readable hash string
  memset(hash, 0, PAGE_SIZE);
  for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
    snprintf(hash + (i * 2), 4, "%02x", digest[i]);
  }

  // Read buffer for xattr value
  buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
  if (buffer == NULL) {
    printk(KERN_INFO "failed to allocate buffer for xattr value\n");
    goto out2;
  }

  // Get xattr value from target file
  size = __vfs_getxattr(dentry, inode, "security.hash", buffer, PAGE_SIZE - 1);

  rc = 0;

  // If hash is missing, block execution
  if (size < 0) {
    printk(KERN_INFO "Missing `security.hash` value!\n");
    rc = -EPERM;
  } else {
    // Compare
    if (crypto_memneq(buffer, hash, strlen(hash)) == 0) {
      printk(KERN_INFO
             "Hash of %s matched expected result %s - allowing execution\n",
             bprm->filename, hash);
      rc = 0;
    } else {
      printk(KERN_INFO "Hash mismatch for %s - denying execution [%s != %s]\n",
             bprm->filename, hash, buffer);
      rc = -EPERM;
    }
  }

  kfree(buffer);

out2:
  kfree(hash);

out:
  kfree(digest);

  return (rc);
}