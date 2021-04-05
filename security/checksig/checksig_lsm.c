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
// The above repo has lsm hash check,
// stores hash in security attribute, while we use name attribute.
// It also stores hash in kernel memory, which we haven't figured out for new kernel yet.

// Checks that the name attribute of a file matches "Jyotsna"
static void check_attr(struct linux_binprm * bprm) {
    char * name_attr = NULL;
    char * expected_attr = "__EC700";
    char * hash = NULL;
    u8 * digest;
    struct dentry * dentry = bprm -> file -> f_path.dentry;
    struct inode * inode = d_backing_inode(dentry);
    struct crypto_shash * tfm;
    struct shash_desc * desc;
    char * rbuf;
    loff_t i_size, offset = 0;
    int rc = 0;
    int i;

    name_attr = kzalloc(8, GFP_KERNEL);
    if (name_attr == NULL) {
        printk(KERN_INFO "failed to allocate buffer for xattr value\n");
		return rc;
    }
    int size = __vfs_getxattr(dentry, inode, "user.key", name_attr, PAGE_SIZE - 1);
    if (crypto_memneq(name_attr, expected_attr, strlen(expected_attr)) == 0) {
        digest = (u8 * ) kmalloc(SHA1_DIGEST_SIZE, GFP_KERNEL);
        if (!digest) {
            printk(KERN_INFO "failed to allocate storage for digest");
			return 0;

        }
        memset(digest, 0, SHA1_DIGEST_SIZE);
		// TODO: This has some issues, try different algorithm?
        tfm = crypto_alloc_shash("sha1", 0, 0);

        if (IS_ERR(tfm)) {
			int error = PTR_ERR(tfm);
            printk(KERN_INFO "failed to setup sha1 hasher\n");
			return error;
        }

        desc = kmalloc(sizeof( * desc) + crypto_shash_descsize(tfm), GFP_KERNEL);

        if (!desc) {
            printk(KERN_INFO "Failed to kmalloc desc");
			crypto_free_shash(tfm);
			return 0;
        }
        desc -> tfm = tfm;
		// TODO: Kernel 5.10 does not have flags member
        //desc->flags = crypto_shash_get_flags(tfm);

        rc = crypto_shash_init(desc);
        if (rc) {
            printk(KERN_INFO "failed to crypto_shash_init");
    		kfree(desc);
			return 0;
        }

        rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);

        if (!rbuf) {
            printk(KERN_INFO "failed to kzalloc");
			kfree(desc);
			return 0;
        }
        i_size = i_size_read(inode);

        while (offset < i_size) {

            int rbuf_len;
            rbuf_len = kernel_read(bprm -> file, offset, rbuf, PAGE_SIZE);
            if (rbuf_len < 0) {
                rc = rbuf_len;
                break;
            }

            if (rbuf_len == 0)
                break;

            offset += rbuf_len;

            rc = crypto_shash_update(desc, rbuf, rbuf_len);

            if (rc)
                break;
        }

        if (!rc)
            rc = crypto_shash_final(desc, digest);

        hash = (char * ) kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!hash) {
            printk(KERN_INFO "failed to allocate storage for digest-pretty");
            rc = -ENOMEM;
			return rc;
        }
        memset(hash, 0, PAGE_SIZE);
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
            snprintf(hash + (i * 2), 4, "%02x", digest[i]);
        }

        printk(KERN_INFO "Hash of %s matched expected result %s - allowing execution\n", bprm -> filename, name_attr);
        printk(KERN_INFO "Hash is : %s", hash);

        kfree(rbuf);
        kfree(desc);
        kfree(name_attr);
    }
}

static struct security_hook_list checksig_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(bprm_check_security, check_attr),
};

static int __init checksig_init(void) {
    security_add_hooks(checksig_hooks, ARRAY_SIZE(checksig_hooks), "checksig");
    printk(KERN_INFO "LSM initialized: checksig\n");
    return 0;
}

DEFINE_LSM(checksig_init) = {
    .init = checksig_init,
    .name = "checksig",
};
