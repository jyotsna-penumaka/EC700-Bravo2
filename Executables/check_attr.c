#include <trace/events/sched.h>
#include <linux/xattr.h>
#include <crypto/algapi.h>
#include <crypto/sha.h>
#include <crypto/hash.h>

static int check_attr (struct linux_binprm *bprm){
	    char * name_attr = NULL;
        char * expected_user = "Jyotsna";
		char * key = "__EC700";
        struct dentry *dentry = bprm->file->f_path.dentry;
        struct inode *inode = d_backing_inode(dentry);
        name_attr = kzalloc(8, GFP_KERNEL);
        if (name_attr == NULL){
                printk(KERN_INFO "failed to allocate buffer for xattr value\n");
        }
        int size = __vfs_getxattr(dentry, inode, "user.name", name_attr, PAGE_SIZE - 1);
        if (crypto_memneq(name_attr, expected_user, strlen(expected_user)) == 0)
        {
				int size = __vfs_getxattr(dentry, inode, "user.key", name_attr, PAGE_SIZE - 1);
				        if (crypto_memneq(name_attr, key, strlen(expected_user)) == 0)
        				{
							printk(KERN_INFO "Hash of %s matched expected result %s - allowing execution\n", bprm->filename, name_attr);
							return 0;
						}
				return -1;
        }
}