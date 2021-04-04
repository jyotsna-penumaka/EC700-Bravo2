# checksig

This LSM denies execution of binaries to non-root users. To allow execution:

- Set the signature attribute `user.sig` to `Jyotsna`. You can use `setfattr -n user.sig -v Jyotsna <binary>`.
- ~~Set `security.signed` extended-attribute in the binary. You may have to enable ext4 security labels.~~