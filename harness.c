#include "../src/snaffs.h"

// This won't build, because it would've been linked to our "snaffs" file system library (which we can't share).
// But it gives you the idea. You want to declare a "struct fuse_operations ops" for the fuzzer to use.

// You also want to define "SetupFs()" and "TeardownFs()" functions, which will be called before and after each
// fuzzing run. For snaffs, we use it to allocate an in-memory file system and run makefs; and then to free it.

struct fuse_operations ops = {
    .getattr = snaffs_getattr,
    .mkdir = snaffs_mkdir,
    .rmdir = snaffs_rmdir,
    .rename = snaffs_rename,
    .link = snaffs_link,
    .unlink = snaffs_unlink,
    .chmod = snaffs_chmod,
    .chown = snaffs_chown,
    .truncate = snaffs_truncate,
    .open = snaffs_open,
    .read = snaffs_read,
    .write = snaffs_write,
    .statfs = snaffs_statfs,
    .readdir = snaffs_readdir,
    .init = snaffs_init,
    .destroy = snaffs_destroy,
    .create = snaffs_create,
    .utimens = snaffs_utimens,
};

void SetupFs() {
  CHECK_OR_FAIL(store_open("memory"));
  CHECK_OR_FAIL(makefs());
}

void TeardownFs() {
  CHECK_OR_FAIL(store_close());
  errno = 0;
}
