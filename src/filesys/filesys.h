#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

/* Block device that contains the file system. */
extern struct block* fs_device;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(struct dir* anchor_dir, const char* filepath, off_t initial_size);
struct file* filesys_open(struct dir* anchor_dir, const char* filepath);
bool filesys_remove(struct dir* anchor_dir, const char* name);
struct dir* filesys_opendir(struct dir* anchor_dir, const char* dirpath);
bool filesys_mkdir(struct dir* anchor_dir, const char* dirpath);
struct inode* filesys_open_inode(struct dir* anchor_dir, const char* filepath);

#endif /* filesys/filesys.h */
