#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <list.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

struct bitmap;

#define DIRECT_SECTORS_COUNT 15
#define INDIRECT_SECTORS_COUNT 110
#define SINGLE_BLOCK_SECTORS_COUNT 128 // how many sector pointers can fit one sector
#define TOTAL_SECTORS_COUNT (DIRECT_SECTORS_COUNT + (INDIRECT_SECTORS_COUNT * SINGLE_BLOCK_SECTORS_COUNT))

/* inode meta data flags */
enum inode_flags {
  INODE_FILE_TYPE = 000,
  INODE_DIR_TYPE = 001
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;         /* File size in bytes. */
  enum inode_flags flags;
  unsigned magic;       /* Magic number. */
  block_sector_t sector_pointers[DIRECT_SECTORS_COUNT]; /* Direct sector pointers */
  block_sector_t indirect_sector_pointers[INDIRECT_SECTORS_COUNT]; /* Indirect sector pointers */
};

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

void inode_init(void);
bool inode_create(block_sector_t, off_t, enum inode_flags);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
block_sector_t inode_get_sector(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
bool inode_is_dir(const struct inode*);

void cache_flush(void);

#endif /* filesys/inode.h */
