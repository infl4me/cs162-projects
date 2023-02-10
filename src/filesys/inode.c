#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/inode.h"

struct cache_entry {
  bool dirty;
  bool warm;
  block_sector_t sector;
  uint8_t data[BLOCK_SECTOR_SIZE];
};

void cache_init(void);
void cache_read_sector(block_sector_t sector, void* buffer, int sector_ofs, int chunk_size);
void cache_write_sector(block_sector_t sector, const void* buffer, int sector_ofs, int chunk_size);

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

static uint8_t CACHE_MAX_SIZE = 64;
static struct cache_entry* cache;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  cache_init();
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      cache_write_sector(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          cache_write_sector(disk_inode->start + i, zeros, 0, BLOCK_SECTOR_SIZE);
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read_sector(inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    cache_read_sector(sector_idx, buffer + bytes_read, sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    cache_write_sector(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

void cache_init() {
  cache = calloc(CACHE_MAX_SIZE, sizeof(struct cache_entry));
  ASSERT(cache != NULL);
}

void cache_read_sector(block_sector_t sector, void* buffer, int sector_ofs, int chunk_size) {
  struct cache_entry* cache_entry = &cache[sector % CACHE_MAX_SIZE];

  if (!cache_entry->warm) {
    block_read(fs_device, sector, cache_entry->data);
    cache_entry->sector = sector;
    cache_entry->warm = true;
    cache_entry->dirty = false;
  }

  // sector already in cache, just copy it into the buffer
  if (cache_entry->sector == sector) {
    memcpy(buffer, cache_entry->data + sector_ofs, chunk_size);
    return;
  }

  // if sector is different and cache is dirty, evict the cache entry
  // load current sector into the cache
  // write current cache entry into the buffer
  if (cache_entry->dirty) {
    block_write(fs_device, cache_entry->sector, cache_entry->data);
  }

  block_read(fs_device, sector, cache_entry->data);
  memcpy(buffer, cache_entry->data + sector_ofs, chunk_size);

  cache_entry->sector = sector;
  cache_entry->dirty = false;
}

void cache_write_sector(block_sector_t sector, const void* buffer, int sector_ofs, int chunk_size) {
  struct cache_entry* cache_entry = &cache[sector % CACHE_MAX_SIZE];

  // if cache empty load sector
  if (!cache_entry->warm) {
    block_read(fs_device, sector, cache_entry->data);
    cache_entry->sector = sector;
    cache_entry->warm = true;
    cache_entry->dirty = false;
  }

  // if sector matches write right into the cache and return
  if (cache_entry->sector == sector) {
    memcpy(cache_entry->data + sector_ofs, buffer, chunk_size);
    cache_entry->dirty = true;
    return;
  }

  // if sector is different and cache is dirty, evict the cache entry
  // write current sector into the cache
  // write buffer onto cache entry
  if (cache_entry->dirty) {
    block_write(fs_device, cache_entry->sector, cache_entry->data);
  }

  block_read(fs_device, sector, cache_entry->data);
  memcpy(cache_entry->data + sector_ofs, buffer, chunk_size);
  cache_entry->sector = sector;
  cache_entry->dirty = true;
}

void cache_flush() {
  for (size_t i = 0; i < CACHE_MAX_SIZE; i++) {
    struct cache_entry* cache_entry = &cache[i];
    if (cache_entry->dirty) {
      block_write(fs_device, cache_entry->sector, cache_entry->data);
      cache_entry->dirty = false;
    }
  }
}
