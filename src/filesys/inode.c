#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
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

static char zeros[BLOCK_SECTOR_SIZE];

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);

  if (pos >= inode->data.length) {
    return 0;
  }

  block_sector_t sector_idx = pos / BLOCK_SECTOR_SIZE;

  ASSERT(sector_idx < TOTAL_SECTORS_COUNT);

  if (sector_idx < DIRECT_SECTORS_COUNT) {
    return inode->data.sector_pointers[sector_idx];
  }

  size_t indirect_pointer_idx = (sector_idx - DIRECT_SECTORS_COUNT) / SINGLE_BLOCK_SECTORS_COUNT;
  size_t indirect_pointer_sector_idx =
      (sector_idx - DIRECT_SECTORS_COUNT) % SINGLE_BLOCK_SECTORS_COUNT;

  static block_sector_t buffer[SINGLE_BLOCK_SECTORS_COUNT];
  cache_read_sector(inode->data.indirect_sector_pointers[indirect_pointer_idx], buffer, 0,
                    BLOCK_SECTOR_SIZE);

  return buffer[indirect_pointer_sector_idx];
}

/*
  allocates sectors_count number of sectors starting at sector_idx for inode using direct pointers
*/
static void allocate_direct_pointers(struct inode* inode, size_t sector_idx, size_t sectors_count) {
  block_sector_t sector;

  for (size_t i = sector_idx; i < sector_idx + sectors_count; i++) {
    ASSERT(free_map_allocate(1, &sector));
    inode->data.sector_pointers[i] = sector;
    cache_write_sector(sector, zeros, 0, BLOCK_SECTOR_SIZE);
  }
}

/*
  allocates sectors_count number of sectors starting at sector_idx for inode using indirect pointers
*/
static void allocate_indirect_pointers(struct inode* inode, size_t sector_idx,
                                       size_t sectors_count) {
  size_t first_pointer_idx = sector_idx / SINGLE_BLOCK_SECTORS_COUNT;
  size_t first_sector_idx = sector_idx % SINGLE_BLOCK_SECTORS_COUNT;

  size_t first_pointer_free_sectors = SINGLE_BLOCK_SECTORS_COUNT - first_sector_idx;
  size_t sectors_left_to_allocate =
      sectors_count <= first_pointer_free_sectors ? 0 : sectors_count - first_pointer_free_sectors;
  size_t pointers_to_allocate =
      sectors_left_to_allocate > 0
          ? DIV_ROUND_UP(sectors_left_to_allocate, SINGLE_BLOCK_SECTORS_COUNT)
          : 0;
  size_t last_sector_idx = pointers_to_allocate == 0
                               ? first_sector_idx + sectors_count - 1
                               : (sectors_left_to_allocate % SINGLE_BLOCK_SECTORS_COUNT) - 1;

  static block_sector_t sector_buffer[SINGLE_BLOCK_SECTORS_COUNT];
  block_sector_t sector;
  bool is_first_run = first_sector_idx == 0;

  for (size_t i = first_pointer_idx; i <= first_pointer_idx + pointers_to_allocate; i++) {
    bool is_first_i = i == first_pointer_idx;
    bool is_last_i = i == first_pointer_idx + pointers_to_allocate;

    // if it's first pointer it's already allocated, just read the sector into the buffer
    // otherwise allocate indirect pointer
    // although there is a special case when it's a first run, then need to allocate new sector
    if (is_first_i && !is_first_run) {
      cache_read_sector(inode->data.indirect_sector_pointers[i], sector_buffer, 0,
                        BLOCK_SECTOR_SIZE);
    } else {
      ASSERT(free_map_allocate(1, &inode->data.indirect_sector_pointers[i]))
      memset(sector_buffer, 0, sizeof(block_sector_t) * SINGLE_BLOCK_SECTORS_COUNT);
      // cache_write_sector(inode->data.indirect_sector_pointers[i], zeros, 0, BLOCK_SECTOR_SIZE);
    }

    size_t j_start = is_first_i ? first_sector_idx : 0;
    size_t j_end = is_last_i ? last_sector_idx : SINGLE_BLOCK_SECTORS_COUNT - 1;

    for (size_t j = j_start; j <= j_end; j++) {
      ASSERT(free_map_allocate(1, &sector));
      sector_buffer[j] = sector;
      cache_write_sector(sector_buffer[j], zeros, 0, BLOCK_SECTOR_SIZE);
    }

    cache_write_sector(inode->data.indirect_sector_pointers[i], sector_buffer, 0,
                       BLOCK_SECTOR_SIZE);
  }
}

static bool allocate_sectors(struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);

  if (pos < inode_length(inode)) {
    return false;
  }

  block_sector_t current_sector_idx = inode_length(inode) / BLOCK_SECTOR_SIZE;
  block_sector_t target_sector_idx = pos / BLOCK_SECTOR_SIZE;
  ASSERT(target_sector_idx < TOTAL_SECTORS_COUNT);

  // allocate direct pointers
  block_sector_t first_direct_sector_idx = current_sector_idx;
  block_sector_t last_direct_sector_idx =
      target_sector_idx < DIRECT_SECTORS_COUNT ? target_sector_idx : DIRECT_SECTORS_COUNT - 1;
  int64_t count = last_direct_sector_idx - first_direct_sector_idx;
  ASSERT(count >= 0);
  if (inode_length(inode) == 0) {
    // special first run case when current_sector_idx is not yet allocated
    allocate_direct_pointers(inode, 0, count + 1);
  } else if (count > 0) {
    allocate_direct_pointers(inode, first_direct_sector_idx + 1, count);
  }

  // allocate indirect pointers
  if (target_sector_idx >= DIRECT_SECTORS_COUNT) {
    // special case when current_sector_idx is not yet allocated
    bool is_first_run = current_sector_idx < DIRECT_SECTORS_COUNT;

    block_sector_t first_sector_idx =
        current_sector_idx < DIRECT_SECTORS_COUNT ? 0 : current_sector_idx - DIRECT_SECTORS_COUNT;
    block_sector_t last_sector_idx = target_sector_idx - DIRECT_SECTORS_COUNT;
    if (is_first_run) {
      allocate_indirect_pointers(inode, 0, last_sector_idx - first_sector_idx + 1);
    } else {
      allocate_indirect_pointers(inode, first_sector_idx + 1, last_sector_idx - first_sector_idx);
    }
  }

  inode->data.length = pos;
  cache_write_sector(inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);

  return true;
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

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);

  if (disk_inode == NULL) {
    return false;
  }

  size_t sectors = bytes_to_sectors(length);
  size_t direct_sectors = sectors > DIRECT_SECTORS_COUNT ? DIRECT_SECTORS_COUNT : sectors;
  size_t indirect_sectors = sectors > DIRECT_SECTORS_COUNT ? sectors - DIRECT_SECTORS_COUNT : 0;
  size_t indirect_pointers =
      indirect_sectors > 0 ? (indirect_sectors / SINGLE_BLOCK_SECTORS_COUNT) + 1 : 0;

  ASSERT(indirect_pointers <= INDIRECT_SECTORS_COUNT);

  disk_inode->length = length;
  disk_inode->magic = INODE_MAGIC;

  if (free_map_allocate(direct_sectors, disk_inode->sector_pointers)) {
    if (direct_sectors > 0) {
      for (size_t i = 0; i < direct_sectors; i++) {
        disk_inode->sector_pointers[i] = disk_inode->sector_pointers[0] + i;
        cache_write_sector(disk_inode->sector_pointers[i], zeros, 0, BLOCK_SECTOR_SIZE);
      }
    }

    if (indirect_pointers > 0) {
      static block_sector_t sector_buffer[SINGLE_BLOCK_SECTORS_COUNT];

      for (size_t i = 0; i < indirect_pointers; i++) {
        size_t sectors_left = indirect_sectors - (i * SINGLE_BLOCK_SECTORS_COUNT);
        size_t sectors_to_allocate =
            sectors_left > SINGLE_BLOCK_SECTORS_COUNT ? SINGLE_BLOCK_SECTORS_COUNT : sectors_left;

        // allocate indirect pointer
        ASSERT(free_map_allocate(1, &disk_inode->indirect_sector_pointers[i]));

        // allocate sectors that indirect pointer points to
        ASSERT(free_map_allocate(sectors_to_allocate, &sector_buffer[0]));

        // fill in buffer with pointers
        // and write zeros to sectors
        for (size_t j = 0; j < sectors_to_allocate; j++) {
          sector_buffer[j] = sector_buffer[0] + j;
          cache_write_sector(sector_buffer[j], zeros, 0, BLOCK_SECTOR_SIZE);
        }

        // zero out remaining space
        for (size_t j = sectors_to_allocate; j < SINGLE_BLOCK_SECTORS_COUNT; j++) {
          sector_buffer[j] = 0;
        }

        cache_write_sector(disk_inode->indirect_sector_pointers[i], sector_buffer, 0,
                           BLOCK_SECTOR_SIZE);
      }
    }

    cache_write_sector(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
  }

  free(disk_inode);

  return true;
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

      size_t sectors = bytes_to_sectors(inode->data.length);
      size_t direct_sectors = sectors > DIRECT_SECTORS_COUNT ? DIRECT_SECTORS_COUNT : sectors;
      size_t indirect_sectors = sectors > DIRECT_SECTORS_COUNT ? sectors - DIRECT_SECTORS_COUNT : 0;
      size_t indirect_pointers =
          indirect_sectors > 0 ? (indirect_sectors / SINGLE_BLOCK_SECTORS_COUNT) + 1 : 0;

      for (size_t i = 0; i < direct_sectors; i++) {
        free_map_release(inode->data.sector_pointers[i], 1);
      }

      if (indirect_pointers > 0) {
        static block_sector_t buffer[SINGLE_BLOCK_SECTORS_COUNT];

        for (size_t i = 0; i < indirect_pointers; i++) {
          size_t sectors_left = indirect_sectors - (i * SINGLE_BLOCK_SECTORS_COUNT);
          size_t sectors_to_deallocate =
              sectors_left > SINGLE_BLOCK_SECTORS_COUNT ? SINGLE_BLOCK_SECTORS_COUNT : sectors_left;

          cache_read_sector(inode->data.indirect_sector_pointers[i], buffer, 0, BLOCK_SECTOR_SIZE);

          for (size_t j = 0; j < sectors_to_deallocate; j++) {
            free_map_release(buffer[j], 1);
          }

          free_map_release(inode->data.indirect_sector_pointers[i], 1);
        }
      }
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
    if (sector_idx == 0) {
      break;
    }

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

  allocate_sectors(inode, offset + size);

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    if (sector_idx == 0) {
      break;
    }

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
