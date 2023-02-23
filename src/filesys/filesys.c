#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
struct inode* dir_tree_lookup(struct dir* anchor_dir, const char* path, bool return_dir,
                              char* filename_buffer);

/*
  Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
  next call will return the next file name part.
  Returns 1 if successful, 0 at end of string, -1 for a too-long file name part.
*/
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;
  /* Skip leading slashes. If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;
  /* Copy up to NAME_MAX character from SRC to DST. Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';
  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  cache_flush();
  free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(struct dir* _anchor_dir, const char* filepath, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* anchor_dir = _anchor_dir == NULL ? dir_open_root() : _anchor_dir;

  char filename[NAME_MAX + 1];
  struct inode* inode = dir_tree_lookup(anchor_dir, filepath, true, filename);

  if (_anchor_dir == NULL)
    dir_close(anchor_dir);

  struct dir* parent_dir = inode == NULL ? NULL : dir_open(inode);

  bool success = (parent_dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, INODE_FILE_TYPE) &&
                  dir_add(parent_dir, filename, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(parent_dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(struct dir* anchor_dir, const char* name) {
  struct dir* dir = anchor_dir == NULL ? dir_open_root() : anchor_dir;
  struct inode* inode = dir_tree_lookup(dir, name, false, NULL);

  if (anchor_dir == NULL)
    dir_close(dir);

  if (inode == NULL)
    return NULL;

  if (inode_is_dir(inode)) {
    inode_close(inode);
    return NULL;
  }

  return file_open(inode);
}

struct inode* filesys_open_inode(struct dir* anchor_dir, const char* name) {
  return dir_tree_lookup(anchor_dir, name, false, NULL);
}

struct dir* filesys_opendir(struct dir* anchor_dir, const char* name) {
  struct inode* inode = dir_tree_lookup(anchor_dir, name, false, NULL);

  if (inode == NULL)
    return NULL;

  if (!inode_is_dir(inode)) {
    inode_close(inode);
    return NULL;
  }

  return dir_open(inode);
}

/*
  Looks up for a file (or directory) starting at anchor_dir inside the given PATH 
  if return_dir is true returns inode of the directory that contains the wanted file
  if filename_buffer is present it's filled with the name of the wanted file

  Returns inode of the wanted file (or directory) or NULL if file not found
*/
struct inode* dir_tree_lookup(struct dir* anchor_dir, const char* path, bool return_dir,
                              char* filename_buffer) {
  if (anchor_dir == NULL)
    return NULL;
  if (inode_get_sector(dir_get_inode(anchor_dir)) == ROOT_DIR_SECTOR) {
    // handle corner case of path="/" here
    if (path[0] == '/' && path[1] == '\0') {
      return inode_reopen(dir_get_inode(anchor_dir));
    }
  }

  char name[NAME_MAX + 1];
  const char* srcp = path;

  int search_result = get_next_part(name, &srcp);

  if (search_result != 1)
    return NULL;

  struct inode* inode = NULL;
  struct dir* dir = dir_reopen(anchor_dir);
  bool lookup_success;

  while (dir != NULL && (lookup_success = dir_lookup(dir, name, &inode))) {
    search_result = get_next_part(name, &srcp);

    if (search_result == 1) {
      dir_close(dir);
      dir = dir_open(inode);
    } else if (search_result == 0) {
      break;
    } else if (search_result == -1) {
      dir_close(dir);
      return NULL;
    }
  }

  if (dir == NULL) {
    return NULL;
  }

  if (filename_buffer != NULL)
    strlcpy(filename_buffer, name, sizeof name);

  // if lookup is success and return_dir is true or
  // if lookup failed but return_dir is true and it is the last part of the PATH
  // return current dir instead of the file
  if ((lookup_success && return_dir) ||
      (!lookup_success && return_dir && get_next_part(name, &srcp) == 0)) {
    inode_close(inode);
    inode = inode_reopen(dir_get_inode(dir));
  }

  dir_close(dir);

  return inode;
}

bool filesys_is_empty_dir(struct inode* dir_inode);
bool filesys_is_empty_dir(struct inode* dir_inode) {
  // each dir contains at least two entries: "." and ".."
  // so consider that anything bigger then two entries is not empty
  return (uint32_t)inode_length(dir_inode) <= sizeof(struct dir_entry) * 2;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(struct dir* _anchor_dir, const char* filepath) {
  struct dir* anchor_dir = _anchor_dir == NULL ? dir_open_root() : _anchor_dir;

  char filename[NAME_MAX + 1];
  struct inode* dir_inode = dir_tree_lookup(anchor_dir, filepath, true, filename);
  if (_anchor_dir == NULL)
    dir_close(anchor_dir);

  struct dir* parent_dir = dir_inode == NULL ? NULL : dir_open(dir_inode);
  if (parent_dir == NULL)
    return false;

  struct inode* file_inode = NULL;
  if (!dir_lookup(parent_dir, filename, &file_inode)) {
    dir_close(parent_dir);
    return false;
  }

  if (inode_is_dir(file_inode) && !filesys_is_empty_dir(file_inode)) {
    dir_close(parent_dir);
    inode_close(file_inode);
    return false;
  }

  inode_close(file_inode);
  dir_remove(parent_dir, filename);
  dir_close(parent_dir);

  return true;
}

bool filesys_mkdir(struct dir* anchor_dir, const char* dirpath) {
  char dirname[NAME_MAX + 1];
  struct inode* inode = dir_tree_lookup(anchor_dir, dirpath, true, dirname);

  if (inode == NULL)
    return false;

  struct dir* parent_dir = dir_open(inode);

  block_sector_t inode_sector = 0;
  bool success = (parent_dir != NULL && free_map_allocate(1, &inode_sector) &&
                  dir_create(inode_sector, 0) && dir_add(parent_dir, dirname, inode_sector));

  struct dir* new_dir = success ? dir_open(inode_open(inode_sector)) : NULL;
  if (success && new_dir != NULL) {
    success = dir_add(new_dir, ".", inode_sector) &&
              dir_add(new_dir, "..", inode_get_sector(dir_get_inode(parent_dir)));
    dir_close(new_dir);
  }
              ASSERT(success);

  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(parent_dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  bool success = dir_create(ROOT_DIR_SECTOR, 16);
  if (success) {
    struct dir* root_dir = dir_open(inode_open(ROOT_DIR_SECTOR));
    success = root_dir != NULL && dir_add(root_dir, ".", ROOT_DIR_SECTOR) &&
              dir_add(root_dir, "..", ROOT_DIR_SECTOR);
    dir_close(root_dir);
  } else {
    PANIC("root directory creation failed");
  }

  free_map_close();
  printf("done.\n");
}
