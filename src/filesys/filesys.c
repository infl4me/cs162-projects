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

  char name[NAME_MAX + 1];
  const char* srcp = path;

  if (get_next_part(name, &srcp) != 1)
    return NULL;

  struct inode* inode = NULL;
  struct dir* dir = dir_reopen(anchor_dir);

  while (dir != NULL && dir_lookup(dir, name, &inode)) {
    dir_close(dir);

    switch (get_next_part(name, &srcp)) {
      // current inode is a dir, go next
      case 1:
        dir = dir_open(inode);
        break;
      // current inode is the last part of the path, we done
      case 0:
        return inode;
      // path is invalid
      case -1:
        return NULL;
    }
  }

  // if dir lookup failed
  // and it's the last directory in the path
  // and return_dir set to true return directory inode
  if (dir != NULL && return_dir) {
    if (filename_buffer != NULL)
      strlcpy(filename_buffer, name, sizeof name);
    if (get_next_part(name, &srcp) == 0) {
      inode = inode_reopen(dir_get_inode(dir));
      dir_close(dir);
      return inode;
    }
  }

  // if dir lookup failed
  dir_close(dir);
  return NULL;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}
// bool filesys_remove(struct dir* anchor_dir, const char* filepath) {
//   struct dir* dir = anchor_dir == NULL ? dir_open_root() : anchor_dir;

//   char filename[NAME_MAX + 1];
//   struct inode* inode = dir_tree_lookup(anchor_dir, filepath, true, filename);
//   if (anchor_dir == NULL) dir_close(dir);

//   struct dir* parent_dir = inode == NULL ? NULL : dir_open(inode);

//   bool success = parent_dir != NULL && dir_remove(parent_dir, filename);
//   dir_close(parent_dir);

//   return success;
// }

bool filesys_mkdir(struct dir* anchor_dir, const char* dirpath) {
  char dirname[NAME_MAX + 1];
  struct inode* inode = dir_tree_lookup(anchor_dir, dirpath, true, dirname);

  if (inode == NULL)
    return false;

  struct dir* dir = dir_open(inode);

  block_sector_t inode_sector = 0;
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  dir_create(inode_sector, 16) && dir_add(dir, dirname, inode_sector));

  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return true;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
