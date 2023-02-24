#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/synch.h"
#include <float.h>

static void syscall_handler(struct intr_frame*);
void exit_process(int status);
void soft_exit_process(int status);
void syscall_release(void);
void syscall_acquire(void);
bool file_syscall_handler(struct intr_frame*);
void validate_string_in_user_region(const char* string);
void validate_buffer_in_user_region(const void* buffer, size_t length);
struct dir* get_anchor_dir(char** filepathp);

static struct lock syscall_lock;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&syscall_lock);
}

void exit_process(int status) {
  syscall_release();
  process_exit(status);
}

void soft_exit_process(int status) {
  syscall_release();
  soft_process_exit(status);
}

void syscall_acquire() {
  struct thread* t = thread_current();
  t->in_syscall = true;
  lock_acquire(&syscall_lock);
}

void syscall_release() {
  struct thread* t = thread_current();
  t->in_syscall = false;
  lock_release(&syscall_lock);
}

/*
 * This does not check that the buffer consists of only mapped pages; it merely
 * checks the buffer exists entirely below PHYS_BASE.
 */
void validate_buffer_in_user_region(const void* buffer, size_t length) {
  struct thread* cur_t = thread_current();
  uintptr_t delta = PHYS_BASE - buffer;

  if (!is_user_vaddr(buffer) || length > delta ||
      (buffer != NULL && pagedir_get_page(cur_t->pcb->pagedir, buffer) == NULL)) {
    exit_process(-1);
  }
}

/*
 * This does not check that the string consists of only mapped pages; it merely
 * checks the string exists entirely below PHYS_BASE.
 */
void validate_string_in_user_region(const char* string) {
  uintptr_t delta = PHYS_BASE - (const void*)string;
  if (!is_user_vaddr(string) || strnlen(string, delta) == delta)
    exit_process(-1);
}

void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  syscall_acquire();

  validate_buffer_in_user_region(args, sizeof(uint32_t));

  if (file_syscall_handler(f)) {
    syscall_release();
    return;
  }

  switch (args[0]) {
    // processes
    case SYS_EXIT:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      exit_process(args[1]);
      NOT_REACHED();
      break;
    case SYS_SOFT_EXIT:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      soft_exit_process(args[1]);
      NOT_REACHED();
      break;
    case SYS_EXEC:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);

      f->eax = process_execute((char*)args[1]);
      break;
    case SYS_WAIT:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      syscall_release();
      f->eax = process_wait(args[1]);
      syscall_acquire();
      break;

    // synch
    case SYS_LOCK_INIT:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      f->eax = process_init_lock(args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      syscall_release();
      f->eax = process_acquire_lock(args[1]);
      syscall_acquire();
      break;
    case SYS_LOCK_RELEASE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      syscall_release();
      f->eax = process_release_lock(args[1]);
      syscall_acquire();
      break;
    case SYS_SEMA_INIT:
      validate_buffer_in_user_region(&args[1], 2 * sizeof(uint32_t));

      f->eax = process_sema_init(args[1], args[2]);
      break;
    case SYS_SEMA_UP:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      syscall_release();
      f->eax = process_sema_up(args[1]);
      syscall_acquire();
      break;
    case SYS_SEMA_DOWN:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      syscall_release();
      f->eax = process_sema_down(args[1]);
      syscall_acquire();
      break;

    // threads
    case SYS_PT_CREATE:
      validate_buffer_in_user_region(&args[1], 3 * sizeof(uint32_t));
      validate_buffer_in_user_region((void*)args[1], sizeof(uint32_t));
      validate_buffer_in_user_region((void*)args[2], sizeof(uint32_t));
      validate_buffer_in_user_region((void*)args[3], sizeof(uint32_t));

      f->eax = pthread_execute((stub_fun)args[1], (pthread_fun)args[2], (void*)args[3]);
      break;
    case SYS_PT_JOIN:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      syscall_release();
      f->eax = pthread_join((tid_t)args[1]);
      syscall_acquire();
      break;
    case SYS_PT_EXIT:
      syscall_release();
      pthread_exit();
      NOT_REACHED();
      break;
    case SYS_GET_TID:
      f->eax = thread_current()->tid;
      break;

    // other
    case SYS_PRACTICE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      f->eax = args[1] + 1;
      break;
    case SYS_COMPUTE_E:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_HALT:
      syscall_release();
      shutdown_power_off();
      NOT_REACHED();

    default:
      syscall_release();
      NOT_REACHED();
      break;
  }

  syscall_release();
}

struct dir* get_anchor_dir(char** filepathp) {
  struct dir* dir = NULL;
  struct thread* cur_t = thread_current();
  char* filepath = *filepathp;

  if (filepath[0] == '/') {
    dir = dir_open_root();
  } else {
    dir = cur_t->pcb->current_dir;
  }

  return dir;
}

// handles file's syscalls
// returns true if syscall was handled
bool file_syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  struct process_file* process_file;
  struct thread* cur_t = thread_current();
  char* filepath = NULL;

  switch (args[0]) {
    // FILESYS SYSCALLS
    case SYS_CREATE:
      validate_buffer_in_user_region(&args[1], 2 * sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);

      filepath = (char*)args[1];
      f->eax = filesys_create(get_anchor_dir(&filepath), filepath, args[2]);
      break;
    case SYS_REMOVE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);

      filepath = (char*)args[1];
      f->eax = filesys_remove(get_anchor_dir(&filepath), filepath);
      break;
    case SYS_OPEN:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);

      filepath = (char*)args[1];
      struct inode* inode = filesys_open_inode(get_anchor_dir(&filepath), filepath);

      if (inode == NULL) {
        f->eax = FD_ERROR;
        return 1;
      }

      void* file = NULL;

      if (inode_is_dir(inode)) {
        file = dir_open(inode);
      } else {
        file = file_open(inode);
      }

      if (file == NULL) {
        f->eax = FD_ERROR;
        return 1;
      }

      f->eax = register_process_file(file, inode_is_dir(inode));
      break;
    case SYS_FILESIZE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      process_file = find_process_file(args[1]);

      if (process_file->is_dir) {
        f->eax = -1;
        return 1;
      }

      f->eax = process_file == NULL ? 0 : file_length(process_file->file);
      break;
    case SYS_READ:
      validate_buffer_in_user_region(&args[1], 3 * sizeof(uint32_t));
      validate_string_in_user_region((char*)args[2]);

      if (args[1] == STDIN_FILENO) {
        uint8_t* buffer = (uint8_t*)args[2];
        int c;

        for (uint32_t i = 0; i < args[3]; i++) {
          c = input_getc();
          if (c == '\n') {
            f->eax = i;
            return 1;
          } else {
            buffer[i] = input_getc();
          }
        }

        f->eax = args[3];

        return 1;
      }

      process_file = find_process_file(args[1]);
      if (process_file == NULL || process_file->is_dir) {
        f->eax = -1;
        return 1;
      }

      f->eax = file_read(process_file->file, (void*)args[2], args[3]);

      break;
    case SYS_WRITE:
      validate_buffer_in_user_region(&args[1], 3 * sizeof(uint32_t));
      validate_buffer_in_user_region((void*)args[2], sizeof(uint32_t));

      if (args[1] == STDOUT_FILENO) {
        // if write target is stdout, redirect it to kernel console
        putbuf((char*)args[2], args[3]);
        f->eax = args[3];
        return 1;
      }

      process_file = find_process_file(args[1]);
      if (process_file == NULL || process_file->is_dir) {
        f->eax = -1;
        return 1;
      }

      f->eax = file_write(process_file->file, (void*)args[2], args[3]);

      break;
    case SYS_SEEK:
      validate_buffer_in_user_region(&args[1], 2 * sizeof(uint32_t));

      process_file = find_process_file(args[1]);
      if (process_file == NULL || process_file->is_dir) {
        return 1;
      }

      file_seek(process_file->file, args[2]);

      break;
    case SYS_TELL:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      process_file = find_process_file(args[1]);
      if (process_file == NULL || process_file->is_dir) {
        f->eax = 0;
        return 1;
      }

      f->eax = file_tell(process_file->file);

      break;
    case SYS_CLOSE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        return 1;
      }

      if (process_file->is_dir) {
        dir_close(process_file->file);
      } else {
        file_close(process_file->file);
      }

      remove_process_file(args[1]);

      break;
    case SYS_INUMBER:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        return 1;
      }

      if (process_file->is_dir) {
        // TODO:
        f->eax = (int)inode_get_inumber(dir_get_inode(process_file->file));
      } else {
        f->eax = (int)file_inumber(process_file->file);
      }

      break;
    case SYS_ISDIR:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        f->eax = -1;
        return 1;
      }

      f->eax = process_file->is_dir;

      break;
    case SYS_CHDIR:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);

      filepath = (char*)args[1];
      struct dir* dir = filesys_opendir(get_anchor_dir(&filepath), filepath);
      if (dir == NULL) {
        f->eax = false;
        return 1;
      }

      dir_close(cur_t->pcb->current_dir);
      cur_t->pcb->current_dir = dir;

      f->eax = true;

      break;

    case SYS_MKDIR:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);

      filepath = (char*)args[1];
      f->eax = filesys_mkdir(get_anchor_dir(&filepath), filepath);

      break;
    case SYS_READDIR:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_buffer_in_user_region(&args[2], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[2]);

      process_file = find_process_file(args[1]);
      if (process_file == NULL || !process_file->is_dir) {
        f->eax = false;
        return 1;
      }

      f->eax = filesys_readdir((struct dir*)process_file->file, (char*)args[2]);

      break;
    default:
      return 0;
  }

  return 1;
}
