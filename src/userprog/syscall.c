#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/synch.h"
#include <float.h>

static void syscall_handler(struct intr_frame*);
bool is_pointer_valid(uint32_t* sp);
void exit_process(int status);
void soft_exit_process(int status);
void check_args(uint32_t* args, int num_args);
bool is_addr_valid(uint32_t* addr);
bool is_char_pointer_valid(uint32_t* p);
void check_args_filesys(uint32_t* args, int num_args);
void syscall_release(void);
void syscall_acquire(void);
bool file_syscall_handler(struct intr_frame*);

static struct lock syscall_lock;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&syscall_lock);
}

void exit_process(int status) {
  syscall_release();
  process_exit(status);
}

void soft_exit_process(int status) { soft_process_exit(status); }

bool is_addr_valid(uint32_t* addr) {
  // check that addr in userspace and mapped to page (prbly there is better way to check that addr is mapped)
  return is_user_vaddr(addr) && pagedir_get_page(thread_current()->pcb->pagedir, addr) != NULL;
}

void check_args(uint32_t* args, int num_args) {
  // cant use is_pointer_valid here, since simple args can hang over into another page as opposed to pointer arg
  if (!is_addr_valid(&args[num_args])) {
    exit_process(-1);
  }
}

void check_args_filesys(uint32_t* args, int num_args) {
  // cant use is_pointer_valid here, since simple args can hang over into another page as opposed to pointer arg
  if (!is_addr_valid(&args[num_args])) {
    exit_process(-1);
  }
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

bool is_pointer_valid(uint32_t* p) {
  // check that p aligned and doesnt spans to another page, probably there is better way to do that
  return is_addr_valid(p) && ((PGSIZE - pg_ofs(p)) >= sizeof(uint32_t*));
}

bool is_char_pointer_valid(uint32_t* p) {
  if (!is_pointer_valid((uint32_t*)*p)) {
    return false;
  }

  int max_length = PGSIZE - pg_ofs((char*)(*p));
  int i;

  for (i = 0; i < max_length; i++) {
    if (p[i] == '\0') {
      return true;
    }
  }

  // at the moment we are at the boundary of two pages
  // so, here, we recursively passing the start of second page to check
  return is_char_pointer_valid(&p[i]);
}

// handles file's syscalls
// returns true if syscall was handled
bool file_syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);
  struct file* file;
  struct process_file* process_file;

  switch (args[0]) {
    // FILESYS SYSCALLS
    case SYS_CREATE:
      check_args_filesys(args, 2);

      if (!is_char_pointer_valid(&args[1])) {
        exit_process(-1);
      }

      f->eax = filesys_create((char*)args[1], args[2]);

      break;
    case SYS_REMOVE:
      check_args_filesys(args, 1);

      if (!is_char_pointer_valid(&args[1])) {
        exit_process(-1);
      }

      f->eax = filesys_remove((char*)args[1]);

      break;
    case SYS_OPEN:
      check_args_filesys(args, 1);

      if (!is_char_pointer_valid(&args[1])) {
        exit_process(-1);
      }

      file = filesys_open((char*)args[1]);
      if (file == NULL) {
        f->eax = FD_ERROR;
        return 1;
      }

      f->eax = register_process_file(file);

      break;
    case SYS_FILESIZE:
      check_args_filesys(args, 1);

      process_file = find_process_file(args[1]);

      f->eax = process_file == NULL ? 0 : file_length(process_file->file);

      break;
    case SYS_READ:
      check_args_filesys(args, 3);

      if (!is_pointer_valid((uint32_t*)args[2])) {
        exit_process(-1);
      }

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
      if (process_file == NULL) {
        f->eax = -1;
        return 1;
      }

      f->eax = file_read(process_file->file, (void*)args[2], args[3]);

      break;
    case SYS_WRITE:
      check_args_filesys(args, 3);

      if (!is_pointer_valid((uint32_t*)args[2])) {
        // exit_process(-1);
      }

      if (args[1] == STDOUT_FILENO) {
        // if write target is stdout, redirect it to kernel console
        putbuf((char*)args[2], args[3]);
        f->eax = args[3];
        return 1;
      }

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        f->eax = 0;
        return 1;
      }

      f->eax = file_write(process_file->file, (void*)args[2], args[3]);

      break;
    case SYS_SEEK:
      check_args_filesys(args, 2);

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        return 1;
      }

      file_seek(process_file->file, args[2]);

      break;
    case SYS_TELL:
      check_args_filesys(args, 1);

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        f->eax = 0;
        return 1;
      }

      f->eax = file_tell(process_file->file);

      break;
    case SYS_CLOSE:
      check_args_filesys(args, 1);

      process_file = find_process_file(args[1]);
      if (process_file == NULL) {
        return 1;
      }

      file_close(process_file->file);
      remove_process_file(args[1]);

      break;
    default:
      return 0;
  }

  return 1;
}

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  syscall_acquire();

  if (!is_pointer_valid(args)) {
    exit_process(-1);
  }

  if (file_syscall_handler(f)) {
    syscall_release();
    return;
  }

  switch (args[0]) {
    // processes
    case SYS_EXIT:
      check_args(args, 1);

      exit_process(args[1]);
      NOT_REACHED();

      break;
    case SYS_SOFT_EXIT:
      check_args(args, 1);

      exit_process(args[1]);
      NOT_REACHED();

      break;
    case SYS_EXEC:
      check_args(args, 1);

      if (!is_pointer_valid(&args[1])) {
        exit_process(-1);
      }

      if (!is_char_pointer_valid(&args[1])) {
        exit_process(-1);
      }

      f->eax = process_execute((char*)args[1]);
      break;
    case SYS_WAIT:
      check_args(args, 1);

      syscall_release();
      f->eax = process_wait(args[1]);
      syscall_acquire();
      break;

    // synch
    case SYS_LOCK_INIT:
      check_args(args, 1);

      f->eax = process_init_lock(args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      check_args(args, 1);

      syscall_release();
      f->eax = process_acquire_lock(args[1]);
      syscall_acquire();
      break;
    case SYS_LOCK_RELEASE:
      check_args(args, 1);

      syscall_release();
      f->eax = process_release_lock(args[1]);
      syscall_acquire();
      break;
    case SYS_SEMA_INIT:
      check_args(args, 2);

      f->eax = process_sema_init(args[1], args[2]);
      break;
    case SYS_SEMA_UP:
      check_args(args, 1);

      syscall_release();
      f->eax = process_sema_up(args[1]);
      syscall_acquire();
      break;
    case SYS_SEMA_DOWN:
      check_args(args, 1);

      syscall_release();
      f->eax = process_sema_down(args[1]);
      syscall_acquire();
      break;

    // threads
    case SYS_PT_CREATE:
      check_args(args, 3);

      if (!is_pointer_valid(&args[1]) || !is_pointer_valid(&args[2]) ||
          !is_pointer_valid(&args[3])) {
        exit_process(-1);
      }

      f->eax = pthread_execute((stub_fun)args[1], (pthread_fun)args[2], (void*)args[3]);
      break;
    case SYS_PT_JOIN:
      check_args(args, 1);

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
      check_args(args, 1);

      f->eax = args[1] + 1;
      break;
    case SYS_COMPUTE_E:
      check_args(args, 1);

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
