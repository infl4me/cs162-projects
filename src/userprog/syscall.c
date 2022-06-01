#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "pagedir.h"

static void syscall_handler(struct intr_frame*);
bool are_args_valid(uint32_t* args, int num_args);
bool is_sp_valid(uint32_t* sp);
void exit_process(int status);
void check_args(uint32_t* args, int num_args);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

void exit_process(int status) {
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}

bool are_args_valid(uint32_t* args, int num_args) {
  return is_user_vaddr(&args[num_args]) &&
         pagedir_get_page(thread_current()->pcb->pagedir, &args[num_args]) != NULL;
}

void check_args(uint32_t* args, int num_args) {
  if (!are_args_valid(args, num_args)) {
    exit_process(-1);
  }
}

bool is_sp_valid(uint32_t* sp) {
  return is_user_vaddr(sp) && pagedir_get_page(thread_current()->pcb->pagedir, sp) != NULL &&
         ((PGSIZE - pg_ofs(sp)) >= sizeof(uint32_t*));
}

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  if (!is_sp_valid(args)) {
    exit_process(-1);
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // printf("System call number: %d\n", args[0]);

  switch (args[0]) {
    case SYS_PRACTICE:
      check_args(args, 1);

      f->eax = args[1] + 1;
      break;
    case SYS_EXIT:
      check_args(args, 1);

      f->eax = args[1];
      exit_process(args[1]);
      break;
    case SYS_WRITE:
      check_args(args, 3);

      if (args[1] == STDOUT_FILENO) {
        // if write target is stdout, redirect it to kernel console
        putbuf((char*)args[2], args[3]);
        f->eax = args[3];
      } else {
        NOT_REACHED();
      }
      break;

    default:
      NOT_REACHED();
      break;
  }
}
