#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "filesys/file.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* file descriptor */
typedef int fd;
#define FD_ERROR ((fd)-1) /* Error value for fd. */

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  pid_t parent_pid;
  struct list process_files;
  struct file* exec_file; // pointer to process executable file
};

struct process_child {
  struct list_elem process_child_elem;
  pid_t parent_pid;
  pid_t child_pid;
  int exit_status;            // exit status of child
  struct semaphore exit_wait; // semaphore of waiting exit of child
};

struct process_file {
  struct list_elem process_file_elem;
  fd fd;
  struct file* file;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int status);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);
struct process_child* find_child(pid_t parent_pid, pid_t child_pid);
fd register_process_file(struct file* file);
fd allocate_fd(void);
struct process_file* find_process_file(fd fd);
bool remove_process_file(fd fd);

#endif /* userprog/process.h */
