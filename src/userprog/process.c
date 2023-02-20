#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static struct list process_children;
static struct lock process_children_lock;

// used to synch shared logic between process' threads
static struct lock process_threads_lock;

static struct lock process_locks_lock;
static struct lock process_semas_lock;

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void** esp, uint32_t page_number);
struct process_thread* get_main_process_thread(void);
struct process_thread* get_unexited_process_thread(void);
bool is_there_running_process_thread(void);
struct process_thread* find_process_thread(tid_t, struct process*);

struct user_lock {
  uintptr_t user_lock_id;
  struct lock lock;
  struct list_elem user_lock_elem;
};

struct user_sema {
  uintptr_t user_sema_id;
  struct semaphore sema;
  struct list_elem user_sema_elem;
};

/* Lock used by allocate_fd(). */
static struct lock fd_lock;
/* Returns a tid to use for a new thread. */
fd allocate_fd(void) {
  /* not starting from 0 or 1 to reserve them for special purposes
  such as stdin/stdout descriptors */
  static fd next_fd = 5;
  fd fd;

  lock_acquire(&fd_lock);
  fd = next_fd++;
  lock_release(&fd_lock);

  return fd;
}

fd register_process_file(struct file* file) {
  struct process_file* process_file = malloc(sizeof(struct process_file));
  if (process_file == NULL) {
    return FD_ERROR;
  }

  struct thread* t = thread_current();
  fd fd = allocate_fd();

  process_file->fd = fd;
  process_file->file = file;

  list_push_back(&t->pcb->process_files, &process_file->process_file_elem);

  return fd;
}

struct process_thread* get_unexited_process_thread() {
  struct list_elem* e;
  struct thread* cur_t = thread_current();
  struct process_thread* process_thread;

  for (e = list_begin(&cur_t->pcb->process_threads); e != list_end(&cur_t->pcb->process_threads);
       e = list_next(e)) {
    process_thread = list_entry(e, struct process_thread, process_thread_elem);
    if (cur_t->tid != process_thread->tid && !process_thread->thread_exited) {
      return process_thread;
    }
  }

  return NULL;
}

bool is_there_running_process_thread() { return get_unexited_process_thread() != NULL; }

struct process_thread* find_process_thread(tid_t tid, struct process* pcb) {
  struct list_elem* e;
  struct process_thread* process_thread = NULL;

  for (e = list_begin(&pcb->process_threads); e != list_end(&pcb->process_threads);
       e = list_next(e)) {
    process_thread = list_entry(e, struct process_thread, process_thread_elem);
    if (process_thread->tid == tid) {
      return process_thread;
    }
  }

  return NULL;
}

struct process_file* find_process_file(fd fd) {
  struct list_elem* e;
  struct thread* thread = thread_current();

  for (e = list_begin(&thread->pcb->process_files); e != list_end(&thread->pcb->process_files);
       e = list_next(e)) {
    struct process_file* process_file = list_entry(e, struct process_file, process_file_elem);
    if (process_file->fd == fd) {
      return process_file;
    }
  }

  return NULL;
}

bool remove_process_file(fd fd) {
  struct process_file* process_file = find_process_file(fd);
  if (process_file == NULL) {
    return false;
  }

  list_remove(&process_file->process_file_elem);
  return true;
}

static struct semaphore temporary;

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  sema_init(&temporary, 0);

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;
  t->pcb->pid = t->tid;
  t->pcb->parent_dir = NULL;
  t->pcb->current_dir = NULL;

  list_init(&process_children);
  lock_init(&process_children_lock);
  lock_init(&fd_lock);
  lock_init(&process_threads_lock);
  lock_init(&process_locks_lock);
  lock_init(&process_semas_lock);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

struct start_process_args {
  char* command;
  pid_t parent_pid;
  bool exec_success;
  struct dir* parent_dir;

  // semaphore to wait until start_process to finish setting up new process
  // so process_execute can do its housekeeping until process actually starts running
  // this way new process won't exit until process_execute is done
  struct semaphore process_set_wait;
  // semaphore to wait until process_execute to finish housekeeping
  struct semaphore process_exec_wait;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;
  struct thread* cur_t = thread_current();
  struct process_child* process_child;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  struct start_process_args* start_process_args = malloc(sizeof(struct start_process_args));

  if (start_process_args == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  start_process_args->command = fn_copy;
  start_process_args->parent_pid = cur_t->pcb->pid;
  start_process_args->exec_success = 0;
  start_process_args->parent_dir = cur_t->pcb->current_dir;
  sema_init(&start_process_args->process_set_wait, 0);
  sema_init(&start_process_args->process_exec_wait, 0);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, start_process_args);

  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
    free(start_process_args);
    return TID_ERROR;
  }

  sema_down(&start_process_args->process_set_wait);

  if (!start_process_args->exec_success) {
    palloc_free_page(fn_copy);
    free(start_process_args);
    return TID_ERROR;
  }

  process_child = malloc(sizeof(struct process_child));
  if (process_child == NULL) {
    palloc_free_page(fn_copy);
    free(start_process_args);
    return TID_ERROR;
  }

  process_child->child_pid = tid;
  process_child->parent_pid = cur_t->pcb->pid;
  process_child->exit_status = 0;
  process_child->process_child_exited = false;
  process_child->waiter_tid = TID_ERROR;
  sema_init(&process_child->exit_wait, 0);
  list_push_back(&process_children, &process_child->process_child_elem);

  sema_up(&start_process_args->process_exec_wait);

  palloc_free_page(fn_copy);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* args_) {
  struct start_process_args* args = (struct start_process_args*)args_;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;
  struct process_thread* process_thread;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  int argc = 0;
  int max_argc = 30;
  char* argv[max_argc];
  int file_name_length;
  int command_total_length;

  if (success) {
    if (args->parent_dir == NULL) {
      // if it's first process current_dir is root and no parent_dir
      new_pcb->parent_dir = NULL;
      new_pcb->current_dir = dir_open_root();
      success = new_pcb->current_dir != NULL;
    } else {
      new_pcb->parent_dir = dir_reopen(args->parent_dir);
      new_pcb->current_dir = dir_reopen(args->parent_dir);
      success = new_pcb->parent_dir != NULL && new_pcb->current_dir != NULL;
    }
  }

  // break command into controllable array of pointers
  if (success) {
    char* save_ptr;
    char* token = strtok_r(args->command, " ", &save_ptr);

    for (argc = 0; argc < max_argc && token != NULL; argc++) {
      argv[argc] = token;
      token = strtok_r(NULL, " ", &save_ptr);
    }

    success = argc && argv[0] != NULL;

    if (success) {
      file_name_length = strlen(argv[0]) + 1;
      command_total_length = argv[argc - 1] - argv[0] + file_name_length;
    }
  }

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, argv[0], file_name_length);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(argv[0], &if_.eip, &if_.esp);
  }

  if (success) {
    process_thread = malloc(sizeof(struct process_thread));
    success = process_thread != NULL;
  }

  if (success) {
    new_pcb->process_exited = false;
    new_pcb->pid = t->tid;
    new_pcb->parent_pid = args->parent_pid;
    new_pcb->process_threads_count = 0;
    new_pcb->process_stack_pages_count = 0;
    list_init(&new_pcb->process_files);
    list_init(&new_pcb->process_threads);
    list_init(&new_pcb->process_locks);
    list_init(&new_pcb->process_semas);
    list_init(&new_pcb->process_free_stack_pages);

    process_thread->tid = t->tid;
    process_thread->thread_exited = false;
    process_thread->thread_waiter = NULL;
    t->process_thread_id = 0;
    sema_init(&process_thread->exit_wait, 0);
    list_push_back(&new_pcb->process_threads, &process_thread->process_thread_elem);
  }

  /* 
    put argc, argv and other values according to 80x86 convention onto the stack
  */
  if (success) {
    if_.esp -= (command_total_length + (16 - command_total_length % 16)) +
               (16 - (sizeof(char*) * (argc - 1) % 16));  // align stack to 16-byte
    memcpy(if_.esp, args->command, command_total_length); // copy arguments onto the stack

    void* esp = if_.esp; // if_.esp now is the base where the arguments start

    esp = (char**)esp - 1;
    *(char**)esp = NULL; // argv[argc] = NULL

    // push pointers to the arguments onto the stack
    for (int i = argc - 1; i >= 0; i--) {
      esp = (char**)esp - 1;
      *(char**)esp = (char*)if_.esp + (argv[i] - argv[0]);
    }

    esp = (char**)esp - 1;
    *(char***)esp = (char**)esp + 1; // push pointer to argv

    esp = (int*)esp - 1;
    *(int*)esp = argc; // push argc

    esp = (char**)esp - 1;
    *(char**)esp = NULL; // push fake return address

    if_.esp = esp;
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    dir_close(new_pcb->parent_dir);
    dir_close(new_pcb->current_dir);

    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  args->exec_success = success;
  sema_up(&args->process_set_wait);
  sema_down(&args->process_exec_wait);

  free(args);

  if (!success) {
    free(process_thread);
    thread_exit();
  }

  asm("fsave (%0);" : : "g"(&if_.fp_registers)); // fill in the frame with current FP registers

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

struct process_child* find_child(pid_t parent_pid, pid_t child_pid) {
  struct list_elem* e;

  for (e = list_begin(&process_children); e != list_end(&process_children); e = list_next(e)) {
    struct process_child* process_child = list_entry(e, struct process_child, process_child_elem);
    if (process_child->parent_pid == parent_pid && process_child->child_pid == child_pid) {
      return process_child;
    }
  }

  return NULL;
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct thread* cur_t = thread_current();

  lock_acquire(&process_children_lock);

  struct process_child* process_child = find_child(cur_t->pcb->pid, child_pid);
  if (!process_child) {
    lock_release(&process_children_lock);
    return TID_ERROR;
  }

  if (process_child->waiter_tid != TID_ERROR) {
    lock_release(&process_children_lock);
    return TID_ERROR;
  }

  process_child->waiter_tid = cur_t->tid;

  if (process_child->process_child_exited) {
    lock_release(&process_children_lock);
    return process_child->exit_status;
  }

  lock_release(&process_children_lock);

  sema_down(&process_child->exit_wait);

  ASSERT(process_child->process_child_exited);

  return process_child->exit_status;
}

struct process_thread* get_main_process_thread() {
  struct thread* cur_t = thread_current();
  struct list_elem* e = list_begin(&cur_t->pcb->process_threads);
  struct process_thread* process_thread = list_entry(e, struct process_thread, process_thread_elem);

  return process_thread;
}

void process_intr_exit() {
  struct thread* cur_t = thread_current();

  if (cur_t->pcb && cur_t->pcb->process_exited) {
    intr_enable();
    process_exit(cur_t->pcb->exit_status);
  }
}

void soft_process_exit(int status) {
  struct thread* cur_t = thread_current();
  cur_t->pcb->exit_status = status;
  pthread_exit();
}

/* Free the current process's resources. */
void process_exit(int status) {
  struct thread* cur_t = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur_t->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  lock_acquire(&process_threads_lock);
  cur_t->pcb->exit_status = status;
  cur_t->pcb->process_exited = true;

  // exit process only if it is the last process thread
  if (is_there_running_process_thread()) {
    lock_release(&process_threads_lock);
    pthread_exit();
  }
  lock_release(&process_threads_lock);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur_t->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur_t->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  // child process POV
  // acquire the lock so the parent process won't intervene with exiting before we done
  {
    lock_acquire(&process_children_lock);
    // main thread might already been exited, so use get_main_process_thread
    struct process_child* process_child =
        find_child(cur_t->pcb->parent_pid,
                   is_main_thread(cur_t, cur_t->pcb) ? cur_t->tid : get_main_process_thread()->tid);
    if (process_child) {
      process_child->exit_status = cur_t->pcb->exit_status;
      process_child->process_child_exited = true;
      sema_up(&process_child->exit_wait);
    }
    lock_release(&process_children_lock);
  }

  // parent process POV
  // if parent exits then need to clear all process_child, since they are no longer needed
  {
    lock_acquire(&process_children_lock);
    struct list_elem *elem, *next;

    for (elem = list_begin(&process_children); elem != list_end(&process_children); elem = next) {
      next = list_next(elem);
      struct process_child* process_child =
          list_entry(elem, struct process_child, process_child_elem);
      if (process_child->parent_pid == cur_t->pcb->pid) {
        list_remove(elem);
        free(process_child);
      }
    }

    lock_release(&process_children_lock);
  }

  file_close(cur_t->pcb->exec_file);

  dir_close(cur_t->pcb->parent_dir);
  dir_close(cur_t->pcb->current_dir);

  // free process file descriptors
  {
    struct list_elem *elem, *next;
    for (elem = list_begin(&cur_t->pcb->process_files);
         elem != list_end(&cur_t->pcb->process_files); elem = next) {
      next = list_next(elem);
      struct process_file* process_file = list_entry(elem, struct process_file, process_file_elem);

      list_remove(&process_file->process_file_elem);
      file_close(process_file->file);
      free(process_file);
    }
  }

  // free process_threads list structures
  {
    struct list_elem *elem, *next;
    for (elem = list_begin(&cur_t->pcb->process_threads);
         elem != list_end(&cur_t->pcb->process_threads); elem = next) {
      next = list_next(elem);
      struct process_thread* process_thread =
          list_entry(elem, struct process_thread, process_thread_elem);

      list_remove(&process_thread->process_thread_elem);
      free(process_thread);
    }
  }

  // free process_free_stack_pages list structures
  {
    struct list_elem *elem, *next;
    for (elem = list_begin(&cur_t->pcb->process_free_stack_pages);
         elem != list_end(&cur_t->pcb->process_free_stack_pages); elem = next) {
      next = list_next(elem);
      struct process_free_stack_page* process_free_stack_page =
          list_entry(elem, struct process_free_stack_page, process_free_stack_page_elem);

      list_remove(&process_free_stack_page->process_free_stack_page_elem);
      free(process_free_stack_page);
    }
  }

  // free process_locks list structures
  {
    struct list_elem *elem, *next;
    for (elem = list_begin(&cur_t->pcb->process_locks);
         elem != list_end(&cur_t->pcb->process_locks); elem = next) {
      next = list_next(elem);
      struct user_lock* user_lock = list_entry(elem, struct user_lock, user_lock_elem);

      list_remove(&user_lock->user_lock_elem);
      free(user_lock);
    }
  }

  // free process_semas list structures
  {
    struct list_elem *elem, *next;
    for (elem = list_begin(&cur_t->pcb->process_semas);
         elem != list_end(&cur_t->pcb->process_semas); elem = next) {
      next = list_next(elem);
      struct user_sema* user_sema = list_entry(elem, struct user_sema, user_sema_elem);

      list_remove(&user_sema->user_sema_elem);
      free(user_sema);
    }
  }

  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur_t->pcb;
  cur_t->pcb = NULL;
  free(pcb_to_free);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */

  if (!success) {
    file_close(file);
  } else {
    t->pcb->exec_file = file;
  }

  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

static bool uninstall_stack_page(uint32_t page_number) {
  struct thread* t = thread_current();

  void* upage = (uint8_t*)PHYS_BASE - (PGSIZE * 2 * page_number) - PGSIZE;
  uint8_t* kpage = pagedir_get_page(t->pcb->pagedir, upage);

  if (kpage == NULL) {
    return false;
  }

  palloc_free_page(kpage);
  pagedir_clear_page(t->pcb->pagedir, upage);

  return true;
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void** esp, uint32_t page_number) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    // leave every second page empty for now
    // so if a thread's stack is overflowed it will access an empty page with page fault
    uint8_t* base = (uint8_t*)PHYS_BASE - (PGSIZE * 2 * page_number);

    // use base - PGSIZE because installation of a page goes in reverse way
    // as opposed to stack growth
    success = install_page(base - PGSIZE, kpage, true);

    if (success)
      *esp = base;
    else
      palloc_free_page(kpage);
  }

  return success;
}

struct start_pthread_args {
  stub_fun sf;
  pthread_fun tf;
  void* arg;
  struct process* pcb;

  bool setup_failed;
  struct semaphore process_thread_setup_wait;
};

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  struct thread* cur_t = thread_current();
  tid_t tid;

  struct start_pthread_args* start_pthread_args = malloc(sizeof(struct start_pthread_args));
  if (start_pthread_args == NULL) {
    return TID_ERROR;
  }

  start_pthread_args->sf = sf;
  start_pthread_args->tf = tf;
  start_pthread_args->arg = arg;
  start_pthread_args->pcb = cur_t->pcb;
  sema_init(&start_pthread_args->process_thread_setup_wait, 0);

  tid = thread_create(cur_t->name, PRI_DEFAULT, start_pthread, start_pthread_args);
  if (tid == TID_ERROR) {
    free(start_pthread_args);
    return TID_ERROR;
  }

  // wait until start_pthread is done setting up the thread
  sema_down(&start_pthread_args->process_thread_setup_wait);

  if (start_pthread_args->setup_failed) {
    free(start_pthread_args);
    return TID_ERROR;
  }

  free(start_pthread_args);

  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* args_) {
  struct start_pthread_args* args = (struct start_pthread_args*)args_;
  struct intr_frame if_;
  bool success = false;
  struct thread* t = thread_current();

  struct process_thread* process_thread = malloc(sizeof(struct process_thread));
  if (process_thread == NULL) {
    args->setup_failed = true;
    sema_up(&args->process_thread_setup_wait);
    thread_exit();
  }

  t->pcb = args->pcb;
  process_activate();

  process_thread->tid = t->tid;
  process_thread->thread_exited = false;
  process_thread->thread_waiter = NULL;
  sema_init(&process_thread->exit_wait, 0);

  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  if_.eip = (void*)args->sf;

  lock_acquire(&process_threads_lock);

  if (!list_empty(&t->pcb->process_free_stack_pages)) {
    struct process_free_stack_page* process_free_stack_page =
        list_entry(list_pop_front(&t->pcb->process_free_stack_pages),
                   struct process_free_stack_page, process_free_stack_page_elem);
    t->stack_page_number = process_free_stack_page->page_number;
    free(process_free_stack_page);
  } else {
    t->stack_page_number = ++t->pcb->process_stack_pages_count;
  }

  t->process_thread_id = ++t->pcb->process_threads_count;
  list_push_back(&args->pcb->process_threads, &process_thread->process_thread_elem);

  lock_release(&process_threads_lock);

  success = setup_thread(&if_.esp, t->stack_page_number);

  if (!success) {
    free(process_thread);
    args->setup_failed = true;
    sema_up(&args->process_thread_setup_wait);
    thread_exit();
  }

  if_.esp = (void**)if_.esp - 1;
  *(void**)if_.esp = NULL; // stack align

  if_.esp = (void**)if_.esp - 1;
  *(void**)if_.esp = args->arg; // push arg

  if_.esp = (void**)if_.esp - 1;
  *(void**)if_.esp = args->tf; // push tf

  if_.esp = (void**)if_.esp - 1;
  *(void**)if_.esp = NULL; // push fake return address

  args->setup_failed = false;
  sema_up(&args->process_thread_setup_wait);

  asm("fsave (%0);" : : "g"(&if_.fp_registers)); // fill in the frame with current FP registers

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
  struct thread* cur_t = thread_current();

  if (tid == cur_t->tid) {
    return TID_ERROR;
  }

  lock_acquire(&process_threads_lock);

  struct process_thread* process_thread = find_process_thread(tid, cur_t->pcb);

  if (process_thread == NULL || process_thread->thread_waiter != NULL) {
    lock_release(&process_threads_lock);
    return TID_ERROR;
  }

  process_thread->thread_waiter = cur_t;

  if (process_thread->thread_exited) {
    lock_release(&process_threads_lock);
    return tid;
  }

  lock_release(&process_threads_lock);

  sema_down(&process_thread->exit_wait);

  lock_acquire(&process_threads_lock);
  // do not remove main thread's structure
  if (tid != cur_t->pcb->pid) {
    struct list_elem* e;
    process_thread = NULL;
    for (e = list_begin(&cur_t->pcb->process_threads); e != list_end(&cur_t->pcb->process_threads);
         e = list_next(e)) {
      process_thread = list_entry(e, struct process_thread, process_thread_elem);
      if (process_thread->tid == tid) {
        list_remove(e);
        free(process_thread);
        break;
      }
    }
  }
  lock_release(&process_threads_lock);

  return tid;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* cur_t = thread_current();

  lock_acquire(&process_threads_lock);

  // exit process if it is the last process thread
  if (!is_there_running_process_thread()) {
    lock_release(&process_threads_lock);
    process_exit(cur_t->pcb->exit_status);
  }

  if (is_main_thread(cur_t, cur_t->pcb)) {
    lock_release(&process_threads_lock);
    pthread_exit_main();
    return;
  }

  struct process_thread* process_thread = find_process_thread(cur_t->tid, cur_t->pcb);
  ASSERT(process_thread != NULL);

  process_thread->thread_exited = true;

  struct process_free_stack_page* process_free_stack_page =
      malloc(sizeof(struct process_free_stack_page));
  if (process_free_stack_page == NULL) {
    lock_release(&process_threads_lock);
    process_exit(cur_t->pcb->exit_status);
  }

  ASSERT(uninstall_stack_page(cur_t->stack_page_number));

  process_free_stack_page->page_number = cur_t->stack_page_number;
  list_push_back(&cur_t->pcb->process_free_stack_pages,
                 &process_free_stack_page->process_free_stack_page_elem);

  lock_release(&process_threads_lock);
  sema_up(&process_thread->exit_wait);

  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* cur_t = thread_current();

  lock_acquire(&process_threads_lock);
  struct process_thread* main_process_thread = get_main_process_thread();
  main_process_thread->thread_exited = true;
  cur_t->pcb->main_thread = NULL;
  lock_release(&process_threads_lock);
  sema_up(&main_process_thread->exit_wait);
  thread_exit();
}

bool process_init_lock(uintptr_t user_lock_id) {
  if (user_lock_id == (int)NULL) {
    return false;
  }

  struct thread* cur_t = thread_current();
  struct user_lock* user_lock = malloc(sizeof(struct user_lock));

  if (user_lock == NULL) {
    return false;
  }

  user_lock->user_lock_id = user_lock_id;
  lock_init(&user_lock->lock);

  lock_acquire(&process_locks_lock);
  list_push_back(&cur_t->pcb->process_locks, &user_lock->user_lock_elem);
  lock_release(&process_locks_lock);

  return true;
}

bool process_acquire_lock(uintptr_t user_lock_id) {
  if (user_lock_id == (int)NULL) {
    return false;
  }

  struct list_elem* e;
  struct thread* cur_t = thread_current();

  struct user_lock* user_lock = NULL;

  lock_acquire(&process_locks_lock);

  for (e = list_begin(&cur_t->pcb->process_locks); e != list_end(&cur_t->pcb->process_locks);
       e = list_next(e)) {
    struct user_lock* cur_user_lock = list_entry(e, struct user_lock, user_lock_elem);
    if (cur_user_lock->user_lock_id == user_lock_id) {
      user_lock = cur_user_lock;
      break;
    }
  }

  if (user_lock == NULL || user_lock->lock.holder == cur_t)
    return false;

  lock_release(&process_locks_lock);

  lock_acquire(&user_lock->lock);

  return true;
}

bool process_release_lock(uintptr_t user_lock_id) {
  if (user_lock_id == (int)NULL) {
    return false;
  }

  struct list_elem* e;
  struct thread* cur_t = thread_current();

  struct user_lock* user_lock = NULL;

  lock_acquire(&process_locks_lock);

  for (e = list_begin(&cur_t->pcb->process_locks); e != list_end(&cur_t->pcb->process_locks);
       e = list_next(e)) {
    struct user_lock* cur_user_lock = list_entry(e, struct user_lock, user_lock_elem);
    if (cur_user_lock->user_lock_id == user_lock_id) {
      user_lock = cur_user_lock;
      break;
    }
  }

  if (user_lock == NULL || user_lock->lock.holder != cur_t)
    return false;

  lock_release(&process_locks_lock);

  lock_release(&user_lock->lock);

  return true;
}

bool process_sema_init(uintptr_t user_sema_id, int value) {
  if (user_sema_id == (int)NULL || value < 0) {
    return false;
  }

  struct thread* cur_t = thread_current();
  struct user_sema* user_sema = malloc(sizeof(struct user_sema));

  if (user_sema == NULL) {
    return false;
  }

  user_sema->user_sema_id = user_sema_id;
  sema_init(&user_sema->sema, value);

  lock_acquire(&process_semas_lock);
  list_push_back(&cur_t->pcb->process_semas, &user_sema->user_sema_elem);
  lock_release(&process_semas_lock);

  return true;
}

bool process_sema_down(uintptr_t user_sema_id) {
  if (user_sema_id == (int)NULL) {
    return false;
  }

  struct list_elem* e;
  struct thread* cur_t = thread_current();

  struct user_sema* user_sema = NULL;

  lock_acquire(&process_semas_lock);

  for (e = list_begin(&cur_t->pcb->process_semas); e != list_end(&cur_t->pcb->process_semas);
       e = list_next(e)) {
    struct user_sema* cur_user_sema = list_entry(e, struct user_sema, user_sema_elem);
    if (cur_user_sema->user_sema_id == user_sema_id) {
      user_sema = cur_user_sema;
      break;
    }
  }

  if (user_sema == NULL)
    return false;

  lock_release(&process_semas_lock);

  sema_down(&user_sema->sema);

  return true;
}

bool process_sema_up(uintptr_t user_sema_id) {
  if (user_sema_id == (int)NULL) {
    return false;
  }

  struct list_elem* e;
  struct thread* cur_t = thread_current();

  struct user_sema* user_sema = NULL;

  lock_acquire(&process_semas_lock);

  for (e = list_begin(&cur_t->pcb->process_semas); e != list_end(&cur_t->pcb->process_semas);
       e = list_next(e)) {
    struct user_sema* cur_user_sema = list_entry(e, struct user_sema, user_sema_elem);
    if (cur_user_sema->user_sema_id == user_sema_id) {
      user_sema = cur_user_sema;
      break;
    }
  }

  if (user_sema == NULL)
    return false;

  lock_release(&process_semas_lock);

  sema_up(&user_sema->sema);

  return true;
}

bool process_chdir(const char* file);
bool process_chdir(const char* file) {
  struct dir* anchor_dir = NULL;
  struct thread* cur_t = thread_current();

  if (file[0] == '/') {
    anchor_dir = dir_open_root();
  } else if (file[0] == '.' && file[1] == '.') {
    anchor_dir = cur_t->pcb->parent_dir;
  } else if (file[0] == '.') {
    anchor_dir = cur_t->pcb->current_dir;
  } else {
    return false;
  }

  if (anchor_dir == NULL)
    return false;

  struct dir* dir = filesys_open_dir(anchor_dir, file);

  if (dir == NULL)
    return false;

  dir_close(cur_t->pcb->current_dir);
  cur_t->pcb->current_dir = dir;

  return true;
}
