CS 162 Projects Repository
=======================

Current repository contains my solutions for projects of Berkley's "COMPUTER SCIENCE 162 — OPERATING SYSTEMS AND SYSTEM PROGRAMMING" [course](https://hkn.eecs.berkeley.edu/courseguides/CS/162). Assigments: [link](https://inst.eecs.berkeley.edu/~cs162/sp22/)

## Course Overview
The purpose of this course is to teach the design of operating systems and operating systems concepts that appear in other advanced systems. Topics covered include operating systems, systems programming, networked and distributed systems, and storage systems, including multiple-program systems (processes, interprocess communication, synchronization), memory allocation (segmentation, paging), resource allocation and scheduling, file systems, basic networking (sockets, layering, APIs, reliability), transactions, security and privacy.

## Projects Overview
Our projects in CS 162 will use [Pintos](https://en.wikipedia.org/wiki/Pintos), an educational operating system. They’re designed to give you practical experience with the central ideas of operating systems in the context of developing a real, working kernel, without being excessively complex. The skeleton code for Pintos has several limitations in its file system, thread scheduler, and support for user programs. In the course of these projects, you will greatly improve Pintos in each of these areas.

[Project 1: User Programs](https://inst.eecs.berkeley.edu/~cs162/sp22/static/proj/proj-userprog.pdf)
- **Argument passing.** The `process_execute` function is used to create new user processes in Pintos. Currently, it does not support command-line arguments. You must implement argument passing such that the main function of the user process will receive the appropriate `argc` and `argv`.
- **Process Control Syscalls.** Pintos currently only supports one syscall, `exit`, which terminates the calling process. You will add support for the following new syscalls: `practice`, `halt`, `exec`, `wait`.
- **File Operation Syscalls.** In addition to the process control syscalls, you will also need to implement the following file operation syscalls: `create`, `remove`, `open`, `filesize`, `read`, `write`, `seek`, `tell`, and `close`.
- **Floating Point Operations.** Pintos currently does not support floating point operations. You must implement such functionality so that both user programs and the kernel can use floating point instructions.

[Project 2: Threads](https://inst.eecs.berkeley.edu/~cs162/sp22/static/proj/proj-threads.pdf)
- **Efficient Alarm Clock.** The current implementation of timer sleep is inefficient, because it calls `thread_yield` in a loop until enough time has passed. This consumes CPU cycles while the thread is waiting. Your task is to reimplement timer sleep so that it executes efficiently without any busy waiting.
- **Strict Priority Scheduler.** In Pintos, each thread has a priority value. However, the current scheduler does not respect these priority values. You must modify the scheduler so that higher-priority
threads always run before lower-priority threads. Additionally, you must implement priority donation for Pintos locks.
- **User Threads.** For this task, you will need to implement a simplified version of the `pthread` library. User programs would be allowed to create their own threads using the functions `pthread_create` and
`pthread_exit`. Threads can also wait on other threads with the `pthread_join` function, which is similar to the `wait` syscall for processes. In addition, you must also implement user-level synchronization. After all, threads are not all that useful if we can’t synchronize them properly with locks and semaphores. You will be required to implement `lock_init`, `lock_acquire`, `lock_release`, `sema_init`, `sema_down`, and `sema_up` for user programs.

[Project 3: File System](https://inst.eecs.berkeley.edu/~cs162/sp22/static/proj/proj-filesys.pdf)
- **Buffer Cache.** The functions inode_read_at and inode_write_at currently access the file system’s underlying block device directly each time you call them. Your task is to add a buffer cache for the file system, to improve the performance of reads and writes.
- **Extensible Files.** Pintos currently cannot extend the size of files because the Pintos file system allocates each file as a single contiguous set of blocks. Your task is to modify the Pintos file system to support extending files. One possibility is to use an indexed inode structure with direct, indirect, and doubly-indirect pointers, similar to Unix FFS.
- **Subdirectories.** The current Pintos file system supports directories, but user programs have no way of using them (i.e. files can only be placed in the root directory right now). You must add the following system calls to allow user programs to manipulate directories: `chdir`, `mkdir`, `readdir`, `isdir`. You must also update the following system calls so that they work with directories: `open`, `close`, `exec`, `remove`, `inumber`. You must also add support for relative paths for any syscall with a file path argument. 

[Project 4: Virtual Memory](https://inst.eecs.berkeley.edu/~cs162/sp22/static/hw/memory.pdf)
- **Stack Growth.** In Project User Programs, the stack was a single page at the top of the user virtual address space, and programs were limited to that much stack. Now, if the stack grows past its current size, allocate additional pages as necessary. Allocate additional pages only if they “appear” to be stack accesses. Devise a heuristic that attempts to distinguish stack accesses from other accesses.
- **Dynamic Memory Allocation.** For this portion of the project, you’ll need to extend Pintos with the `sbrk` system call, so that your dynamic memory allocator can request memory from the operating system.

Project 4 implemented in [another repository](https://github.com/infl4me/cs162-homework/tree/master/hw-memory/src)
