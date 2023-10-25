#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* System call numbers. */
enum 
  {
    /* Projects 2 and later. */
    SYSTEM_HALT,                   /* Halt the operating system. */
    SYSTEM_EXIT,                   /* Terminate this process. */
    SYSTEM_EXEC,                   /* Start another process. */
    SYSTEM_WAIT,                   /* Wait for a child process to die. */
    SYSTEM_CREATE,                 /* Create a file. */
    SYSTEM_REMOVE,                 /* Delete a file. */
    SYSTEM_OPEN,                   /* Open a file. */
    SYSTEM_FILESIZE,               /* Obtain a file's size. */
    SYSTEM_READ,                   /* Read from a file. */
    SYSTEM_WRITE,                  /* Write to a file. */
    SYSTEM_SEEK,                   /* Change position in a file. */
    SYSTEM_TELL,                   /* Report current position in a file. */
    SYSTEM_CLOSE,                  /* Close a file. */

    /* Project 3 and optionally project 4. */
    SYSTEM_MMAP,                   /* Map a file into memory. */
    SYSTEM_MUNMAP,                 /* Remove a memory mapping. */

    /* Project 4 only. */
    SYSTEM_CHDIR,                  /* Change the current directory. */
    SYSTEM_MKDIR,                  /* Create a directory. */
    SYSTEM_READDIR,                /* Reads a directory entry. */
    SYSTEM_ISDIR,                  /* Tests if a fd represents a directory. */
    SYSTEM_INUMBER                 /* Returns the inode number for a fd. */
  };

#endif /* lib/syscall-nr.h */
