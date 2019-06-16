{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

-- | Note about __safety of ptrace() in multi-threaded tracers__:
--
-- You must not call @ptrace(pid, ...)@ from an OS thread that's not the
-- tracer of @pid@. Otherwise you'll get an @ESRCH@ error (@No such process@).
--
-- So you must use `runInBoundThread` or @forkOS` around functions from this
-- module, unless their docs indicate that they already do this for you.
module System.Hatrace
  ( traceForkProcess
  , traceForkExecvFullPath
  , sourceTraceForkExecvFullPathWithSink
  , procToArgv
  , forkExecvWithPtrace
  , printSyscallOrSignalNameConduit
  , SyscallEnterDetails_open(..)
  , SyscallExitDetails_open(..)
  , SyscallEnterDetails_openat(..)
  , SyscallExitDetails_openat(..)
  , SyscallEnterDetails_creat(..)
  , SyscallExitDetails_creat(..)
  , SyscallEnterDetails_pipe(..)
  , SyscallExitDetails_pipe(..)
  , SyscallEnterDetails_pipe2(..)
  , SyscallExitDetails_pipe2(..)
  , SyscallEnterDetails_access(..)
  , SyscallExitDetails_access(..)
  , SyscallEnterDetails_faccessat(..)
  , SyscallExitDetails_faccessat(..)
  , SyscallEnterDetails_write(..)
  , SyscallExitDetails_write(..)
  , SyscallEnterDetails_read(..)
  , SyscallExitDetails_read(..)
  , SyscallEnterDetails_close(..)
  , SyscallExitDetails_close(..)
  , SyscallEnterDetails_rename(..)
  , SyscallExitDetails_rename(..)
  , SyscallEnterDetails_renameat(..)
  , SyscallExitDetails_renameat(..)
  , SyscallEnterDetails_renameat2(..)
  , SyscallExitDetails_renameat2(..)
  , SyscallEnterDetails_stat(..)
  , SyscallExitDetails_stat(..)
  , SyscallEnterDetails_fstat(..)
  , SyscallExitDetails_fstat(..)
  , SyscallEnterDetails_lstat(..)
  , SyscallExitDetails_lstat(..)
  , SyscallEnterDetails_newfstatat(..)
  , SyscallExitDetails_newfstatat(..)
  , SyscallEnterDetails_execve(..)
  , SyscallExitDetails_execve(..)
  , SyscallEnterDetails_exit(..)
  , SyscallExitDetails_exit(..)
  , SyscallEnterDetails_exit_group(..)
  , SyscallExitDetails_exit_group(..)
  , SyscallEnterDetails_ioperm(..)
  , SyscallExitDetails_ioperm(..)
  , SyscallEnterDetails_iopl(..)
  , SyscallExitDetails_iopl(..)
  , SyscallEnterDetails_modify_ldt(..)
  , SyscallExitDetails_modify_ldt(..)
  , SyscallEnterDetails_arch_prctl(..)
  , SyscallExitDetails_arch_prctl(..)
  , SyscallEnterDetails_sigreturn(..)
  , SyscallExitDetails_sigreturn(..)
  , SyscallEnterDetails_rt_sigreturn(..)
  , SyscallExitDetails_rt_sigreturn(..)
  , SyscallEnterDetails_mmap(..)
  , SyscallExitDetails_mmap(..)
  , SyscallEnterDetails_set_thread_area(..)
  , SyscallExitDetails_set_thread_area(..)
  , SyscallEnterDetails_get_thread_area(..)
  , SyscallExitDetails_get_thread_area(..)
  , SyscallEnterDetails_vm86old(..)
  , SyscallExitDetails_vm86old(..)
  , SyscallEnterDetails_vm86(..)
  , SyscallExitDetails_vm86(..)
  , SyscallEnterDetails_ioprio_set(..)
  , SyscallExitDetails_ioprio_set(..)
  , SyscallEnterDetails_ioprio_get(..)
  , SyscallExitDetails_ioprio_get(..)
  , SyscallEnterDetails_getrandom(..)
  , SyscallExitDetails_getrandom(..)
  , SyscallEnterDetails_pciconfig_read(..)
  , SyscallExitDetails_pciconfig_read(..)
  , SyscallEnterDetails_pciconfig_write(..)
  , SyscallExitDetails_pciconfig_write(..)
  , SyscallEnterDetails_io_setup(..)
  , SyscallExitDetails_io_setup(..)
  , SyscallEnterDetails_io_destroy(..)
  , SyscallExitDetails_io_destroy(..)
  , SyscallEnterDetails_io_submit(..)
  , SyscallExitDetails_io_submit(..)
  , SyscallEnterDetails_io_cancel(..)
  , SyscallExitDetails_io_cancel(..)
  , SyscallEnterDetails_io_getevents(..)
  , SyscallExitDetails_io_getevents(..)
  , SyscallEnterDetails_io_pgetevents(..)
  , SyscallExitDetails_io_pgetevents(..)
  , SyscallEnterDetails_bdflush(..)
  , SyscallExitDetails_bdflush(..)
  , SyscallEnterDetails_getcwd(..)
  , SyscallExitDetails_getcwd(..)
  , SyscallEnterDetails_lookup_dcookie(..)
  , SyscallExitDetails_lookup_dcookie(..)
  , SyscallEnterDetails_eventfd2(..)
  , SyscallExitDetails_eventfd2(..)
  , SyscallEnterDetails_eventfd(..)
  , SyscallExitDetails_eventfd(..)
  , SyscallEnterDetails_epoll_create1(..)
  , SyscallExitDetails_epoll_create1(..)
  , SyscallEnterDetails_epoll_create(..)
  , SyscallExitDetails_epoll_create(..)
  , SyscallEnterDetails_epoll_ctl(..)
  , SyscallExitDetails_epoll_ctl(..)
  , SyscallEnterDetails_epoll_wait(..)
  , SyscallExitDetails_epoll_wait(..)
  , SyscallEnterDetails_epoll_pwait(..)
  , SyscallExitDetails_epoll_pwait(..)
  , SyscallEnterDetails_uselib(..)
  , SyscallExitDetails_uselib(..)
  , SyscallEnterDetails_execveat(..)
  , SyscallExitDetails_execveat(..)
  , SyscallEnterDetails_fcntl(..)
  , SyscallExitDetails_fcntl(..)
  , SyscallEnterDetails_fcntl64(..)
  , SyscallExitDetails_fcntl64(..)
  , SyscallEnterDetails_name_to_handle_at(..)
  , SyscallExitDetails_name_to_handle_at(..)
  , SyscallEnterDetails_open_by_handle_at(..)
  , SyscallExitDetails_open_by_handle_at(..)
  , SyscallEnterDetails_dup3(..)
  , SyscallExitDetails_dup3(..)
  , SyscallEnterDetails_dup2(..)
  , SyscallExitDetails_dup2(..)
  , SyscallEnterDetails_dup(..)
  , SyscallExitDetails_dup(..)
  , SyscallEnterDetails_sysfs(..)
  , SyscallExitDetails_sysfs(..)
  , SyscallEnterDetails_ioctl(..)
  , SyscallExitDetails_ioctl(..)
  , SyscallEnterDetails_flock(..)
  , SyscallExitDetails_flock(..)
  , SyscallEnterDetails_mknodat(..)
  , SyscallExitDetails_mknodat(..)
  , SyscallEnterDetails_mknod(..)
  , SyscallExitDetails_mknod(..)
  , SyscallEnterDetails_mkdirat(..)
  , SyscallExitDetails_mkdirat(..)
  , SyscallEnterDetails_mkdir(..)
  , SyscallExitDetails_mkdir(..)
  , SyscallEnterDetails_rmdir(..)
  , SyscallExitDetails_rmdir(..)
  , SyscallEnterDetails_unlinkat(..)
  , SyscallExitDetails_unlinkat(..)
  , SyscallEnterDetails_unlink(..)
  , SyscallExitDetails_unlink(..)
  , SyscallEnterDetails_symlinkat(..)
  , SyscallExitDetails_symlinkat(..)
  , SyscallEnterDetails_symlink(..)
  , SyscallExitDetails_symlink(..)
  , SyscallEnterDetails_linkat(..)
  , SyscallExitDetails_linkat(..)
  , SyscallEnterDetails_link(..)
  , SyscallExitDetails_link(..)
  , SyscallEnterDetails_umount(..)
  , SyscallExitDetails_umount(..)
  , SyscallEnterDetails_oldumount(..)
  , SyscallExitDetails_oldumount(..)
  , SyscallEnterDetails_mount(..)
  , SyscallExitDetails_mount(..)
  , SyscallEnterDetails_pivot_root(..)
  , SyscallExitDetails_pivot_root(..)
  , SyscallEnterDetails_fanotify_init(..)
  , SyscallExitDetails_fanotify_init(..)
  , SyscallEnterDetails_fanotify_mark(..)
  , SyscallExitDetails_fanotify_mark(..)
  , SyscallEnterDetails_inotify_init1(..)
  , SyscallExitDetails_inotify_init1(..)
  , SyscallEnterDetails_inotify_init(..)
  , SyscallExitDetails_inotify_init(..)
  , SyscallEnterDetails_inotify_add_watch(..)
  , SyscallExitDetails_inotify_add_watch(..)
  , SyscallEnterDetails_inotify_rm_watch(..)
  , SyscallExitDetails_inotify_rm_watch(..)
  , SyscallEnterDetails_truncate(..)
  , SyscallExitDetails_truncate(..)
  , SyscallEnterDetails_ftruncate(..)
  , SyscallExitDetails_ftruncate(..)
  , SyscallEnterDetails_truncate64(..)
  , SyscallExitDetails_truncate64(..)
  , SyscallEnterDetails_ftruncate64(..)
  , SyscallExitDetails_ftruncate64(..)
  , SyscallEnterDetails_fallocate(..)
  , SyscallExitDetails_fallocate(..)
  , SyscallEnterDetails_chdir(..)
  , SyscallExitDetails_chdir(..)
  , SyscallEnterDetails_fchdir(..)
  , SyscallExitDetails_fchdir(..)
  , SyscallEnterDetails_chroot(..)
  , SyscallExitDetails_chroot(..)
  , SyscallEnterDetails_fchmod(..)
  , SyscallExitDetails_fchmod(..)
  , SyscallEnterDetails_fchmodat(..)
  , SyscallExitDetails_fchmodat(..)
  , SyscallEnterDetails_chmod(..)
  , SyscallExitDetails_chmod(..)
  , SyscallEnterDetails_fchownat(..)
  , SyscallExitDetails_fchownat(..)
  , SyscallEnterDetails_chown(..)
  , SyscallExitDetails_chown(..)
  , SyscallEnterDetails_lchown(..)
  , SyscallExitDetails_lchown(..)
  , SyscallEnterDetails_fchown(..)
  , SyscallExitDetails_fchown(..)
  , SyscallEnterDetails_vhangup(..)
  , SyscallExitDetails_vhangup(..)
  , SyscallEnterDetails_quotactl(..)
  , SyscallExitDetails_quotactl(..)
  , SyscallEnterDetails_lseek(..)
  , SyscallExitDetails_lseek(..)
  , SyscallEnterDetails_pread64(..)
  , SyscallExitDetails_pread64(..)
  , SyscallEnterDetails_pwrite64(..)
  , SyscallExitDetails_pwrite64(..)
  , SyscallEnterDetails_readv(..)
  , SyscallExitDetails_readv(..)
  , SyscallEnterDetails_writev(..)
  , SyscallExitDetails_writev(..)
  , SyscallEnterDetails_preadv(..)
  , SyscallExitDetails_preadv(..)
  , SyscallEnterDetails_preadv2(..)
  , SyscallExitDetails_preadv2(..)
  , SyscallEnterDetails_pwritev(..)
  , SyscallExitDetails_pwritev(..)
  , SyscallEnterDetails_pwritev2(..)
  , SyscallExitDetails_pwritev2(..)
  , SyscallEnterDetails_sendfile(..)
  , SyscallExitDetails_sendfile(..)
  , SyscallEnterDetails_sendfile64(..)
  , SyscallExitDetails_sendfile64(..)
  , SyscallEnterDetails_copy_file_range(..)
  , SyscallExitDetails_copy_file_range(..)
  , SyscallEnterDetails_getdents(..)
  , SyscallExitDetails_getdents(..)
  , SyscallEnterDetails_getdents64(..)
  , SyscallExitDetails_getdents64(..)
  , SyscallEnterDetails_poll(..)
  , SyscallExitDetails_poll(..)
  , SyscallEnterDetails_ppoll(..)
  , SyscallExitDetails_ppoll(..)
  , SyscallEnterDetails_signalfd4(..)
  , SyscallExitDetails_signalfd4(..)
  , SyscallEnterDetails_signalfd(..)
  , SyscallExitDetails_signalfd(..)
  , SyscallEnterDetails_vmsplice(..)
  , SyscallExitDetails_vmsplice(..)
  , SyscallEnterDetails_splice(..)
  , SyscallExitDetails_splice(..)
  , SyscallEnterDetails_tee(..)
  , SyscallExitDetails_tee(..)
  , SyscallEnterDetails_readlinkat(..)
  , SyscallExitDetails_readlinkat(..)
  , SyscallEnterDetails_readlink(..)
  , SyscallExitDetails_readlink(..)
  , SyscallEnterDetails_stat64(..)
  , SyscallExitDetails_stat64(..)
  , SyscallEnterDetails_lstat64(..)
  , SyscallExitDetails_lstat64(..)
  , SyscallEnterDetails_fstat64(..)
  , SyscallExitDetails_fstat64(..)
  , SyscallEnterDetails_fstatat64(..)
  , SyscallExitDetails_fstatat64(..)
  , SyscallEnterDetails_statx(..)
  , SyscallExitDetails_statx(..)
  , SyscallEnterDetails_statfs(..)
  , SyscallExitDetails_statfs(..)
  , SyscallEnterDetails_statfs64(..)
  , SyscallExitDetails_statfs64(..)
  , SyscallEnterDetails_fstatfs(..)
  , SyscallExitDetails_fstatfs(..)
  , SyscallEnterDetails_fstatfs64(..)
  , SyscallExitDetails_fstatfs64(..)
  , SyscallEnterDetails_ustat(..)
  , SyscallExitDetails_ustat(..)
  , SyscallEnterDetails_sync(..)
  , SyscallExitDetails_sync(..)
  , SyscallEnterDetails_syncfs(..)
  , SyscallExitDetails_syncfs(..)
  , SyscallEnterDetails_fsync(..)
  , SyscallExitDetails_fsync(..)
  , SyscallEnterDetails_fdatasync(..)
  , SyscallExitDetails_fdatasync(..)
  , SyscallEnterDetails_sync_file_range(..)
  , SyscallExitDetails_sync_file_range(..)
  , SyscallEnterDetails_sync_file_range2(..)
  , SyscallExitDetails_sync_file_range2(..)
  , SyscallEnterDetails_timerfd_create(..)
  , SyscallExitDetails_timerfd_create(..)
  , SyscallEnterDetails_timerfd_settime(..)
  , SyscallExitDetails_timerfd_settime(..)
  , SyscallEnterDetails_timerfd_gettime(..)
  , SyscallExitDetails_timerfd_gettime(..)
  , SyscallEnterDetails_userfaultfd(..)
  , SyscallExitDetails_userfaultfd(..)
  , SyscallEnterDetails_utimensat(..)
  , SyscallExitDetails_utimensat(..)
  , SyscallEnterDetails_futimesat(..)
  , SyscallExitDetails_futimesat(..)
  , SyscallEnterDetails_utimes(..)
  , SyscallExitDetails_utimes(..)
  , SyscallEnterDetails_utime(..)
  , SyscallExitDetails_utime(..)
  , SyscallEnterDetails_setxattr(..)
  , SyscallExitDetails_setxattr(..)
  , SyscallEnterDetails_lsetxattr(..)
  , SyscallExitDetails_lsetxattr(..)
  , SyscallEnterDetails_fsetxattr(..)
  , SyscallExitDetails_fsetxattr(..)
  , SyscallEnterDetails_getxattr(..)
  , SyscallExitDetails_getxattr(..)
  , SyscallEnterDetails_lgetxattr(..)
  , SyscallExitDetails_lgetxattr(..)
  , SyscallEnterDetails_fgetxattr(..)
  , SyscallExitDetails_fgetxattr(..)
  , SyscallEnterDetails_listxattr(..)
  , SyscallExitDetails_listxattr(..)
  , SyscallEnterDetails_llistxattr(..)
  , SyscallExitDetails_llistxattr(..)
  , SyscallEnterDetails_flistxattr(..)
  , SyscallExitDetails_flistxattr(..)
  , SyscallEnterDetails_removexattr(..)
  , SyscallExitDetails_removexattr(..)
  , SyscallEnterDetails_lremovexattr(..)
  , SyscallExitDetails_lremovexattr(..)
  , SyscallEnterDetails_fremovexattr(..)
  , SyscallExitDetails_fremovexattr(..)
  , SyscallEnterDetails_msgget(..)
  , SyscallExitDetails_msgget(..)
  , SyscallEnterDetails_msgctl(..)
  , SyscallExitDetails_msgctl(..)
  , SyscallEnterDetails_msgsnd(..)
  , SyscallExitDetails_msgsnd(..)
  , SyscallEnterDetails_msgrcv(..)
  , SyscallExitDetails_msgrcv(..)
  , SyscallEnterDetails_semget(..)
  , SyscallExitDetails_semget(..)
  , SyscallEnterDetails_semctl(..)
  , SyscallExitDetails_semctl(..)
  , SyscallEnterDetails_semtimedop(..)
  , SyscallExitDetails_semtimedop(..)
  , SyscallEnterDetails_semop(..)
  , SyscallExitDetails_semop(..)
  , SyscallEnterDetails_shmget(..)
  , SyscallExitDetails_shmget(..)
  , SyscallEnterDetails_shmctl(..)
  , SyscallExitDetails_shmctl(..)
  , SyscallEnterDetails_shmat(..)
  , SyscallExitDetails_shmat(..)
  , SyscallEnterDetails_shmdt(..)
  , SyscallExitDetails_shmdt(..)
  , SyscallEnterDetails_ipc(..)
  , SyscallExitDetails_ipc(..)
  , SyscallEnterDetails_acct(..)
  , SyscallExitDetails_acct(..)
  , SyscallEnterDetails_perf_event_open(..)
  , SyscallExitDetails_perf_event_open(..)
  , SyscallEnterDetails_personality(..)
  , SyscallExitDetails_personality(..)
  , SyscallEnterDetails_waitid(..)
  , SyscallExitDetails_waitid(..)
  , SyscallEnterDetails_wait4(..)
  , SyscallExitDetails_wait4(..)
  , SyscallEnterDetails_waitpid(..)
  , SyscallExitDetails_waitpid(..)
  , SyscallEnterDetails_set_tid_address(..)
  , SyscallExitDetails_set_tid_address(..)
  , SyscallEnterDetails_fork(..)
  , SyscallExitDetails_fork(..)
  , SyscallEnterDetails_vfork(..)
  , SyscallExitDetails_vfork(..)
  , SyscallEnterDetails_clone(..)
  , SyscallExitDetails_clone(..)
  , SyscallEnterDetails_unshare(..)
  , SyscallExitDetails_unshare(..)
  , SyscallEnterDetails_set_robust_list(..)
  , SyscallExitDetails_set_robust_list(..)
  , SyscallEnterDetails_get_robust_list(..)
  , SyscallExitDetails_get_robust_list(..)
  , SyscallEnterDetails_futex(..)
  , SyscallExitDetails_futex(..)
  , SyscallEnterDetails_getgroups(..)
  , SyscallExitDetails_getgroups(..)
  , SyscallEnterDetails_setgroups(..)
  , SyscallExitDetails_setgroups(..)
  , SyscallEnterDetails_kcmp(..)
  , SyscallExitDetails_kcmp(..)
  , SyscallEnterDetails_kexec_load(..)
  , SyscallExitDetails_kexec_load(..)
  , SyscallEnterDetails_kexec_file_load(..)
  , SyscallExitDetails_kexec_file_load(..)
  , SyscallEnterDetails_delete_module(..)
  , SyscallExitDetails_delete_module(..)
  , SyscallEnterDetails_init_module(..)
  , SyscallExitDetails_init_module(..)
  , SyscallEnterDetails_finit_module(..)
  , SyscallExitDetails_finit_module(..)
  , SyscallEnterDetails_setns(..)
  , SyscallExitDetails_setns(..)
  , SyscallEnterDetails_syslog(..)
  , SyscallExitDetails_syslog(..)
  , SyscallEnterDetails_ptrace(..)
  , SyscallExitDetails_ptrace(..)
  , SyscallEnterDetails_reboot(..)
  , SyscallExitDetails_reboot(..)
  , SyscallEnterDetails_rseq(..)
  , SyscallExitDetails_rseq(..)
  , SyscallEnterDetails_nice(..)
  , SyscallExitDetails_nice(..)
  , SyscallEnterDetails_sched_setscheduler(..)
  , SyscallExitDetails_sched_setscheduler(..)
  , SyscallEnterDetails_sched_setparam(..)
  , SyscallExitDetails_sched_setparam(..)
  , SyscallEnterDetails_sched_setattr(..)
  , SyscallExitDetails_sched_setattr(..)
  , SyscallEnterDetails_sched_getscheduler(..)
  , SyscallExitDetails_sched_getscheduler(..)
  , SyscallEnterDetails_sched_getparam(..)
  , SyscallExitDetails_sched_getparam(..)
  , SyscallEnterDetails_sched_getattr(..)
  , SyscallExitDetails_sched_getattr(..)
  , SyscallEnterDetails_sched_setaffinity(..)
  , SyscallExitDetails_sched_setaffinity(..)
  , SyscallEnterDetails_sched_getaffinity(..)
  , SyscallExitDetails_sched_getaffinity(..)
  , SyscallEnterDetails_sched_yield(..)
  , SyscallExitDetails_sched_yield(..)
  , SyscallEnterDetails_sched_get_priority_max(..)
  , SyscallExitDetails_sched_get_priority_max(..)
  , SyscallEnterDetails_sched_get_priority_min(..)
  , SyscallExitDetails_sched_get_priority_min(..)
  , SyscallEnterDetails_sched_rr_get_interval(..)
  , SyscallExitDetails_sched_rr_get_interval(..)
  , SyscallEnterDetails_membarrier(..)
  , SyscallExitDetails_membarrier(..)
  , SyscallEnterDetails_seccomp(..)
  , SyscallExitDetails_seccomp(..)
  , SyscallEnterDetails_restart_syscall(..)
  , SyscallExitDetails_restart_syscall(..)
  , SyscallEnterDetails_rt_sigprocmask(..)
  , SyscallExitDetails_rt_sigprocmask(..)
  , SyscallEnterDetails_rt_sigpending(..)
  , SyscallExitDetails_rt_sigpending(..)
  , SyscallEnterDetails_kill(..)
  , SyscallExitDetails_kill(..)
  , SyscallEnterDetails_tgkill(..)
  , SyscallExitDetails_tgkill(..)
  , SyscallEnterDetails_tkill(..)
  , SyscallExitDetails_tkill(..)
  , SyscallEnterDetails_sigpending(..)
  , SyscallExitDetails_sigpending(..)
  , SyscallEnterDetails_sigprocmask(..)
  , SyscallExitDetails_sigprocmask(..)
  , SyscallEnterDetails_rt_sigaction(..)
  , SyscallExitDetails_rt_sigaction(..)
  , SyscallEnterDetails_sigaction(..)
  , SyscallExitDetails_sigaction(..)
  , SyscallEnterDetails_sgetmask(..)
  , SyscallExitDetails_sgetmask(..)
  , SyscallEnterDetails_ssetmask(..)
  , SyscallExitDetails_ssetmask(..)
  , SyscallEnterDetails_signal(..)
  , SyscallExitDetails_signal(..)
  , SyscallEnterDetails_pause(..)
  , SyscallExitDetails_pause(..)
  , SyscallEnterDetails_rt_sigsuspend(..)
  , SyscallExitDetails_rt_sigsuspend(..)
  , SyscallEnterDetails_sigsuspend(..)
  , SyscallExitDetails_sigsuspend(..)
  , SyscallEnterDetails_setpriority(..)
  , SyscallExitDetails_setpriority(..)
  , SyscallEnterDetails_getpriority(..)
  , SyscallExitDetails_getpriority(..)
  , SyscallEnterDetails_setregid(..)
  , SyscallExitDetails_setregid(..)
  , SyscallEnterDetails_setgid(..)
  , SyscallExitDetails_setgid(..)
  , SyscallEnterDetails_setreuid(..)
  , SyscallExitDetails_setreuid(..)
  , SyscallEnterDetails_setuid(..)
  , SyscallExitDetails_setuid(..)
  , SyscallEnterDetails_setresuid(..)
  , SyscallExitDetails_setresuid(..)
  , SyscallEnterDetails_getresuid(..)
  , SyscallExitDetails_getresuid(..)
  , SyscallEnterDetails_setresgid(..)
  , SyscallExitDetails_setresgid(..)
  , SyscallEnterDetails_getresgid(..)
  , SyscallExitDetails_getresgid(..)
  , SyscallEnterDetails_setfsuid(..)
  , SyscallExitDetails_setfsuid(..)
  , SyscallEnterDetails_setfsgid(..)
  , SyscallExitDetails_setfsgid(..)
  , SyscallEnterDetails_getpid(..)
  , SyscallExitDetails_getpid(..)
  , SyscallEnterDetails_gettid(..)
  , SyscallExitDetails_gettid(..)
  , SyscallEnterDetails_getppid(..)
  , SyscallExitDetails_getppid(..)
  , SyscallEnterDetails_getuid(..)
  , SyscallExitDetails_getuid(..)
  , SyscallEnterDetails_geteuid(..)
  , SyscallExitDetails_geteuid(..)
  , SyscallEnterDetails_getgid(..)
  , SyscallExitDetails_getgid(..)
  , SyscallEnterDetails_getegid(..)
  , SyscallExitDetails_getegid(..)
  , SyscallEnterDetails_times(..)
  , SyscallExitDetails_times(..)
  , SyscallEnterDetails_setpgid(..)
  , SyscallExitDetails_setpgid(..)
  , SyscallEnterDetails_getpgid(..)
  , SyscallExitDetails_getpgid(..)
  , SyscallEnterDetails_getpgrp(..)
  , SyscallExitDetails_getpgrp(..)
  , SyscallEnterDetails_getsid(..)
  , SyscallExitDetails_getsid(..)
  , SyscallEnterDetails_setsid(..)
  , SyscallExitDetails_setsid(..)
  , SyscallEnterDetails_uname(..)
  , SyscallExitDetails_uname(..)
  , SyscallEnterDetails_olduname(..)
  , SyscallExitDetails_olduname(..)
  , SyscallEnterDetails_sethostname(..)
  , SyscallExitDetails_sethostname(..)
  , SyscallEnterDetails_gethostname(..)
  , SyscallExitDetails_gethostname(..)
  , SyscallEnterDetails_setdomainname(..)
  , SyscallExitDetails_setdomainname(..)
  , SyscallEnterDetails_getrlimit(..)
  , SyscallExitDetails_getrlimit(..)
  , SyscallEnterDetails_prlimit64(..)
  , SyscallExitDetails_prlimit64(..)
  , SyscallEnterDetails_setrlimit(..)
  , SyscallExitDetails_setrlimit(..)
  , SyscallEnterDetails_getrusage(..)
  , SyscallExitDetails_getrusage(..)
  , SyscallEnterDetails_umask(..)
  , SyscallExitDetails_umask(..)
  , SyscallEnterDetails_prctl(..)
  , SyscallExitDetails_prctl(..)
  , SyscallEnterDetails_getcpu(..)
  , SyscallExitDetails_getcpu(..)
  , SyscallEnterDetails_sysinfo(..)
  , SyscallExitDetails_sysinfo(..)
  , SyscallEnterDetails_nanosleep(..)
  , SyscallExitDetails_nanosleep(..)
  , SyscallEnterDetails_getitimer(..)
  , SyscallExitDetails_getitimer(..)
  , SyscallEnterDetails_alarm(..)
  , SyscallExitDetails_alarm(..)
  , SyscallEnterDetails_setitimer(..)
  , SyscallExitDetails_setitimer(..)
  , SyscallEnterDetails_clock_settime(..)
  , SyscallExitDetails_clock_settime(..)
  , SyscallEnterDetails_clock_gettime(..)
  , SyscallExitDetails_clock_gettime(..)
  , SyscallEnterDetails_clock_getres(..)
  , SyscallExitDetails_clock_getres(..)
  , SyscallEnterDetails_clock_nanosleep(..)
  , SyscallExitDetails_clock_nanosleep(..)
  , SyscallEnterDetails_timer_create(..)
  , SyscallExitDetails_timer_create(..)
  , SyscallEnterDetails_timer_gettime(..)
  , SyscallExitDetails_timer_gettime(..)
  , SyscallEnterDetails_timer_getoverrun(..)
  , SyscallExitDetails_timer_getoverrun(..)
  , SyscallEnterDetails_timer_settime(..)
  , SyscallExitDetails_timer_settime(..)
  , SyscallEnterDetails_timer_delete(..)
  , SyscallExitDetails_timer_delete(..)
  , SyscallEnterDetails_clock_adjtime(..)
  , SyscallExitDetails_clock_adjtime(..)
  , SyscallEnterDetails_time(..)
  , SyscallExitDetails_time(..)
  , SyscallEnterDetails_stime(..)
  , SyscallExitDetails_stime(..)
  , SyscallEnterDetails_gettimeofday(..)
  , SyscallExitDetails_gettimeofday(..)
  , SyscallEnterDetails_settimeofday(..)
  , SyscallExitDetails_settimeofday(..)
  , SyscallEnterDetails_adjtimex(..)
  , SyscallExitDetails_adjtimex(..)
  , SyscallEnterDetails_fadvise64_64(..)
  , SyscallExitDetails_fadvise64_64(..)
  , SyscallEnterDetails_fadvise64(..)
  , SyscallExitDetails_fadvise64(..)
  , SyscallEnterDetails_madvise(..)
  , SyscallExitDetails_madvise(..)
  , SyscallEnterDetails_memfd_create(..)
  , SyscallExitDetails_memfd_create(..)
  , SyscallEnterDetails_mbind(..)
  , SyscallExitDetails_mbind(..)
  , SyscallEnterDetails_set_mempolicy(..)
  , SyscallExitDetails_set_mempolicy(..)
  , SyscallEnterDetails_migrate_pages(..)
  , SyscallExitDetails_migrate_pages(..)
  , SyscallEnterDetails_get_mempolicy(..)
  , SyscallExitDetails_get_mempolicy(..)
  , SyscallEnterDetails_move_pages(..)
  , SyscallExitDetails_move_pages(..)
  , SyscallEnterDetails_mincore(..)
  , SyscallExitDetails_mincore(..)
  , SyscallEnterDetails_mlock(..)
  , SyscallExitDetails_mlock(..)
  , SyscallEnterDetails_mlock2(..)
  , SyscallExitDetails_mlock2(..)
  , SyscallEnterDetails_munlock(..)
  , SyscallExitDetails_munlock(..)
  , SyscallEnterDetails_mlockall(..)
  , SyscallExitDetails_mlockall(..)
  , SyscallEnterDetails_munlockall(..)
  , SyscallExitDetails_munlockall(..)
  , SyscallEnterDetails_brk(..)
  , SyscallExitDetails_brk(..)
  , SyscallEnterDetails_munmap(..)
  , SyscallExitDetails_munmap(..)
  , SyscallEnterDetails_remap_file_pages(..)
  , SyscallExitDetails_remap_file_pages(..)
  , SyscallEnterDetails_mprotect(..)
  , SyscallExitDetails_mprotect(..)
  , SyscallEnterDetails_pkey_mprotect(..)
  , SyscallExitDetails_pkey_mprotect(..)
  , SyscallEnterDetails_pkey_alloc(..)
  , SyscallExitDetails_pkey_alloc(..)
  , SyscallEnterDetails_pkey_free(..)
  , SyscallExitDetails_pkey_free(..)
  , SyscallEnterDetails_mremap(..)
  , SyscallExitDetails_mremap(..)
  , SyscallEnterDetails_msync(..)
  , SyscallExitDetails_msync(..)
  , SyscallEnterDetails_process_vm_readv(..)
  , SyscallExitDetails_process_vm_readv(..)
  , SyscallEnterDetails_process_vm_writev(..)
  , SyscallExitDetails_process_vm_writev(..)
  , SyscallEnterDetails_readahead(..)
  , SyscallExitDetails_readahead(..)
  , SyscallEnterDetails_swapoff(..)
  , SyscallExitDetails_swapoff(..)
  , SyscallEnterDetails_swapon(..)
  , SyscallExitDetails_swapon(..)
  , SyscallEnterDetails_socket(..)
  , SyscallExitDetails_socket(..)
  , SyscallEnterDetails_socketpair(..)
  , SyscallExitDetails_socketpair(..)
  , SyscallEnterDetails_bind(..)
  , SyscallExitDetails_bind(..)
  , SyscallEnterDetails_listen(..)
  , SyscallExitDetails_listen(..)
  , SyscallEnterDetails_accept4(..)
  , SyscallExitDetails_accept4(..)
  , SyscallEnterDetails_accept(..)
  , SyscallExitDetails_accept(..)
  , SyscallEnterDetails_connect(..)
  , SyscallExitDetails_connect(..)
  , SyscallEnterDetails_getsockname(..)
  , SyscallExitDetails_getsockname(..)
  , SyscallEnterDetails_getpeername(..)
  , SyscallExitDetails_getpeername(..)
  , SyscallEnterDetails_sendto(..)
  , SyscallExitDetails_sendto(..)
  , SyscallEnterDetails_send(..)
  , SyscallExitDetails_send(..)
  , SyscallEnterDetails_recvfrom(..)
  , SyscallExitDetails_recvfrom(..)
  , SyscallEnterDetails_recv(..)
  , SyscallExitDetails_recv(..)
  , SyscallEnterDetails_setsockopt(..)
  , SyscallExitDetails_setsockopt(..)
  , SyscallEnterDetails_getsockopt(..)
  , SyscallExitDetails_getsockopt(..)
  , SyscallEnterDetails_shutdown(..)
  , SyscallExitDetails_shutdown(..)
  , SyscallEnterDetails_sendmsg(..)
  , SyscallExitDetails_sendmsg(..)
  , SyscallEnterDetails_sendmmsg(..)
  , SyscallExitDetails_sendmmsg(..)
  , SyscallEnterDetails_recvmsg(..)
  , SyscallExitDetails_recvmsg(..)
  , SyscallEnterDetails_recvmmsg(..)
  , SyscallExitDetails_recvmmsg(..)
  , SyscallEnterDetails_socketcall(..)
  , SyscallExitDetails_socketcall(..)
  , SyscallEnterDetails_add_key(..)
  , SyscallExitDetails_add_key(..)
  , SyscallEnterDetails_request_key(..)
  , SyscallExitDetails_request_key(..)
  , SyscallEnterDetails_keyctl(..)
  , SyscallExitDetails_keyctl(..)
  , SyscallEnterDetails_select(..)
  , SyscallExitDetails_select(..)
  , SyscallEnterDetails_pselect6(..)
  , SyscallExitDetails_pselect6(..)
  , SyscallEnterDetails_mq_open(..)
  , SyscallExitDetails_mq_open(..)
  , SyscallEnterDetails_mq_unlink(..)
  , SyscallExitDetails_mq_unlink(..)
  , SyscallEnterDetails_bpf(..)
  , SyscallExitDetails_bpf(..)
  , SyscallEnterDetails_capget(..)
  , SyscallExitDetails_capget(..)
  , SyscallEnterDetails_capset(..)
  , SyscallExitDetails_capset(..)
  , SyscallEnterDetails_rt_sigtimedwait(..)
  , SyscallExitDetails_rt_sigtimedwait(..)
  , SyscallEnterDetails_rt_sigqueueinfo(..)
  , SyscallExitDetails_rt_sigqueueinfo(..)
  , SyscallEnterDetails_rt_tgsigqueueinfo(..)
  , SyscallExitDetails_rt_tgsigqueueinfo(..)
  , SyscallEnterDetails_sigaltstack(..)
  , SyscallExitDetails_sigaltstack(..)
  , SyscallEnterDetails_mq_timedsend(..)
  , SyscallExitDetails_mq_timedsend(..)
  , SyscallEnterDetails_mq_timedreceive(..)
  , SyscallExitDetails_mq_timedreceive(..)
  , SyscallEnterDetails_mq_notify(..)
  , SyscallExitDetails_mq_notify(..)
  , SyscallEnterDetails_mq_getsetattr(..)
  , SyscallExitDetails_mq_getsetattr(..)
  , DetailedSyscallEnter(..)
  , DetailedSyscallExit(..)
  , ERRNO(..)
  , foreignErrnoToERRNO
  , getSyscallEnterDetails
  , syscallEnterDetailsOnlyConduit
  , syscallExitDetailsOnlyConduit
  , FileWriteEvent(..)
  , fileWritesConduit
  , FileWriteBehavior(..)
  , atomicWritesSink
  , SyscallStopType(..)
  , TraceEvent(..)
  , TraceState(..)
  , Syscall(..)
  , SyscallArgs(..)
  , sendSignal
  , doesProcessHaveChildren
  , getFdPath
  , getExePath
  -- * Re-exports
  , KnownSyscall(..)
  ) where

import           Conduit (foldlC)
import           Control.Arrow (second)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.IO.Unlift (MonadUnliftIO)
import           Data.Bits ((.|.), shiftL, shiftR)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
import           Data.Conduit
import qualified Data.Conduit.List as CL
import           Data.Either (partitionEithers)
import           Data.List (genericLength)
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Word (Word32, Word64)
import           Foreign.C.Error (Errno(..), throwErrnoIfMinus1, throwErrnoIfMinus1_, getErrno, resetErrno, eCHILD, eINVAL)
import           Foreign.C.String (peekCString)
import           Foreign.C.Types (CInt(..), CLong(..), CULong(..), CChar(..), CSize(..), CUInt(..), CLLong(..), CUChar(..))
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Marshal.Alloc (alloca)
import           Foreign.Marshal.Array (withArray)
import           Foreign.Marshal.Utils (withMany)
import           Foreign.Ptr (Ptr, nullPtr, wordPtrToPtr)
import           Foreign.Storable (peekByteOff, sizeOf)
import           GHC.Stack (HasCallStack, callStack, getCallStack, prettySrcLoc)
import           System.Directory (canonicalizePath, doesFileExist, findExecutable)
import           System.Exit (ExitCode(..), die)
import           System.FilePath ((</>))
import           System.IO.Error (modifyIOError, ioeGetLocation, ioeSetLocation)
import           System.Linux.Ptrace (TracedProcess(..), peekBytes, peekNullTerminatedBytes, peekNullWordTerminatedWords, detach)
import qualified System.Linux.Ptrace as Ptrace
import           System.Linux.Ptrace.Syscall hiding (ptrace_syscall, ptrace_detach)
import qualified System.Linux.Ptrace.Syscall as Ptrace.Syscall
import           System.Linux.Ptrace.Types (Regs(..))
import           System.Linux.Ptrace.X86_64Regs (X86_64Regs(..))
import           System.Linux.Ptrace.X86Regs (X86Regs(..))
import           System.Posix.Files (readSymbolicLink)
import           System.Posix.Internals (withFilePath)
import           System.Posix.Signals (Signal, sigTRAP, sigSTOP, sigTSTP, sigTTIN, sigTTOU)
import           System.Posix.Types (CPid(..), CMode(..))
import           System.Posix.Waitpid (waitpid, waitpidFullStatus, Status(..), FullStatus(..), Flag(..))
import           UnliftIO.Concurrent (runInBoundThread)
import           UnliftIO.IORef (newIORef, writeIORef, readIORef)

import           System.Hatrace.SignalMap (signalMap)
import           System.Hatrace.SyscallTables.Generated (KnownSyscall(..), syscallName, syscallMap_i386, syscallMap_x64_64)
import           System.Hatrace.Types


mapLeft :: (a1 -> a2) -> Either a1 b -> Either a2 b
mapLeft f = either (Left . f) Right


-- | Not using "Foreign.C.Error"'s `Errno` because it doesn't have a `Show`
-- instance, which would be a pain for consumers of our API.
--
-- Use `foreignErrnoToERRNO` to convert between them.
newtype ERRNO = ERRNO CInt
  deriving (Eq, Ord, Show)


-- | Turn a "Foreign.C.Error" `Errno` into `ERRNO`.
foreignErrnoToERRNO :: Errno -> ERRNO
foreignErrnoToERRNO (Errno e) = ERRNO e


-- | Adds some prefix (separated by @: @) to the error location of an `IOError`.
addIOErrorPrefix :: String -> IO a -> IO a
addIOErrorPrefix prefix action = do
  modifyIOError (\e -> ioeSetLocation e (prefix ++ ": " ++ ioeGetLocation e)) action


-- | We generally use this function to make it more obvious via what kind of
-- invocation of ptrace() it failed, because it's very easy to get
-- ptrace calls wrong. Without this, you'd just get
--
-- > ptrace: does not exist (No such process)
--
-- for pretty much any wrong invocation.
-- By adding the location to the exception, these
-- details show up in our test suite and our users' error messages.
--
-- Note that where possible, use a single invocation of this function
-- instead of nested invocations, so that the exception has to be caught
-- and rethrown as few times as possible.
annotatePtrace :: String -> IO a -> IO a
annotatePtrace = addIOErrorPrefix


-- | Wrapper around `Ptrace.System.ptrace_syscall` that prints its name in
-- `IOError`s it raises.
ptrace_syscall :: (HasCallStack) => CPid -> Maybe Signal -> IO ()
ptrace_syscall pid mbSignal = do
  let debugCallLocation = if
        | False -> -- set this to True to get caller source code lines for failures
            -- Put the top-most call stack caller into the error message
            concat
              [ prettySrcLoc srcLoc
              | (_, srcLoc):_ <- [getCallStack callStack]
              ] ++ " (pid " ++ show pid ++ "): "
        | otherwise -> ""
  annotatePtrace (debugCallLocation ++ "ptrace_syscall") $
    Ptrace.Syscall.ptrace_syscall pid mbSignal


-- | Wrapper around `Ptrace.System.detach` that prints its name in
-- `IOError`s it raises.
ptrace_detach :: CPid -> IO ()
ptrace_detach pid = annotatePtrace "ptrace_detach" $ detach (TracedProcess pid)


waitpidForExactPidStopOrError :: (HasCallStack) => CPid -> IO ()
waitpidForExactPidStopOrError pid = do
  mr <- waitpid pid []
  case mr of
    Nothing -> error "waitpidForExactPidStopOrError: BUG: no PID was returned by waitpid"
    Just (returnedPid, status)
      | returnedPid /= pid -> error $ "waitpidForExactPidStopOrError: BUG: returned PID != expected pid: " ++ show (returnedPid, pid)
      | otherwise ->
        case status of
          Stopped sig | sig == sigSTOP -> return () -- all OK
          -- TODO: This seems to happen when we ourselves (the tracer) are being `strace`d. Investigate.
          _ -> error $ "waitpidForExactPidStopOrError: BUG: unexpected status: " ++ show status


foreign import ccall safe "fork_exec_with_ptrace" c_fork_exec_with_ptrace :: CInt -> Ptr (Ptr CChar) -> IO CPid


-- | Forks a tracee process, makes it PTRACE_TRACEME and then SIGSTOP itself.
-- Waits for the tracee process to have entered the STOPPED state.
-- After waking up from the stop (as controlled by the tracer, that is,
-- other functions you'll use after calling this one),
-- the tracee will execv() the given program with arguments.
--
-- Since execv() is used, the first argument must be the /full path/
-- to the executable.
forkExecvWithPtrace :: (HasCallStack) => [String] -> IO CPid
forkExecvWithPtrace args = do
  childPid <- withMany withFilePath args $ \cstrs -> do
    withArray cstrs $ \argsPtr -> do
      let argc = genericLength args
      throwErrnoIfMinus1 "fork_exec_with_ptrace" $ c_fork_exec_with_ptrace argc argsPtr
  -- Wait for the tracee to stop itself
  waitpidForExactPidStopOrError childPid
  return childPid


-- | A conduit that starts a traced process from given @args@, and yields all
-- trace events that occur to it.
--
-- Already uses `runInBoundThread` internally, so using this ensures that you
-- don't accidentally run a @ptrace()@ call from an OS thread that's not the
-- tracer of the started process.
sourceTraceForkExecvFullPathWithSink :: (MonadUnliftIO m) => [String] -> ConduitT (CPid, TraceEvent) Void m a -> m (ExitCode, a)
sourceTraceForkExecvFullPathWithSink args sink = runInBoundThread $ do
  childPid <- liftIO $ forkExecvWithPtrace args
  -- Now the child is stopped. Set options, then start it.
  liftIO $ annotatePtrace "ptrace_setoptions" $ ptrace_setoptions childPid
    -- Set `PTRACE_O_TRACESYSGOOD` to make it easy for the tracer
    -- to distinguish normal traps from those caused by a syscall.
    [ TraceSysGood
    -- Set `PTRACE_O_EXITKILL` so that if we crash, everything below
    -- also terminates.
    , ExitKill
    -- Tracing child processes
    , TraceClone
    , TraceFork
    , TraceVFork
    , TraceVForkDone
    -- Sign up for the various PTRACE_EVENT_* events we want to handle below.
    , TraceExec
    , TraceExit
    ]
  -- Start the child.
  liftIO $ ptrace_syscall childPid Nothing

  exitCodeRef <- newIORef (Nothing :: Maybe ExitCode)
  let loop state = do
        (newState, (returnedPid, event)) <- liftIO $ waitForTraceEvent state

        yield (returnedPid, event)

        -- Cases in which we have to restart the tracee
        -- (by calling `ptrace_syscall` again).
        liftIO $ case event of
          SyscallStop _enterOrExit -> do
            -- Tell the process to continue into / out of the syscall,
            -- and generate another event at the next syscall or signal.
            ptrace_syscall returnedPid Nothing
          PTRACE_EVENT_Stop _ptraceEvent -> do
            -- Continue past the event.
            ptrace_syscall returnedPid Nothing
            -- As discussed in the docs of PTRACE_EVENT_EXIT, even for that
            -- event the child is still alive and needs to be restarted
            -- before it truly exits.
          GroupStop sig -> do
            -- Continue past the event.
            ptrace_syscall returnedPid (Just sig)
          SignalDeliveryStop sig -> do
            -- Deliver the signal
            ptrace_syscall returnedPid (Just sig)
          Death _exitCode -> return () -- can't restart it, it's dead

        -- The program runs.
        -- It is in this section of the code where the traced program actually runs:
        -- between `ptrace_syscall` and `waitForTraceEvent`'s waitpid()' returning
        -- (this statement is of course only accurate for single-threaded programs
        -- without child processes; otherwise multiple things can be running).

        case event of
          Death exitCode | returnedPid == childPid -> do
            -- Our direct child exited, we are done.
            -- TODO: Figure out how to handle the situation that our
            --       direct child exits when children are still alive
            --       (because it didn't reap them or because they
            --       double-forked to daemonize).
            writeIORef exitCodeRef (Just exitCode)
            -- no further `loop`ing
          _ -> do
            loop newState

  a <- runConduit $ loop initialTraceState .| sink
  mExitCode <- readIORef exitCodeRef
  finalExitCode <- liftIO $ case mExitCode of
    Just e -> pure e
    Nothing -> do
      -- If the child hasn't exited yet, Detach from it and let it run
      -- to an end.
      -- TODO: We probably have to do that for all tracees.
      preDetachWaitpidResult <- waitpid childPid []
      case preDetachWaitpidResult of
        Nothing -> error "sourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
        Just{} -> do
          -- TODO as the man page says:
          --        PTRACE_DETACH  is a restarting operation; therefore it requires the tracee to be in ptrace-stop.
          --      We need to ensure/check we're in a ptrace-stop here.
          --      Further from the man page:
          --        If the tracee is running when the tracer wants to detach it, the usual
          --        solution is to send SIGSTOP (using tgkill(2), to make sure it goes to
          --        the correct  thread),  wait  for the  tracee  to  stop  in
          --        signal-delivery-stop for SIGSTOP and then detach it (suppressing
          --        SIGSTOP injection).  A design bug is that this can race with concurrent
          --        SIGSTOPs. Another complication is that the tracee may enter other
          --        ptrace-stops and needs to be restarted and waited for again, until
          --        SIGSTOP is seen.  Yet another complication  is  to be sure that the
          --        tracee is not already ptrace-stopped, because no signal delivery
          --        happens while it is—not even SIGSTOP.
          ptrace_detach childPid
          waitpidResult <- waitpidFullStatus childPid []
          case waitpidResult of
            Nothing -> error "sourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
            Just (_returnedPid, status, FullStatus fullStatus) -> case status of
              Exited 0 -> pure ExitSuccess
              _ -> pure $ ExitFailure (fromIntegral fullStatus)
  return (finalExitCode, a)


wordToPtr :: Word -> Ptr a
wordToPtr w = wordPtrToPtr (fromIntegral w)
{-# INLINE wordToPtr #-}


word64ToPtr :: Word64 -> Ptr a
word64ToPtr w = wordPtrToPtr (fromIntegral w)
{-# INLINE word64ToPtr #-}


-- * Syscall details
--
-- __Note:__ The data types below use @DuplicateRecordFields@.
--
-- Users should also use @DuplicateRecordFields@ to avoid getting
-- @Ambiguous occurrence@ errors.

data SyscallEnterDetails_open = SyscallEnterDetails_open
  { pathname :: Ptr CChar
  , flags :: CInt
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_open = SyscallExitDetails_open
  { enterDetail :: SyscallEnterDetails_open
  , fd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_openat = SyscallEnterDetails_openat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , flags :: CInt
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_openat = SyscallExitDetails_openat
  { enterDetail :: SyscallEnterDetails_openat
  , fd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_creat = SyscallEnterDetails_creat
  { pathname :: Ptr CChar
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_creat = SyscallExitDetails_creat
  { enterDetail :: SyscallEnterDetails_creat
  , fd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_pipe = SyscallEnterDetails_pipe
  { pipefd :: Ptr CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_pipe = SyscallExitDetails_pipe
  { enterDetail :: SyscallEnterDetails_pipe
  , readfd :: CInt
  , writefd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_pipe2 = SyscallEnterDetails_pipe2
  { pipefd :: Ptr CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_pipe2 = SyscallExitDetails_pipe2
  { enterDetail :: SyscallEnterDetails_pipe2
  , readfd :: CInt
  , writefd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_exit = SyscallEnterDetails_exit
  { status :: CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_exit = SyscallExitDetails_exit
  { enterDetail :: SyscallEnterDetails_exit
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_exit_group = SyscallEnterDetails_exit_group
  { status :: CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_exit_group = SyscallExitDetails_exit_group
  { enterDetail :: SyscallEnterDetails_exit_group
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_write = SyscallEnterDetails_write
  { fd :: CInt
  , buf :: Ptr Void
  , count :: CSize
  -- Peeked details
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_write = SyscallExitDetails_write
  { enterDetail :: SyscallEnterDetails_write
  , writtenCount :: CSize
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_read = SyscallEnterDetails_read
  { fd :: CInt
  , buf :: Ptr Void
  , count :: CSize
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_read = SyscallExitDetails_read
  { enterDetail :: SyscallEnterDetails_read
  -- Peeked details
  , readCount :: CSize
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_close = SyscallEnterDetails_close
  { fd :: CInt
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_close = SyscallExitDetails_close
  { enterDetail :: SyscallEnterDetails_close
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_rename = SyscallEnterDetails_rename
  { oldpath :: Ptr CChar
  , newpath :: Ptr CChar
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_rename = SyscallExitDetails_rename
  { enterDetail :: SyscallEnterDetails_rename
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_renameat = SyscallEnterDetails_renameat
  { olddirfd :: CInt
  , oldpath :: Ptr CChar
  , newdirfd :: CInt
  , newpath :: Ptr CChar
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_renameat = SyscallExitDetails_renameat
  { enterDetail :: SyscallEnterDetails_renameat
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_renameat2 = SyscallEnterDetails_renameat2
  { olddirfd :: CInt
  , oldpath :: Ptr CChar
  , newdirfd :: CInt
  , newpath :: Ptr CChar
  , flags :: CInt
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_renameat2 = SyscallExitDetails_renameat2
  { enterDetail :: SyscallEnterDetails_renameat2
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_access = SyscallEnterDetails_access
  { pathname :: Ptr CChar
  , mode :: CInt
  -- Peeked details
  , accessMode :: FileAccessMode
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_access = SyscallExitDetails_access
  { enterDetail :: SyscallEnterDetails_access
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_faccessat = SyscallEnterDetails_faccessat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , mode :: CInt
  , flags :: CInt
  -- Peeked details
  , accessMode :: FileAccessMode
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_faccessat = SyscallExitDetails_faccessat
  { enterDetail :: SyscallEnterDetails_faccessat
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_stat = SyscallEnterDetails_stat
  { pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_stat = SyscallExitDetails_stat
  { enterDetail :: SyscallEnterDetails_stat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_fstat = SyscallEnterDetails_fstat
  { fd :: CInt
  , statbuf :: Ptr StatStruct
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_fstat = SyscallExitDetails_fstat
  { enterDetail :: SyscallEnterDetails_fstat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_lstat = SyscallEnterDetails_lstat
  { pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_lstat = SyscallExitDetails_lstat
  { enterDetail :: SyscallEnterDetails_lstat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_newfstatat = SyscallEnterDetails_newfstatat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  , flags :: CInt
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_newfstatat = SyscallExitDetails_newfstatat
  { enterDetail :: SyscallEnterDetails_newfstatat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_execve = SyscallEnterDetails_execve
  { filename :: Ptr CChar
  , argv :: Ptr (Ptr CChar)
  , envp :: Ptr (Ptr CChar)
  -- Peeked details
  , filenameBS :: ByteString
  , argvList :: [ByteString]
  , envpList :: [ByteString]
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_execve = SyscallExitDetails_execve
  { optionalEnterDetail :: Maybe SyscallEnterDetails_execve
  , execveResult :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_ioperm = SyscallEnterDetails_ioperm
  { from :: CULong
  , num :: CULong
  , turn_on :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_iopl = SyscallEnterDetails_iopl
  { level :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_modify_ldt = SyscallEnterDetails_modify_ldt
  { func :: CInt
  , ptr :: Ptr Void
  , bytecount :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_arch_prctl = SyscallEnterDetails_arch_prctl
  { option :: CInt
  , arg2 :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sigreturn = SyscallEnterDetails_sigreturn
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigreturn = SyscallEnterDetails_rt_sigreturn
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mmap = SyscallEnterDetails_mmap
  { addr :: CULong
  , len :: CULong
  , prot :: CULong
  , flags :: CULong
  , fd :: CULong
  , off :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_set_thread_area = SyscallEnterDetails_set_thread_area
  { u_info :: Ptr Void {- struct user_desc -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_get_thread_area = SyscallEnterDetails_get_thread_area
  { u_info :: Ptr Void {- struct user_desc -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_vm86old = SyscallEnterDetails_vm86old
  { user_vm86 :: Ptr Void {- struct vm86_struct -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_vm86 = SyscallEnterDetails_vm86
  { cmd :: CULong
  , arg :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ioprio_set = SyscallEnterDetails_ioprio_set
  { which :: CInt
  , who :: CInt
  , ioprio :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ioprio_get = SyscallEnterDetails_ioprio_get
  { which :: CInt
  , who :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getrandom = SyscallEnterDetails_getrandom
  { buf :: Ptr CChar
  , bufBS :: ByteString
  , count :: CSize
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pciconfig_read = SyscallEnterDetails_pciconfig_read
  { bus :: CULong
  , dfn :: CULong
  , off :: CULong
  , len :: CULong
  , buf :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pciconfig_write = SyscallEnterDetails_pciconfig_write
  { bus :: CULong
  , dfn :: CULong
  , off :: CULong
  , len :: CULong
  , buf :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_io_setup = SyscallEnterDetails_io_setup
  { nr_events :: CUInt
  , ctxp :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_io_destroy = SyscallEnterDetails_io_destroy
  { ctx :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_io_submit = SyscallEnterDetails_io_submit
  { ctx_id :: CULong
  , nr :: CLong
  , iocbpp :: Ptr (Ptr Void) {- struct iocb -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_io_cancel = SyscallEnterDetails_io_cancel
  { ctx_id :: CULong
  , iocb :: Ptr Void {- struct iocb -}
  , result :: Ptr Void {- struct io_event -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_io_getevents = SyscallEnterDetails_io_getevents
  { ctx_id :: CULong
  , min_nr :: CLong
  , nr :: CLong
  , events :: Ptr Void {- struct io_event -}
  , timeout :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_io_pgetevents = SyscallEnterDetails_io_pgetevents
  { ctx_id :: CULong
  , min_nr :: CLong
  , nr :: CLong
  , events :: Ptr Void {- struct io_event -}
  , timeout :: Ptr Void {- struct __kernel_timespec -}
  , usig :: Ptr Void {- struct __aio_sigset -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_bdflush = SyscallEnterDetails_bdflush
  { func :: CInt
  , data_ :: CLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getcwd = SyscallEnterDetails_getcwd
  { buf :: Ptr CChar
  , bufBS :: ByteString
  , size :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lookup_dcookie = SyscallEnterDetails_lookup_dcookie
  { cookie64 :: CULong
  , buf :: Ptr CChar
  , bufBS :: ByteString
  , len :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_eventfd2 = SyscallEnterDetails_eventfd2
  { count :: CUInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_eventfd = SyscallEnterDetails_eventfd
  { count :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_epoll_create1 = SyscallEnterDetails_epoll_create1
  { flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_epoll_create = SyscallEnterDetails_epoll_create
  { size :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_epoll_ctl = SyscallEnterDetails_epoll_ctl
  { epfd :: CInt
  , op :: CInt
  , fd :: CInt
  , event :: Ptr Void {- struct epoll_event -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_epoll_wait = SyscallEnterDetails_epoll_wait
  { epfd :: CInt
  , events :: Ptr Void {- struct epoll_event -}
  , maxevents :: CInt
  , timeout :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_epoll_pwait = SyscallEnterDetails_epoll_pwait
  { epfd :: CInt
  , events :: Ptr Void {- struct epoll_event -}
  , maxevents :: CInt
  , timeout :: CInt
  , sigmask :: Ptr CULong
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_uselib = SyscallEnterDetails_uselib
  { library :: Ptr CChar
  , libraryBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_execveat = SyscallEnterDetails_execveat
  { fd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , argv :: Ptr (Ptr CChar)
  , envp :: Ptr (Ptr CChar)
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fcntl = SyscallEnterDetails_fcntl
  { fd :: CUInt
  , cmd :: CUInt
  , arg :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fcntl64 = SyscallEnterDetails_fcntl64
  { fd :: CUInt
  , cmd :: CUInt
  , arg :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_name_to_handle_at = SyscallEnterDetails_name_to_handle_at
  { dfd :: CInt
  , name :: Ptr CChar
  , nameBS :: ByteString
  , handle :: Ptr Void {- struct file_handle -}
  , mnt_id :: Ptr CInt
  , flag :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_open_by_handle_at = SyscallEnterDetails_open_by_handle_at
  { mountdirfd :: CInt
  , handle :: Ptr Void {- struct file_handle -}
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_dup3 = SyscallEnterDetails_dup3
  { oldfd :: CUInt
  , newfd :: CUInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_dup2 = SyscallEnterDetails_dup2
  { oldfd :: CUInt
  , newfd :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_dup = SyscallEnterDetails_dup
  { fildes :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sysfs = SyscallEnterDetails_sysfs
  { option :: CInt
  , arg1 :: CULong
  , arg2 :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ioctl = SyscallEnterDetails_ioctl
  { fd :: CUInt
  , cmd :: CUInt
  , arg :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_flock = SyscallEnterDetails_flock
  { fd :: CUInt
  , cmd :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mknodat = SyscallEnterDetails_mknodat
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , mode :: CMode
  , dev :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mknod = SyscallEnterDetails_mknod
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , mode :: CMode
  , dev :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mkdirat = SyscallEnterDetails_mkdirat
  { dfd :: CInt
  , pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , mode :: CMode
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mkdir = SyscallEnterDetails_mkdir
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , mode :: CMode
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rmdir = SyscallEnterDetails_rmdir
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_unlinkat = SyscallEnterDetails_unlinkat
  { dfd :: CInt
  , pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , flag :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_unlink = SyscallEnterDetails_unlink
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_symlinkat = SyscallEnterDetails_symlinkat
  { oldname :: Ptr CChar
  , oldnameBS :: ByteString
  , newdfd :: CInt
  , newname :: Ptr CChar
  , newnameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_symlink = SyscallEnterDetails_symlink
  { oldname :: Ptr CChar
  , oldnameBS :: ByteString
  , newname :: Ptr CChar
  , newnameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_linkat = SyscallEnterDetails_linkat
  { olddfd :: CInt
  , oldname :: Ptr CChar
  , oldnameBS :: ByteString
  , newdfd :: CInt
  , newname :: Ptr CChar
  , newnameBS :: ByteString
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_link = SyscallEnterDetails_link
  { oldname :: Ptr CChar
  , oldnameBS :: ByteString
  , newname :: Ptr CChar
  , newnameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_umount = SyscallEnterDetails_umount
  { name :: Ptr CChar
  , nameBS :: ByteString
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_oldumount = SyscallEnterDetails_oldumount
  { name :: Ptr CChar
  , nameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mount = SyscallEnterDetails_mount
  { dev_name :: Ptr CChar
  , dev_nameBS :: ByteString
  , dir_name :: Ptr CChar
  , dir_nameBS :: ByteString
  , type_ :: Ptr CChar
  , type_BS :: ByteString
  , flags :: CULong
  , data_ :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pivot_root = SyscallEnterDetails_pivot_root
  { new_root :: Ptr CChar
  , new_rootBS :: ByteString
  , put_old :: Ptr CChar
  , put_oldBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fanotify_init = SyscallEnterDetails_fanotify_init
  { flags :: CUInt
  , event_f_flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fanotify_mark = SyscallEnterDetails_fanotify_mark
  { fanotify_fd :: CInt
  , flags :: CUInt
  , mask :: CULong
  , dfd :: CInt
  , pathname :: Ptr CChar
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_inotify_init1 = SyscallEnterDetails_inotify_init1
  { flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_inotify_init = SyscallEnterDetails_inotify_init
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_inotify_add_watch = SyscallEnterDetails_inotify_add_watch
  { fd :: CInt
  , pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , mask :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_inotify_rm_watch = SyscallEnterDetails_inotify_rm_watch
  { fd :: CInt
  , wd :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_truncate = SyscallEnterDetails_truncate
  { path :: Ptr CChar
  , pathBS :: ByteString
  , length_ :: CLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ftruncate = SyscallEnterDetails_ftruncate
  { fd :: CUInt
  , length_ :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_truncate64 = SyscallEnterDetails_truncate64
  { path :: Ptr CChar
  , pathBS :: ByteString
  , length_ :: CLLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ftruncate64 = SyscallEnterDetails_ftruncate64
  { fd :: CUInt
  , length_ :: CLLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fallocate = SyscallEnterDetails_fallocate
  { fd :: CInt
  , mode :: CInt
  , offset :: CLLong
  , len :: CLLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_chdir = SyscallEnterDetails_chdir
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fchdir = SyscallEnterDetails_fchdir
  { fd :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_chroot = SyscallEnterDetails_chroot
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fchmod = SyscallEnterDetails_fchmod
  { fd :: CUInt
  , mode :: CMode
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fchmodat = SyscallEnterDetails_fchmodat
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , mode :: CMode
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_chmod = SyscallEnterDetails_chmod
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , mode :: CMode
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fchownat = SyscallEnterDetails_fchownat
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , user :: CUInt
  , group :: CUInt
  , flag :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_chown = SyscallEnterDetails_chown
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , user :: CUInt
  , group :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lchown = SyscallEnterDetails_lchown
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , user :: CUInt
  , group :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fchown = SyscallEnterDetails_fchown
  { fd :: CUInt
  , user :: CUInt
  , group :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_vhangup = SyscallEnterDetails_vhangup
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_quotactl = SyscallEnterDetails_quotactl
  { cmd :: CUInt
  , special :: Ptr CChar
  , specialBS :: ByteString
  , id_ :: CUInt
  , addr :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lseek = SyscallEnterDetails_lseek
  { fd :: CUInt
  , offset :: CLong
  , whence :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pread64 = SyscallEnterDetails_pread64
  { fd :: CUInt
  , buf :: Ptr CChar
  , bufBS :: ByteString
  , count :: CSize
  , pos :: CLLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pwrite64 = SyscallEnterDetails_pwrite64
  { fd :: CUInt
  , buf :: Ptr CChar
  , bufBS :: ByteString
  , count :: CSize
  , pos :: CLLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_readv = SyscallEnterDetails_readv
  { fd :: CULong
  , vec :: Ptr Void {- struct iovec -}
  , vlen :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_writev = SyscallEnterDetails_writev
  { fd :: CULong
  , vec :: Ptr Void {- struct iovec -}
  , vlen :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_preadv = SyscallEnterDetails_preadv
  { fd :: CULong
  , vec :: Ptr Void {- struct iovec -}
  , vlen :: CULong
  , pos_l :: CULong
  , pos_h :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_preadv2 = SyscallEnterDetails_preadv2
  { fd :: CULong
  , vec :: Ptr Void {- struct iovec -}
  , vlen :: CULong
  , pos_l :: CULong
  , pos_h :: CULong
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pwritev = SyscallEnterDetails_pwritev
  { fd :: CULong
  , vec :: Ptr Void {- struct iovec -}
  , vlen :: CULong
  , pos_l :: CULong
  , pos_h :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pwritev2 = SyscallEnterDetails_pwritev2
  { fd :: CULong
  , vec :: Ptr Void {- struct iovec -}
  , vlen :: CULong
  , pos_l :: CULong
  , pos_h :: CULong
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sendfile = SyscallEnterDetails_sendfile
  { out_fd :: CInt
  , in_fd :: CInt
  , offset :: Ptr CLong
  , count :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sendfile64 = SyscallEnterDetails_sendfile64
  { out_fd :: CInt
  , in_fd :: CInt
  , offset :: Ptr CLLong
  , count :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_copy_file_range = SyscallEnterDetails_copy_file_range
  { fd_in :: CInt
  , off_in :: Ptr CLLong
  , fd_out :: CInt
  , off_out :: Ptr CLLong
  , len :: CSize
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getdents = SyscallEnterDetails_getdents
  { fd :: CUInt
  , dirent :: Ptr Void {- struct linux_dirent -}
  , count :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getdents64 = SyscallEnterDetails_getdents64
  { fd :: CUInt
  , dirent :: Ptr Void {- struct linux_dirent64 -}
  , count :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_poll = SyscallEnterDetails_poll
  { ufds :: Ptr Void {- struct pollfd -}
  , nfds :: CUInt
  , timeout_msecs :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ppoll = SyscallEnterDetails_ppoll
  { ufds :: Ptr Void {- struct pollfd -}
  , nfds :: CUInt
  , tsp :: Ptr Void {- struct __kernel_timespec -}
  , sigmask :: Ptr CULong
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_signalfd4 = SyscallEnterDetails_signalfd4
  { ufd :: CInt
  , user_mask :: Ptr CULong
  , sizemask :: CSize
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_signalfd = SyscallEnterDetails_signalfd
  { ufd :: CInt
  , user_mask :: Ptr CULong
  , sizemask :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_vmsplice = SyscallEnterDetails_vmsplice
  { fd :: CInt
  , uiov :: Ptr Void {- struct iovec -}
  , nr_segs :: CULong
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_splice = SyscallEnterDetails_splice
  { fd_in :: CInt
  , off_in :: Ptr CLLong
  , fd_out :: CInt
  , off_out :: Ptr CLLong
  , len :: CSize
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_tee = SyscallEnterDetails_tee
  { fdin :: CInt
  , fdout :: CInt
  , len :: CSize
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_readlinkat = SyscallEnterDetails_readlinkat
  { dfd :: CInt
  , pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , buf :: Ptr CChar
  , bufBS :: ByteString
  , bufsiz :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_readlink = SyscallEnterDetails_readlink
  { path :: Ptr CChar
  , pathBS :: ByteString
  , buf :: Ptr CChar
  , bufBS :: ByteString
  , bufsiz :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_stat64 = SyscallEnterDetails_stat64
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , statbuf :: Ptr Void {- struct stat64 -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lstat64 = SyscallEnterDetails_lstat64
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , statbuf :: Ptr Void {- struct stat64 -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fstat64 = SyscallEnterDetails_fstat64
  { fd :: CULong
  , statbuf :: Ptr Void {- struct stat64 -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fstatat64 = SyscallEnterDetails_fstatat64
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , statbuf :: Ptr Void {- struct stat64 -}
  , flag :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_statx = SyscallEnterDetails_statx
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , flags :: CUInt
  , mask :: CUInt
  , buffer :: Ptr Void {- struct statx -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_statfs = SyscallEnterDetails_statfs
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , buf :: Ptr Void {- struct statfs -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_statfs64 = SyscallEnterDetails_statfs64
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , sz :: CSize
  , buf :: Ptr Void {- struct statfs64 -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fstatfs = SyscallEnterDetails_fstatfs
  { fd :: CUInt
  , buf :: Ptr Void {- struct statfs -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fstatfs64 = SyscallEnterDetails_fstatfs64
  { fd :: CUInt
  , sz :: CSize
  , buf :: Ptr Void {- struct statfs64 -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ustat = SyscallEnterDetails_ustat
  { dev :: CUInt
  , ubuf :: Ptr Void {- struct ustat -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sync = SyscallEnterDetails_sync
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_syncfs = SyscallEnterDetails_syncfs
  { fd :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fsync = SyscallEnterDetails_fsync
  { fd :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fdatasync = SyscallEnterDetails_fdatasync
  { fd :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sync_file_range = SyscallEnterDetails_sync_file_range
  { fd :: CInt
  , offset :: CLLong
  , nbytes :: CLLong
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sync_file_range2 = SyscallEnterDetails_sync_file_range2
  { fd :: CInt
  , flags :: CUInt
  , offset :: CLLong
  , nbytes :: CLLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timerfd_create = SyscallEnterDetails_timerfd_create
  { clockid :: CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timerfd_settime = SyscallEnterDetails_timerfd_settime
  { ufd :: CInt
  , flags :: CInt
  , utmr :: Ptr Void {- struct __kernel_itimerspec -}
  , otmr :: Ptr Void {- struct __kernel_itimerspec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timerfd_gettime = SyscallEnterDetails_timerfd_gettime
  { ufd :: CInt
  , otmr :: Ptr Void {- struct __kernel_itimerspec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_userfaultfd = SyscallEnterDetails_userfaultfd
  { flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_utimensat = SyscallEnterDetails_utimensat
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , utimes :: Ptr Void {- struct __kernel_timespec -}
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_futimesat = SyscallEnterDetails_futimesat
  { dfd :: CInt
  , filename :: Ptr CChar
  , filenameBS :: ByteString
  , utimes :: Ptr Void {- struct timeval -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_utimes = SyscallEnterDetails_utimes
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , utimes :: Ptr Void {- struct timeval -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_utime = SyscallEnterDetails_utime
  { filename :: Ptr CChar
  , filenameBS :: ByteString
  , times :: Ptr Void {- struct utimbuf -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setxattr = SyscallEnterDetails_setxattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , name :: Ptr CChar
  , nameBS :: ByteString
  , value :: Ptr Void
  , size :: CSize
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lsetxattr = SyscallEnterDetails_lsetxattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , name :: Ptr CChar
  , nameBS :: ByteString
  , value :: Ptr Void
  , size :: CSize
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fsetxattr = SyscallEnterDetails_fsetxattr
  { fd :: CInt
  , name :: Ptr CChar
  , nameBS :: ByteString
  , value :: Ptr Void
  , size :: CSize
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getxattr = SyscallEnterDetails_getxattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , name :: Ptr CChar
  , nameBS :: ByteString
  , value :: Ptr Void
  , size :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lgetxattr = SyscallEnterDetails_lgetxattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , name :: Ptr CChar
  , nameBS :: ByteString
  , value :: Ptr Void
  , size :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fgetxattr = SyscallEnterDetails_fgetxattr
  { fd :: CInt
  , name :: Ptr CChar
  , nameBS :: ByteString
  , value :: Ptr Void
  , size :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_listxattr = SyscallEnterDetails_listxattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , list :: Ptr CChar
  , listBS :: ByteString
  , size :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_llistxattr = SyscallEnterDetails_llistxattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , list :: Ptr CChar
  , listBS :: ByteString
  , size :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_flistxattr = SyscallEnterDetails_flistxattr
  { fd :: CInt
  , list :: Ptr CChar
  , listBS :: ByteString
  , size :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_removexattr = SyscallEnterDetails_removexattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , name :: Ptr CChar
  , nameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_lremovexattr = SyscallEnterDetails_lremovexattr
  { pathname :: Ptr CChar
  , pathnameBS :: ByteString
  , name :: Ptr CChar
  , nameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fremovexattr = SyscallEnterDetails_fremovexattr
  { fd :: CInt
  , name :: Ptr CChar
  , nameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_msgget = SyscallEnterDetails_msgget
  { key :: CInt
  , msgflg :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_msgctl = SyscallEnterDetails_msgctl
  { msqid :: CInt
  , cmd :: CInt
  , buf :: Ptr Void {- struct msqid_ds -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_msgsnd = SyscallEnterDetails_msgsnd
  { msqid :: CInt
  , msgp :: Ptr Void {- struct msgbuf -}
  , msgsz :: CSize
  , msgflg :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_msgrcv = SyscallEnterDetails_msgrcv
  { msqid :: CInt
  , msgp :: Ptr Void {- struct msgbuf -}
  , msgsz :: CSize
  , msgtyp :: CLong
  , msgflg :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_semget = SyscallEnterDetails_semget
  { key :: CInt
  , nsems :: CInt
  , semflg :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_semctl = SyscallEnterDetails_semctl
  { semid :: CInt
  , semnum :: CInt
  , cmd :: CInt
  , arg :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_semtimedop = SyscallEnterDetails_semtimedop
  { semid :: CInt
  , tsops :: Ptr Void {- struct sembuf -}
  , nsops :: CUInt
  , timeout :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_semop = SyscallEnterDetails_semop
  { semid :: CInt
  , tsops :: Ptr Void {- struct sembuf -}
  , nsops :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_shmget = SyscallEnterDetails_shmget
  { key :: CInt
  , size :: CSize
  , shmflg :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_shmctl = SyscallEnterDetails_shmctl
  { shmid :: CInt
  , cmd :: CInt
  , buf :: Ptr Void {- struct shmid_ds -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_shmat = SyscallEnterDetails_shmat
  { shmid :: CInt
  , shmaddr :: Ptr CChar
  , shmaddrBS :: ByteString
  , shmflg :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_shmdt = SyscallEnterDetails_shmdt
  { shmaddr :: Ptr CChar
  , shmaddrBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ipc = SyscallEnterDetails_ipc
  { call :: CUInt
  , first_ :: CInt
  , second_ :: CULong
  , third :: CULong
  , ptr :: Ptr Void
  , fifth :: CLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_acct = SyscallEnterDetails_acct
  { name :: Ptr CChar
  , nameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_perf_event_open = SyscallEnterDetails_perf_event_open
  { attr_uptr :: Ptr Void {- struct perf_event_attr -}
  , pid_ :: CUInt
  , cpu :: CInt
  , group_fd :: CInt
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_personality = SyscallEnterDetails_personality
  { personality :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_waitid = SyscallEnterDetails_waitid
  { which :: CInt
  , upid :: CUInt
  , infop :: Ptr Void {- struct siginfo -}
  , options :: CInt
  , ru :: Ptr Void {- struct rusage -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_wait4 = SyscallEnterDetails_wait4
  { upid :: CUInt
  , stat_addr :: Ptr CInt
  , options :: CInt
  , ru :: Ptr Void {- struct rusage -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_waitpid = SyscallEnterDetails_waitpid
  { pid_ :: CUInt
  , stat_addr :: Ptr CInt
  , options :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_set_tid_address = SyscallEnterDetails_set_tid_address
  { tidptr :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fork = SyscallEnterDetails_fork
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_vfork = SyscallEnterDetails_vfork
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_clone = SyscallEnterDetails_clone
  { clone_flags :: CULong
  , newsp :: CULong
  , parent_tidptr :: Ptr CInt
  , child_tidptr :: Ptr CInt
  , tls :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_unshare = SyscallEnterDetails_unshare
  { unshare_flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_set_robust_list = SyscallEnterDetails_set_robust_list
  { head_ :: Ptr Void {- struct robust_list_head -}
  , len :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_get_robust_list = SyscallEnterDetails_get_robust_list
  { pid_ :: CInt
  , head_ptr :: Ptr (Ptr Void) {- struct robust_list_head -}
  , len_ptr :: Ptr CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_futex = SyscallEnterDetails_futex
  { uaddr :: Ptr CUInt
  , op :: CInt
  , val :: CUInt
  , utime :: Ptr Void {- struct __kernel_timespec -}
  , uaddr2 :: Ptr CUInt
  , val3 :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getgroups = SyscallEnterDetails_getgroups
  { gidsetsize :: CInt
  , grouplist :: Ptr CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setgroups = SyscallEnterDetails_setgroups
  { gidsetsize :: CInt
  , grouplist :: Ptr CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_kcmp = SyscallEnterDetails_kcmp
  { pid1 :: CUInt
  , pid2 :: CUInt
  , type_ :: CInt
  , idx1 :: CULong
  , idx2 :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_kexec_load = SyscallEnterDetails_kexec_load
  { entry :: CULong
  , nr_segments :: CULong
  , segments :: Ptr Void {- struct kexec_segment -}
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_kexec_file_load = SyscallEnterDetails_kexec_file_load
  { kernel_fd :: CInt
  , initrd_fd :: CInt
  , cmdline_len :: CULong
  , cmdline_ptr :: Ptr CChar
  , cmdline_ptrBS :: ByteString
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_delete_module = SyscallEnterDetails_delete_module
  { name_user :: Ptr CChar
  , name_userBS :: ByteString
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_init_module = SyscallEnterDetails_init_module
  { umod :: Ptr Void
  , len :: CULong
  , uargs :: Ptr CChar
  , uargsBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_finit_module = SyscallEnterDetails_finit_module
  { fd :: CInt
  , uargs :: Ptr CChar
  , uargsBS :: ByteString
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setns = SyscallEnterDetails_setns
  { fd :: CInt
  , nstype :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_syslog = SyscallEnterDetails_syslog
  { type_ :: CInt
  , buf :: Ptr CChar
  , bufBS :: ByteString
  , len :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ptrace = SyscallEnterDetails_ptrace
  { request :: CLong
  , pid_ :: CLong
  , addr :: CULong
  , data_ :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_reboot = SyscallEnterDetails_reboot
  { magic1 :: CInt
  , magic2 :: CInt
  , cmd :: CUInt
  , arg :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rseq = SyscallEnterDetails_rseq
  { rseq :: Ptr Void {- struct rseq -}
  , rseq_len :: CUInt
  , flags :: CInt
  , sig :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_nice = SyscallEnterDetails_nice
  { increment :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_setscheduler = SyscallEnterDetails_sched_setscheduler
  { pid_ :: CUInt
  , policy :: CInt
  , param :: Ptr Void {- struct sched_param -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_setparam = SyscallEnterDetails_sched_setparam
  { pid_ :: CUInt
  , param :: Ptr Void {- struct sched_param -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_setattr = SyscallEnterDetails_sched_setattr
  { pid_ :: CUInt
  , uattr :: Ptr Void {- struct sched_attr -}
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_getscheduler = SyscallEnterDetails_sched_getscheduler
  { pid_ :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_getparam = SyscallEnterDetails_sched_getparam
  { pid_ :: CUInt
  , param :: Ptr Void {- struct sched_param -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_getattr = SyscallEnterDetails_sched_getattr
  { pid_ :: CUInt
  , uattr :: Ptr Void {- struct sched_attr -}
  , size :: CUInt
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_setaffinity = SyscallEnterDetails_sched_setaffinity
  { pid_ :: CUInt
  , len :: CUInt
  , user_mask_ptr :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_getaffinity = SyscallEnterDetails_sched_getaffinity
  { pid_ :: CUInt
  , len :: CUInt
  , user_mask_ptr :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_yield = SyscallEnterDetails_sched_yield
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_get_priority_max = SyscallEnterDetails_sched_get_priority_max
  { policy :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_get_priority_min = SyscallEnterDetails_sched_get_priority_min
  { policy :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sched_rr_get_interval = SyscallEnterDetails_sched_rr_get_interval
  { pid_ :: CUInt
  , interval :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_membarrier = SyscallEnterDetails_membarrier
  { cmd :: CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_seccomp = SyscallEnterDetails_seccomp
  { op :: CUInt
  , flags :: CUInt
  , uargs :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_restart_syscall = SyscallEnterDetails_restart_syscall
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigprocmask = SyscallEnterDetails_rt_sigprocmask
  { how :: CInt
  , nset :: Ptr CULong
  , oset :: Ptr CULong
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigpending = SyscallEnterDetails_rt_sigpending
  { uset :: Ptr CULong
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_kill = SyscallEnterDetails_kill
  { pid_ :: CUInt
  , sig :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_tgkill = SyscallEnterDetails_tgkill
  { tgid :: CUInt
  , pid_ :: CUInt
  , sig :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_tkill = SyscallEnterDetails_tkill
  { pid_ :: CUInt
  , sig :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sigpending = SyscallEnterDetails_sigpending
  { uset :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sigprocmask = SyscallEnterDetails_sigprocmask
  { how :: CInt
  , nset :: Ptr CULong
  , oset :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigaction = SyscallEnterDetails_rt_sigaction
  { sig :: CInt
  , act :: Ptr Void {- struct sigaction -}
  , oact :: Ptr Void {- struct sigaction -}
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sigaction = SyscallEnterDetails_sigaction
  { sig :: CInt
  , act :: Ptr Void {- struct old_sigaction -}
  , oact :: Ptr Void {- struct old_sigaction -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sgetmask = SyscallEnterDetails_sgetmask
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_ssetmask = SyscallEnterDetails_ssetmask
  { newmask :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_signal = SyscallEnterDetails_signal
  { sig :: CInt
  , handler :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pause = SyscallEnterDetails_pause
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigsuspend = SyscallEnterDetails_rt_sigsuspend
  { unewset :: Ptr CULong
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sigsuspend = SyscallEnterDetails_sigsuspend
  { mask :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setpriority = SyscallEnterDetails_setpriority
  { which :: CInt
  , who :: CInt
  , niceval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getpriority = SyscallEnterDetails_getpriority
  { which :: CInt
  , who :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setregid = SyscallEnterDetails_setregid
  { rgid :: CUInt
  , egid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setgid = SyscallEnterDetails_setgid
  { gid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setreuid = SyscallEnterDetails_setreuid
  { ruid :: CUInt
  , euid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setuid = SyscallEnterDetails_setuid
  { uid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setresuid = SyscallEnterDetails_setresuid
  { ruid :: CUInt
  , euid :: CUInt
  , suid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getresuid = SyscallEnterDetails_getresuid
  { ruidp :: Ptr CUInt
  , euidp :: Ptr CUInt
  , suidp :: Ptr CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setresgid = SyscallEnterDetails_setresgid
  { rgid :: CUInt
  , egid :: CUInt
  , sgid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getresgid = SyscallEnterDetails_getresgid
  { rgidp :: Ptr CUInt
  , egidp :: Ptr CUInt
  , sgidp :: Ptr CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setfsuid = SyscallEnterDetails_setfsuid
  { uid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setfsgid = SyscallEnterDetails_setfsgid
  { gid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getpid = SyscallEnterDetails_getpid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_gettid = SyscallEnterDetails_gettid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getppid = SyscallEnterDetails_getppid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getuid = SyscallEnterDetails_getuid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_geteuid = SyscallEnterDetails_geteuid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getgid = SyscallEnterDetails_getgid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getegid = SyscallEnterDetails_getegid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_times = SyscallEnterDetails_times
  { tbuf :: Ptr Void {- struct tms -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setpgid = SyscallEnterDetails_setpgid
  { pid_ :: CUInt
  , pgid :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getpgid = SyscallEnterDetails_getpgid
  { pid_ :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getpgrp = SyscallEnterDetails_getpgrp
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getsid = SyscallEnterDetails_getsid
  { pid_ :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setsid = SyscallEnterDetails_setsid
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_uname = SyscallEnterDetails_uname
  { name :: Ptr Void {- struct old_utsname -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_olduname = SyscallEnterDetails_olduname
  { name :: Ptr Void {- struct oldold_utsname -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sethostname = SyscallEnterDetails_sethostname
  { name :: Ptr CChar
  , nameBS :: ByteString
  , len :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_gethostname = SyscallEnterDetails_gethostname
  { name :: Ptr CChar
  , nameBS :: ByteString
  , len :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setdomainname = SyscallEnterDetails_setdomainname
  { name :: Ptr CChar
  , nameBS :: ByteString
  , len :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getrlimit = SyscallEnterDetails_getrlimit
  { resource :: CUInt
  , rlim :: Ptr Void {- struct rlimit -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_prlimit64 = SyscallEnterDetails_prlimit64
  { pid_ :: CUInt
  , resource :: CUInt
  , new_rlim :: Ptr Void {- struct rlimit64 -}
  , old_rlim :: Ptr Void {- struct rlimit64 -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setrlimit = SyscallEnterDetails_setrlimit
  { resource :: CUInt
  , rlim :: Ptr Void {- struct rlimit -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getrusage = SyscallEnterDetails_getrusage
  { who :: CInt
  , ru :: Ptr Void {- struct rusage -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_umask = SyscallEnterDetails_umask
  { mask :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_prctl = SyscallEnterDetails_prctl
  { option :: CInt
  , arg2 :: CULong
  , arg3 :: CULong
  , arg4 :: CULong
  , arg5 :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getcpu = SyscallEnterDetails_getcpu
  { cpup :: Ptr CUInt
  , nodep :: Ptr CUInt
  , unused :: Ptr Void {- struct getcpu_cache -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sysinfo = SyscallEnterDetails_sysinfo
  { info :: Ptr Void {- struct sysinfo -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_nanosleep = SyscallEnterDetails_nanosleep
  { rqtp :: Ptr Void {- struct __kernel_timespec -}
  , rmtp :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getitimer = SyscallEnterDetails_getitimer
  { which :: CInt
  , value :: Ptr Void {- struct itimerval -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_alarm = SyscallEnterDetails_alarm
  { seconds :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setitimer = SyscallEnterDetails_setitimer
  { which :: CInt
  , value :: Ptr Void {- struct itimerval -}
  , ovalue :: Ptr Void {- struct itimerval -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_clock_settime = SyscallEnterDetails_clock_settime
  { which_clock :: CInt
  , tp :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_clock_gettime = SyscallEnterDetails_clock_gettime
  { which_clock :: CInt
  , tp :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_clock_getres = SyscallEnterDetails_clock_getres
  { which_clock :: CInt
  , tp :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_clock_nanosleep = SyscallEnterDetails_clock_nanosleep
  { which_clock :: CInt
  , flags :: CInt
  , rqtp :: Ptr Void {- struct __kernel_timespec -}
  , rmtp :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timer_create = SyscallEnterDetails_timer_create
  { which_clock :: CInt
  , timer_event_spec :: Ptr Void {- struct sigevent -}
  , created_timer_id :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timer_gettime = SyscallEnterDetails_timer_gettime
  { timer_id :: CInt
  , setting :: Ptr Void {- struct __kernel_itimerspec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timer_getoverrun = SyscallEnterDetails_timer_getoverrun
  { timer_id :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timer_settime = SyscallEnterDetails_timer_settime
  { timer_id :: CInt
  , flags :: CInt
  , new_setting :: Ptr Void {- struct __kernel_itimerspec -}
  , old_setting :: Ptr Void {- struct __kernel_itimerspec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_timer_delete = SyscallEnterDetails_timer_delete
  { timer_id :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_clock_adjtime = SyscallEnterDetails_clock_adjtime
  { which_clock :: CInt
  , utx :: Ptr Void {- struct __kernel_timex -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_time = SyscallEnterDetails_time
  { tloc :: Ptr CLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_stime = SyscallEnterDetails_stime
  { tptr :: Ptr CLong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_gettimeofday = SyscallEnterDetails_gettimeofday
  { tv :: Ptr Void {- struct timeval -}
  , tz :: Ptr Void {- struct timezone -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_settimeofday = SyscallEnterDetails_settimeofday
  { tv :: Ptr Void {- struct timeval -}
  , tz :: Ptr Void {- struct timezone -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_adjtimex = SyscallEnterDetails_adjtimex
  { txc_p :: Ptr Void {- struct __kernel_timex -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fadvise64_64 = SyscallEnterDetails_fadvise64_64
  { fd :: CInt
  , offset :: CLLong
  , len :: CLLong
  , advice :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_fadvise64 = SyscallEnterDetails_fadvise64
  { fd :: CInt
  , offset :: CLLong
  , len :: CSize
  , advice :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_madvise = SyscallEnterDetails_madvise
  { start :: CULong
  , len_in :: CSize
  , behavior :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_memfd_create = SyscallEnterDetails_memfd_create
  { uname :: Ptr CChar
  , unameBS :: ByteString
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mbind = SyscallEnterDetails_mbind
  { start :: CULong
  , len :: CULong
  , mode :: CULong
  , nmask :: Ptr CULong
  , maxnode :: CULong
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_set_mempolicy = SyscallEnterDetails_set_mempolicy
  { mode :: CInt
  , nmask :: Ptr CULong
  , maxnode :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_migrate_pages = SyscallEnterDetails_migrate_pages
  { pid_ :: CUInt
  , maxnode :: CULong
  , old_nodes :: Ptr CULong
  , new_nodes :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_get_mempolicy = SyscallEnterDetails_get_mempolicy
  { policy :: Ptr CInt
  , nmask :: Ptr CULong
  , maxnode :: CULong
  , addr :: CULong
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_move_pages = SyscallEnterDetails_move_pages
  { pid_ :: CUInt
  , nr_pages :: CULong
  , pages :: Ptr (Ptr Void)
  , nodes :: Ptr CInt
  , status :: Ptr CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mincore = SyscallEnterDetails_mincore
  { start :: CULong
  , len :: CSize
  , vec :: Ptr CUChar
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mlock = SyscallEnterDetails_mlock
  { start :: CULong
  , len :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mlock2 = SyscallEnterDetails_mlock2
  { start :: CULong
  , len :: CSize
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_munlock = SyscallEnterDetails_munlock
  { start :: CULong
  , len :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mlockall = SyscallEnterDetails_mlockall
  { flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_munlockall = SyscallEnterDetails_munlockall
  { 
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_brk = SyscallEnterDetails_brk
  { brk :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_munmap = SyscallEnterDetails_munmap
  { addr :: CULong
  , len :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_remap_file_pages = SyscallEnterDetails_remap_file_pages
  { start :: CULong
  , size :: CULong
  , prot :: CULong
  , pgoff :: CULong
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mprotect = SyscallEnterDetails_mprotect
  { start :: CULong
  , len :: CSize
  , prot :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pkey_mprotect = SyscallEnterDetails_pkey_mprotect
  { start :: CULong
  , len :: CSize
  , prot :: CULong
  , pkey :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pkey_alloc = SyscallEnterDetails_pkey_alloc
  { flags :: CULong
  , init_val :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pkey_free = SyscallEnterDetails_pkey_free
  { pkey :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mremap = SyscallEnterDetails_mremap
  { addr :: CULong
  , old_len :: CULong
  , new_len :: CULong
  , flags :: CULong
  , new_addr :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_msync = SyscallEnterDetails_msync
  { start :: CULong
  , len :: CSize
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_process_vm_readv = SyscallEnterDetails_process_vm_readv
  { pid_ :: CUInt
  , lvec :: Ptr Void {- struct iovec -}
  , liovcnt :: CULong
  , rvec :: Ptr Void {- struct iovec -}
  , riovcnt :: CULong
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_process_vm_writev = SyscallEnterDetails_process_vm_writev
  { pid_ :: CUInt
  , lvec :: Ptr Void {- struct iovec -}
  , liovcnt :: CULong
  , rvec :: Ptr Void {- struct iovec -}
  , riovcnt :: CULong
  , flags :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_readahead = SyscallEnterDetails_readahead
  { fd :: CInt
  , offset :: CLLong
  , count :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_swapoff = SyscallEnterDetails_swapoff
  { specialfile :: Ptr CChar
  , specialfileBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_swapon = SyscallEnterDetails_swapon
  { specialfile :: Ptr CChar
  , specialfileBS :: ByteString
  , swap_flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_socket = SyscallEnterDetails_socket
  { family :: CInt
  , type_ :: CInt
  , protocol :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_socketpair = SyscallEnterDetails_socketpair
  { family :: CInt
  , type_ :: CInt
  , protocol :: CInt
  , usockvec :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_bind = SyscallEnterDetails_bind
  { fd :: CInt
  , umyaddr :: Ptr Void {- struct sockaddr -}
  , addrlen :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_listen = SyscallEnterDetails_listen
  { fd :: CInt
  , backlog :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_accept4 = SyscallEnterDetails_accept4
  { fd :: CInt
  , upeer_sockaddr :: Ptr Void {- struct sockaddr -}
  , upeer_addrlen :: Ptr CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_accept = SyscallEnterDetails_accept
  { fd :: CInt
  , upeer_sockaddr :: Ptr Void {- struct sockaddr -}
  , upeer_addrlen :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_connect = SyscallEnterDetails_connect
  { fd :: CInt
  , uservaddr :: Ptr Void {- struct sockaddr -}
  , addrlen :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getsockname = SyscallEnterDetails_getsockname
  { fd :: CInt
  , usockaddr :: Ptr Void {- struct sockaddr -}
  , usockaddr_len :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getpeername = SyscallEnterDetails_getpeername
  { fd :: CInt
  , usockaddr :: Ptr Void {- struct sockaddr -}
  , usockaddr_len :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sendto = SyscallEnterDetails_sendto
  { fd :: CInt
  , buff :: Ptr Void
  , len :: CSize
  , flags :: CUInt
  , addr :: Ptr Void {- struct sockaddr -}
  , addr_len :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_send = SyscallEnterDetails_send
  { fd :: CInt
  , buff :: Ptr Void
  , len :: CSize
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_recvfrom = SyscallEnterDetails_recvfrom
  { fd :: CInt
  , ubuf :: Ptr Void
  , size :: CSize
  , flags :: CUInt
  , addr :: Ptr Void {- struct sockaddr -}
  , addr_len :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_recv = SyscallEnterDetails_recv
  { fd :: CInt
  , ubuf :: Ptr Void
  , size :: CSize
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_setsockopt = SyscallEnterDetails_setsockopt
  { fd :: CInt
  , level :: CInt
  , optname :: CInt
  , optval :: Ptr CChar
  , optvalBS :: ByteString
  , optlen :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_getsockopt = SyscallEnterDetails_getsockopt
  { fd :: CInt
  , level :: CInt
  , optname :: CInt
  , optval :: Ptr CChar
  , optvalBS :: ByteString
  , optlen :: Ptr CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_shutdown = SyscallEnterDetails_shutdown
  { fd :: CInt
  , how :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sendmsg = SyscallEnterDetails_sendmsg
  { fd :: CInt
  , msg :: Ptr Void {- struct user_msghdr -}
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sendmmsg = SyscallEnterDetails_sendmmsg
  { fd :: CInt
  , mmsg :: Ptr Void {- struct mmsghdr -}
  , vlen :: CUInt
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_recvmsg = SyscallEnterDetails_recvmsg
  { fd :: CInt
  , msg :: Ptr Void {- struct user_msghdr -}
  , flags :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_recvmmsg = SyscallEnterDetails_recvmmsg
  { fd :: CInt
  , mmsg :: Ptr Void {- struct mmsghdr -}
  , vlen :: CUInt
  , flags :: CUInt
  , timeout :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_socketcall = SyscallEnterDetails_socketcall
  { call :: CInt
  , args :: Ptr CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_add_key = SyscallEnterDetails_add_key
  { _type :: Ptr CChar
  , _typeBS :: ByteString
  , _description :: Ptr CChar
  , _descriptionBS :: ByteString
  , _payload :: Ptr Void
  , plen :: CSize
  , ringid :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_request_key = SyscallEnterDetails_request_key
  { _type :: Ptr CChar
  , _typeBS :: ByteString
  , _description :: Ptr CChar
  , _descriptionBS :: ByteString
  , _callout_info :: Ptr CChar
  , _callout_infoBS :: ByteString
  , destringid :: CInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_keyctl = SyscallEnterDetails_keyctl
  { option :: CInt
  , arg2 :: CULong
  , arg3 :: CULong
  , arg4 :: CULong
  , arg5 :: CULong
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_select = SyscallEnterDetails_select
  { n :: CInt
  , inp :: Ptr Void
  , outp :: Ptr Void
  , exp_ :: Ptr Void
  , tvp :: Ptr Void {- struct timeval -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_pselect6 = SyscallEnterDetails_pselect6
  { n :: CInt
  , inp :: Ptr Void
  , outp :: Ptr Void
  , exp_ :: Ptr Void
  , tsp :: Ptr Void {- struct __kernel_timespec -}
  , sig :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mq_open = SyscallEnterDetails_mq_open
  { u_name :: Ptr CChar
  , u_nameBS :: ByteString
  , oflag :: CInt
  , mode :: CMode
  , u_attr :: Ptr Void {- struct mq_attr -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mq_unlink = SyscallEnterDetails_mq_unlink
  { u_name :: Ptr CChar
  , u_nameBS :: ByteString
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_bpf = SyscallEnterDetails_bpf
  { cmd :: CInt
  , uattr :: Ptr Void
  , size :: CUInt
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_capget = SyscallEnterDetails_capget
  { header :: Ptr Void
  , dataptr :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_capset = SyscallEnterDetails_capset
  { header :: Ptr Void
  , data_ :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigtimedwait = SyscallEnterDetails_rt_sigtimedwait
  { uthese :: Ptr CULong
  , uinfo :: Ptr Void
  , uts :: Ptr Void {- struct __kernel_timespec -}
  , sigsetsize :: CSize
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_sigqueueinfo = SyscallEnterDetails_rt_sigqueueinfo
  { pid_ :: CUInt
  , sig :: CInt
  , uinfo :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_rt_tgsigqueueinfo = SyscallEnterDetails_rt_tgsigqueueinfo
  { tgid :: CUInt
  , pid_ :: CUInt
  , sig :: CInt
  , uinfo :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_sigaltstack = SyscallEnterDetails_sigaltstack
  { uss :: Ptr Void
  , uoss :: Ptr Void
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mq_timedsend = SyscallEnterDetails_mq_timedsend
  { mqdes :: CInt
  , u_msg_ptr :: Ptr CChar
  , u_msg_ptrBS :: ByteString
  , msg_len :: CSize
  , msg_prio :: CUInt
  , u_abs_timeout :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mq_timedreceive = SyscallEnterDetails_mq_timedreceive
  { mqdes :: CInt
  , u_msg_ptr :: Ptr CChar
  , u_msg_ptrBS :: ByteString
  , msg_len :: CSize
  , u_msg_prio :: Ptr CUInt
  , u_abs_timeout :: Ptr Void {- struct __kernel_timespec -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mq_notify = SyscallEnterDetails_mq_notify
  { mqdes :: CInt
  , u_notification :: Ptr Void {- struct sigevent -}
  } deriving (Eq, Ord, Show)
data SyscallEnterDetails_mq_getsetattr = SyscallEnterDetails_mq_getsetattr
  { mqdes :: CInt
  , u_mqstat :: Ptr Void {- struct mq_attr -}
  , u_omqstat :: Ptr Void {- struct mq_attr -}
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_ioperm = SyscallExitDetails_ioperm
  { enterDetail :: SyscallEnterDetails_ioperm
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_iopl = SyscallExitDetails_iopl
  { enterDetail :: SyscallEnterDetails_iopl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_modify_ldt = SyscallExitDetails_modify_ldt
  { enterDetail :: SyscallEnterDetails_modify_ldt
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_arch_prctl = SyscallExitDetails_arch_prctl
  { enterDetail :: SyscallEnterDetails_arch_prctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sigreturn = SyscallExitDetails_sigreturn
  { enterDetail :: SyscallEnterDetails_sigreturn
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigreturn = SyscallExitDetails_rt_sigreturn
  { enterDetail :: SyscallEnterDetails_rt_sigreturn
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mmap = SyscallExitDetails_mmap
  { enterDetail :: SyscallEnterDetails_mmap
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_set_thread_area = SyscallExitDetails_set_thread_area
  { enterDetail :: SyscallEnterDetails_set_thread_area
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_get_thread_area = SyscallExitDetails_get_thread_area
  { enterDetail :: SyscallEnterDetails_get_thread_area
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_vm86old = SyscallExitDetails_vm86old
  { enterDetail :: SyscallEnterDetails_vm86old
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_vm86 = SyscallExitDetails_vm86
  { enterDetail :: SyscallEnterDetails_vm86
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ioprio_set = SyscallExitDetails_ioprio_set
  { enterDetail :: SyscallEnterDetails_ioprio_set
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ioprio_get = SyscallExitDetails_ioprio_get
  { enterDetail :: SyscallEnterDetails_ioprio_get
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getrandom = SyscallExitDetails_getrandom
  { enterDetail :: SyscallEnterDetails_getrandom
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pciconfig_read = SyscallExitDetails_pciconfig_read
  { enterDetail :: SyscallEnterDetails_pciconfig_read
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pciconfig_write = SyscallExitDetails_pciconfig_write
  { enterDetail :: SyscallEnterDetails_pciconfig_write
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_io_setup = SyscallExitDetails_io_setup
  { enterDetail :: SyscallEnterDetails_io_setup
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_io_destroy = SyscallExitDetails_io_destroy
  { enterDetail :: SyscallEnterDetails_io_destroy
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_io_submit = SyscallExitDetails_io_submit
  { enterDetail :: SyscallEnterDetails_io_submit
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_io_cancel = SyscallExitDetails_io_cancel
  { enterDetail :: SyscallEnterDetails_io_cancel
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_io_getevents = SyscallExitDetails_io_getevents
  { enterDetail :: SyscallEnterDetails_io_getevents
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_io_pgetevents = SyscallExitDetails_io_pgetevents
  { enterDetail :: SyscallEnterDetails_io_pgetevents
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_bdflush = SyscallExitDetails_bdflush
  { enterDetail :: SyscallEnterDetails_bdflush
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getcwd = SyscallExitDetails_getcwd
  { enterDetail :: SyscallEnterDetails_getcwd
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lookup_dcookie = SyscallExitDetails_lookup_dcookie
  { enterDetail :: SyscallEnterDetails_lookup_dcookie
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_eventfd2 = SyscallExitDetails_eventfd2
  { enterDetail :: SyscallEnterDetails_eventfd2
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_eventfd = SyscallExitDetails_eventfd
  { enterDetail :: SyscallEnterDetails_eventfd
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_epoll_create1 = SyscallExitDetails_epoll_create1
  { enterDetail :: SyscallEnterDetails_epoll_create1
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_epoll_create = SyscallExitDetails_epoll_create
  { enterDetail :: SyscallEnterDetails_epoll_create
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_epoll_ctl = SyscallExitDetails_epoll_ctl
  { enterDetail :: SyscallEnterDetails_epoll_ctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_epoll_wait = SyscallExitDetails_epoll_wait
  { enterDetail :: SyscallEnterDetails_epoll_wait
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_epoll_pwait = SyscallExitDetails_epoll_pwait
  { enterDetail :: SyscallEnterDetails_epoll_pwait
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_uselib = SyscallExitDetails_uselib
  { enterDetail :: SyscallEnterDetails_uselib
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_execveat = SyscallExitDetails_execveat
  { enterDetail :: SyscallEnterDetails_execveat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fcntl = SyscallExitDetails_fcntl
  { enterDetail :: SyscallEnterDetails_fcntl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fcntl64 = SyscallExitDetails_fcntl64
  { enterDetail :: SyscallEnterDetails_fcntl64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_name_to_handle_at = SyscallExitDetails_name_to_handle_at
  { enterDetail :: SyscallEnterDetails_name_to_handle_at
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_open_by_handle_at = SyscallExitDetails_open_by_handle_at
  { enterDetail :: SyscallEnterDetails_open_by_handle_at
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_dup3 = SyscallExitDetails_dup3
  { enterDetail :: SyscallEnterDetails_dup3
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_dup2 = SyscallExitDetails_dup2
  { enterDetail :: SyscallEnterDetails_dup2
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_dup = SyscallExitDetails_dup
  { enterDetail :: SyscallEnterDetails_dup
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sysfs = SyscallExitDetails_sysfs
  { enterDetail :: SyscallEnterDetails_sysfs
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ioctl = SyscallExitDetails_ioctl
  { enterDetail :: SyscallEnterDetails_ioctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_flock = SyscallExitDetails_flock
  { enterDetail :: SyscallEnterDetails_flock
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mknodat = SyscallExitDetails_mknodat
  { enterDetail :: SyscallEnterDetails_mknodat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mknod = SyscallExitDetails_mknod
  { enterDetail :: SyscallEnterDetails_mknod
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mkdirat = SyscallExitDetails_mkdirat
  { enterDetail :: SyscallEnterDetails_mkdirat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mkdir = SyscallExitDetails_mkdir
  { enterDetail :: SyscallEnterDetails_mkdir
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rmdir = SyscallExitDetails_rmdir
  { enterDetail :: SyscallEnterDetails_rmdir
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_unlinkat = SyscallExitDetails_unlinkat
  { enterDetail :: SyscallEnterDetails_unlinkat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_unlink = SyscallExitDetails_unlink
  { enterDetail :: SyscallEnterDetails_unlink
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_symlinkat = SyscallExitDetails_symlinkat
  { enterDetail :: SyscallEnterDetails_symlinkat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_symlink = SyscallExitDetails_symlink
  { enterDetail :: SyscallEnterDetails_symlink
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_linkat = SyscallExitDetails_linkat
  { enterDetail :: SyscallEnterDetails_linkat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_link = SyscallExitDetails_link
  { enterDetail :: SyscallEnterDetails_link
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_umount = SyscallExitDetails_umount
  { enterDetail :: SyscallEnterDetails_umount
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_oldumount = SyscallExitDetails_oldumount
  { enterDetail :: SyscallEnterDetails_oldumount
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mount = SyscallExitDetails_mount
  { enterDetail :: SyscallEnterDetails_mount
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pivot_root = SyscallExitDetails_pivot_root
  { enterDetail :: SyscallEnterDetails_pivot_root
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fanotify_init = SyscallExitDetails_fanotify_init
  { enterDetail :: SyscallEnterDetails_fanotify_init
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fanotify_mark = SyscallExitDetails_fanotify_mark
  { enterDetail :: SyscallEnterDetails_fanotify_mark
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_inotify_init1 = SyscallExitDetails_inotify_init1
  { enterDetail :: SyscallEnterDetails_inotify_init1
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_inotify_init = SyscallExitDetails_inotify_init
  { enterDetail :: SyscallEnterDetails_inotify_init
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_inotify_add_watch = SyscallExitDetails_inotify_add_watch
  { enterDetail :: SyscallEnterDetails_inotify_add_watch
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_inotify_rm_watch = SyscallExitDetails_inotify_rm_watch
  { enterDetail :: SyscallEnterDetails_inotify_rm_watch
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_truncate = SyscallExitDetails_truncate
  { enterDetail :: SyscallEnterDetails_truncate
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ftruncate = SyscallExitDetails_ftruncate
  { enterDetail :: SyscallEnterDetails_ftruncate
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_truncate64 = SyscallExitDetails_truncate64
  { enterDetail :: SyscallEnterDetails_truncate64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ftruncate64 = SyscallExitDetails_ftruncate64
  { enterDetail :: SyscallEnterDetails_ftruncate64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fallocate = SyscallExitDetails_fallocate
  { enterDetail :: SyscallEnterDetails_fallocate
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_chdir = SyscallExitDetails_chdir
  { enterDetail :: SyscallEnterDetails_chdir
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fchdir = SyscallExitDetails_fchdir
  { enterDetail :: SyscallEnterDetails_fchdir
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_chroot = SyscallExitDetails_chroot
  { enterDetail :: SyscallEnterDetails_chroot
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fchmod = SyscallExitDetails_fchmod
  { enterDetail :: SyscallEnterDetails_fchmod
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fchmodat = SyscallExitDetails_fchmodat
  { enterDetail :: SyscallEnterDetails_fchmodat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_chmod = SyscallExitDetails_chmod
  { enterDetail :: SyscallEnterDetails_chmod
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fchownat = SyscallExitDetails_fchownat
  { enterDetail :: SyscallEnterDetails_fchownat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_chown = SyscallExitDetails_chown
  { enterDetail :: SyscallEnterDetails_chown
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lchown = SyscallExitDetails_lchown
  { enterDetail :: SyscallEnterDetails_lchown
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fchown = SyscallExitDetails_fchown
  { enterDetail :: SyscallEnterDetails_fchown
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_vhangup = SyscallExitDetails_vhangup
  { enterDetail :: SyscallEnterDetails_vhangup
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_quotactl = SyscallExitDetails_quotactl
  { enterDetail :: SyscallEnterDetails_quotactl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lseek = SyscallExitDetails_lseek
  { enterDetail :: SyscallEnterDetails_lseek
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pread64 = SyscallExitDetails_pread64
  { enterDetail :: SyscallEnterDetails_pread64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pwrite64 = SyscallExitDetails_pwrite64
  { enterDetail :: SyscallEnterDetails_pwrite64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_readv = SyscallExitDetails_readv
  { enterDetail :: SyscallEnterDetails_readv
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_writev = SyscallExitDetails_writev
  { enterDetail :: SyscallEnterDetails_writev
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_preadv = SyscallExitDetails_preadv
  { enterDetail :: SyscallEnterDetails_preadv
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_preadv2 = SyscallExitDetails_preadv2
  { enterDetail :: SyscallEnterDetails_preadv2
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pwritev = SyscallExitDetails_pwritev
  { enterDetail :: SyscallEnterDetails_pwritev
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pwritev2 = SyscallExitDetails_pwritev2
  { enterDetail :: SyscallEnterDetails_pwritev2
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sendfile = SyscallExitDetails_sendfile
  { enterDetail :: SyscallEnterDetails_sendfile
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sendfile64 = SyscallExitDetails_sendfile64
  { enterDetail :: SyscallEnterDetails_sendfile64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_copy_file_range = SyscallExitDetails_copy_file_range
  { enterDetail :: SyscallEnterDetails_copy_file_range
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getdents = SyscallExitDetails_getdents
  { enterDetail :: SyscallEnterDetails_getdents
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getdents64 = SyscallExitDetails_getdents64
  { enterDetail :: SyscallEnterDetails_getdents64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_poll = SyscallExitDetails_poll
  { enterDetail :: SyscallEnterDetails_poll
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ppoll = SyscallExitDetails_ppoll
  { enterDetail :: SyscallEnterDetails_ppoll
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_signalfd4 = SyscallExitDetails_signalfd4
  { enterDetail :: SyscallEnterDetails_signalfd4
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_signalfd = SyscallExitDetails_signalfd
  { enterDetail :: SyscallEnterDetails_signalfd
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_vmsplice = SyscallExitDetails_vmsplice
  { enterDetail :: SyscallEnterDetails_vmsplice
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_splice = SyscallExitDetails_splice
  { enterDetail :: SyscallEnterDetails_splice
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_tee = SyscallExitDetails_tee
  { enterDetail :: SyscallEnterDetails_tee
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_readlinkat = SyscallExitDetails_readlinkat
  { enterDetail :: SyscallEnterDetails_readlinkat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_readlink = SyscallExitDetails_readlink
  { enterDetail :: SyscallEnterDetails_readlink
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_stat64 = SyscallExitDetails_stat64
  { enterDetail :: SyscallEnterDetails_stat64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lstat64 = SyscallExitDetails_lstat64
  { enterDetail :: SyscallEnterDetails_lstat64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fstat64 = SyscallExitDetails_fstat64
  { enterDetail :: SyscallEnterDetails_fstat64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fstatat64 = SyscallExitDetails_fstatat64
  { enterDetail :: SyscallEnterDetails_fstatat64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_statx = SyscallExitDetails_statx
  { enterDetail :: SyscallEnterDetails_statx
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_statfs = SyscallExitDetails_statfs
  { enterDetail :: SyscallEnterDetails_statfs
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_statfs64 = SyscallExitDetails_statfs64
  { enterDetail :: SyscallEnterDetails_statfs64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fstatfs = SyscallExitDetails_fstatfs
  { enterDetail :: SyscallEnterDetails_fstatfs
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fstatfs64 = SyscallExitDetails_fstatfs64
  { enterDetail :: SyscallEnterDetails_fstatfs64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ustat = SyscallExitDetails_ustat
  { enterDetail :: SyscallEnterDetails_ustat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sync = SyscallExitDetails_sync
  { enterDetail :: SyscallEnterDetails_sync
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_syncfs = SyscallExitDetails_syncfs
  { enterDetail :: SyscallEnterDetails_syncfs
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fsync = SyscallExitDetails_fsync
  { enterDetail :: SyscallEnterDetails_fsync
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fdatasync = SyscallExitDetails_fdatasync
  { enterDetail :: SyscallEnterDetails_fdatasync
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sync_file_range = SyscallExitDetails_sync_file_range
  { enterDetail :: SyscallEnterDetails_sync_file_range
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sync_file_range2 = SyscallExitDetails_sync_file_range2
  { enterDetail :: SyscallEnterDetails_sync_file_range2
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timerfd_create = SyscallExitDetails_timerfd_create
  { enterDetail :: SyscallEnterDetails_timerfd_create
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timerfd_settime = SyscallExitDetails_timerfd_settime
  { enterDetail :: SyscallEnterDetails_timerfd_settime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timerfd_gettime = SyscallExitDetails_timerfd_gettime
  { enterDetail :: SyscallEnterDetails_timerfd_gettime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_userfaultfd = SyscallExitDetails_userfaultfd
  { enterDetail :: SyscallEnterDetails_userfaultfd
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_utimensat = SyscallExitDetails_utimensat
  { enterDetail :: SyscallEnterDetails_utimensat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_futimesat = SyscallExitDetails_futimesat
  { enterDetail :: SyscallEnterDetails_futimesat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_utimes = SyscallExitDetails_utimes
  { enterDetail :: SyscallEnterDetails_utimes
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_utime = SyscallExitDetails_utime
  { enterDetail :: SyscallEnterDetails_utime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setxattr = SyscallExitDetails_setxattr
  { enterDetail :: SyscallEnterDetails_setxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lsetxattr = SyscallExitDetails_lsetxattr
  { enterDetail :: SyscallEnterDetails_lsetxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fsetxattr = SyscallExitDetails_fsetxattr
  { enterDetail :: SyscallEnterDetails_fsetxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getxattr = SyscallExitDetails_getxattr
  { enterDetail :: SyscallEnterDetails_getxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lgetxattr = SyscallExitDetails_lgetxattr
  { enterDetail :: SyscallEnterDetails_lgetxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fgetxattr = SyscallExitDetails_fgetxattr
  { enterDetail :: SyscallEnterDetails_fgetxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_listxattr = SyscallExitDetails_listxattr
  { enterDetail :: SyscallEnterDetails_listxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_llistxattr = SyscallExitDetails_llistxattr
  { enterDetail :: SyscallEnterDetails_llistxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_flistxattr = SyscallExitDetails_flistxattr
  { enterDetail :: SyscallEnterDetails_flistxattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_removexattr = SyscallExitDetails_removexattr
  { enterDetail :: SyscallEnterDetails_removexattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_lremovexattr = SyscallExitDetails_lremovexattr
  { enterDetail :: SyscallEnterDetails_lremovexattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fremovexattr = SyscallExitDetails_fremovexattr
  { enterDetail :: SyscallEnterDetails_fremovexattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_msgget = SyscallExitDetails_msgget
  { enterDetail :: SyscallEnterDetails_msgget
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_msgctl = SyscallExitDetails_msgctl
  { enterDetail :: SyscallEnterDetails_msgctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_msgsnd = SyscallExitDetails_msgsnd
  { enterDetail :: SyscallEnterDetails_msgsnd
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_msgrcv = SyscallExitDetails_msgrcv
  { enterDetail :: SyscallEnterDetails_msgrcv
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_semget = SyscallExitDetails_semget
  { enterDetail :: SyscallEnterDetails_semget
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_semctl = SyscallExitDetails_semctl
  { enterDetail :: SyscallEnterDetails_semctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_semtimedop = SyscallExitDetails_semtimedop
  { enterDetail :: SyscallEnterDetails_semtimedop
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_semop = SyscallExitDetails_semop
  { enterDetail :: SyscallEnterDetails_semop
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_shmget = SyscallExitDetails_shmget
  { enterDetail :: SyscallEnterDetails_shmget
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_shmctl = SyscallExitDetails_shmctl
  { enterDetail :: SyscallEnterDetails_shmctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_shmat = SyscallExitDetails_shmat
  { enterDetail :: SyscallEnterDetails_shmat
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_shmdt = SyscallExitDetails_shmdt
  { enterDetail :: SyscallEnterDetails_shmdt
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ipc = SyscallExitDetails_ipc
  { enterDetail :: SyscallEnterDetails_ipc
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_acct = SyscallExitDetails_acct
  { enterDetail :: SyscallEnterDetails_acct
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_perf_event_open = SyscallExitDetails_perf_event_open
  { enterDetail :: SyscallEnterDetails_perf_event_open
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_personality = SyscallExitDetails_personality
  { enterDetail :: SyscallEnterDetails_personality
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_waitid = SyscallExitDetails_waitid
  { enterDetail :: SyscallEnterDetails_waitid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_wait4 = SyscallExitDetails_wait4
  { enterDetail :: SyscallEnterDetails_wait4
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_waitpid = SyscallExitDetails_waitpid
  { enterDetail :: SyscallEnterDetails_waitpid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_set_tid_address = SyscallExitDetails_set_tid_address
  { enterDetail :: SyscallEnterDetails_set_tid_address
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fork = SyscallExitDetails_fork
  { enterDetail :: SyscallEnterDetails_fork
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_vfork = SyscallExitDetails_vfork
  { enterDetail :: SyscallEnterDetails_vfork
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_clone = SyscallExitDetails_clone
  { enterDetail :: SyscallEnterDetails_clone
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_unshare = SyscallExitDetails_unshare
  { enterDetail :: SyscallEnterDetails_unshare
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_set_robust_list = SyscallExitDetails_set_robust_list
  { enterDetail :: SyscallEnterDetails_set_robust_list
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_get_robust_list = SyscallExitDetails_get_robust_list
  { enterDetail :: SyscallEnterDetails_get_robust_list
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_futex = SyscallExitDetails_futex
  { enterDetail :: SyscallEnterDetails_futex
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getgroups = SyscallExitDetails_getgroups
  { enterDetail :: SyscallEnterDetails_getgroups
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setgroups = SyscallExitDetails_setgroups
  { enterDetail :: SyscallEnterDetails_setgroups
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_kcmp = SyscallExitDetails_kcmp
  { enterDetail :: SyscallEnterDetails_kcmp
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_kexec_load = SyscallExitDetails_kexec_load
  { enterDetail :: SyscallEnterDetails_kexec_load
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_kexec_file_load = SyscallExitDetails_kexec_file_load
  { enterDetail :: SyscallEnterDetails_kexec_file_load
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_delete_module = SyscallExitDetails_delete_module
  { enterDetail :: SyscallEnterDetails_delete_module
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_init_module = SyscallExitDetails_init_module
  { enterDetail :: SyscallEnterDetails_init_module
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_finit_module = SyscallExitDetails_finit_module
  { enterDetail :: SyscallEnterDetails_finit_module
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setns = SyscallExitDetails_setns
  { enterDetail :: SyscallEnterDetails_setns
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_syslog = SyscallExitDetails_syslog
  { enterDetail :: SyscallEnterDetails_syslog
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ptrace = SyscallExitDetails_ptrace
  { enterDetail :: SyscallEnterDetails_ptrace
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_reboot = SyscallExitDetails_reboot
  { enterDetail :: SyscallEnterDetails_reboot
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rseq = SyscallExitDetails_rseq
  { enterDetail :: SyscallEnterDetails_rseq
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_nice = SyscallExitDetails_nice
  { enterDetail :: SyscallEnterDetails_nice
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_setscheduler = SyscallExitDetails_sched_setscheduler
  { enterDetail :: SyscallEnterDetails_sched_setscheduler
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_setparam = SyscallExitDetails_sched_setparam
  { enterDetail :: SyscallEnterDetails_sched_setparam
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_setattr = SyscallExitDetails_sched_setattr
  { enterDetail :: SyscallEnterDetails_sched_setattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_getscheduler = SyscallExitDetails_sched_getscheduler
  { enterDetail :: SyscallEnterDetails_sched_getscheduler
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_getparam = SyscallExitDetails_sched_getparam
  { enterDetail :: SyscallEnterDetails_sched_getparam
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_getattr = SyscallExitDetails_sched_getattr
  { enterDetail :: SyscallEnterDetails_sched_getattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_setaffinity = SyscallExitDetails_sched_setaffinity
  { enterDetail :: SyscallEnterDetails_sched_setaffinity
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_getaffinity = SyscallExitDetails_sched_getaffinity
  { enterDetail :: SyscallEnterDetails_sched_getaffinity
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_yield = SyscallExitDetails_sched_yield
  { enterDetail :: SyscallEnterDetails_sched_yield
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_get_priority_max = SyscallExitDetails_sched_get_priority_max
  { enterDetail :: SyscallEnterDetails_sched_get_priority_max
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_get_priority_min = SyscallExitDetails_sched_get_priority_min
  { enterDetail :: SyscallEnterDetails_sched_get_priority_min
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sched_rr_get_interval = SyscallExitDetails_sched_rr_get_interval
  { enterDetail :: SyscallEnterDetails_sched_rr_get_interval
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_membarrier = SyscallExitDetails_membarrier
  { enterDetail :: SyscallEnterDetails_membarrier
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_seccomp = SyscallExitDetails_seccomp
  { enterDetail :: SyscallEnterDetails_seccomp
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_restart_syscall = SyscallExitDetails_restart_syscall
  { enterDetail :: SyscallEnterDetails_restart_syscall
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigprocmask = SyscallExitDetails_rt_sigprocmask
  { enterDetail :: SyscallEnterDetails_rt_sigprocmask
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigpending = SyscallExitDetails_rt_sigpending
  { enterDetail :: SyscallEnterDetails_rt_sigpending
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_kill = SyscallExitDetails_kill
  { enterDetail :: SyscallEnterDetails_kill
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_tgkill = SyscallExitDetails_tgkill
  { enterDetail :: SyscallEnterDetails_tgkill
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_tkill = SyscallExitDetails_tkill
  { enterDetail :: SyscallEnterDetails_tkill
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sigpending = SyscallExitDetails_sigpending
  { enterDetail :: SyscallEnterDetails_sigpending
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sigprocmask = SyscallExitDetails_sigprocmask
  { enterDetail :: SyscallEnterDetails_sigprocmask
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigaction = SyscallExitDetails_rt_sigaction
  { enterDetail :: SyscallEnterDetails_rt_sigaction
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sigaction = SyscallExitDetails_sigaction
  { enterDetail :: SyscallEnterDetails_sigaction
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sgetmask = SyscallExitDetails_sgetmask
  { enterDetail :: SyscallEnterDetails_sgetmask
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_ssetmask = SyscallExitDetails_ssetmask
  { enterDetail :: SyscallEnterDetails_ssetmask
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_signal = SyscallExitDetails_signal
  { enterDetail :: SyscallEnterDetails_signal
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pause = SyscallExitDetails_pause
  { enterDetail :: SyscallEnterDetails_pause
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigsuspend = SyscallExitDetails_rt_sigsuspend
  { enterDetail :: SyscallEnterDetails_rt_sigsuspend
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sigsuspend = SyscallExitDetails_sigsuspend
  { enterDetail :: SyscallEnterDetails_sigsuspend
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setpriority = SyscallExitDetails_setpriority
  { enterDetail :: SyscallEnterDetails_setpriority
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getpriority = SyscallExitDetails_getpriority
  { enterDetail :: SyscallEnterDetails_getpriority
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setregid = SyscallExitDetails_setregid
  { enterDetail :: SyscallEnterDetails_setregid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setgid = SyscallExitDetails_setgid
  { enterDetail :: SyscallEnterDetails_setgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setreuid = SyscallExitDetails_setreuid
  { enterDetail :: SyscallEnterDetails_setreuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setuid = SyscallExitDetails_setuid
  { enterDetail :: SyscallEnterDetails_setuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setresuid = SyscallExitDetails_setresuid
  { enterDetail :: SyscallEnterDetails_setresuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getresuid = SyscallExitDetails_getresuid
  { enterDetail :: SyscallEnterDetails_getresuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setresgid = SyscallExitDetails_setresgid
  { enterDetail :: SyscallEnterDetails_setresgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getresgid = SyscallExitDetails_getresgid
  { enterDetail :: SyscallEnterDetails_getresgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setfsuid = SyscallExitDetails_setfsuid
  { enterDetail :: SyscallEnterDetails_setfsuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setfsgid = SyscallExitDetails_setfsgid
  { enterDetail :: SyscallEnterDetails_setfsgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getpid = SyscallExitDetails_getpid
  { enterDetail :: SyscallEnterDetails_getpid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_gettid = SyscallExitDetails_gettid
  { enterDetail :: SyscallEnterDetails_gettid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getppid = SyscallExitDetails_getppid
  { enterDetail :: SyscallEnterDetails_getppid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getuid = SyscallExitDetails_getuid
  { enterDetail :: SyscallEnterDetails_getuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_geteuid = SyscallExitDetails_geteuid
  { enterDetail :: SyscallEnterDetails_geteuid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getgid = SyscallExitDetails_getgid
  { enterDetail :: SyscallEnterDetails_getgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getegid = SyscallExitDetails_getegid
  { enterDetail :: SyscallEnterDetails_getegid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_times = SyscallExitDetails_times
  { enterDetail :: SyscallEnterDetails_times
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setpgid = SyscallExitDetails_setpgid
  { enterDetail :: SyscallEnterDetails_setpgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getpgid = SyscallExitDetails_getpgid
  { enterDetail :: SyscallEnterDetails_getpgid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getpgrp = SyscallExitDetails_getpgrp
  { enterDetail :: SyscallEnterDetails_getpgrp
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getsid = SyscallExitDetails_getsid
  { enterDetail :: SyscallEnterDetails_getsid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setsid = SyscallExitDetails_setsid
  { enterDetail :: SyscallEnterDetails_setsid
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_uname = SyscallExitDetails_uname
  { enterDetail :: SyscallEnterDetails_uname
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_olduname = SyscallExitDetails_olduname
  { enterDetail :: SyscallEnterDetails_olduname
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sethostname = SyscallExitDetails_sethostname
  { enterDetail :: SyscallEnterDetails_sethostname
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_gethostname = SyscallExitDetails_gethostname
  { enterDetail :: SyscallEnterDetails_gethostname
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setdomainname = SyscallExitDetails_setdomainname
  { enterDetail :: SyscallEnterDetails_setdomainname
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getrlimit = SyscallExitDetails_getrlimit
  { enterDetail :: SyscallEnterDetails_getrlimit
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_prlimit64 = SyscallExitDetails_prlimit64
  { enterDetail :: SyscallEnterDetails_prlimit64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setrlimit = SyscallExitDetails_setrlimit
  { enterDetail :: SyscallEnterDetails_setrlimit
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getrusage = SyscallExitDetails_getrusage
  { enterDetail :: SyscallEnterDetails_getrusage
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_umask = SyscallExitDetails_umask
  { enterDetail :: SyscallEnterDetails_umask
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_prctl = SyscallExitDetails_prctl
  { enterDetail :: SyscallEnterDetails_prctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getcpu = SyscallExitDetails_getcpu
  { enterDetail :: SyscallEnterDetails_getcpu
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sysinfo = SyscallExitDetails_sysinfo
  { enterDetail :: SyscallEnterDetails_sysinfo
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_nanosleep = SyscallExitDetails_nanosleep
  { enterDetail :: SyscallEnterDetails_nanosleep
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getitimer = SyscallExitDetails_getitimer
  { enterDetail :: SyscallEnterDetails_getitimer
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_alarm = SyscallExitDetails_alarm
  { enterDetail :: SyscallEnterDetails_alarm
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setitimer = SyscallExitDetails_setitimer
  { enterDetail :: SyscallEnterDetails_setitimer
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_clock_settime = SyscallExitDetails_clock_settime
  { enterDetail :: SyscallEnterDetails_clock_settime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_clock_gettime = SyscallExitDetails_clock_gettime
  { enterDetail :: SyscallEnterDetails_clock_gettime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_clock_getres = SyscallExitDetails_clock_getres
  { enterDetail :: SyscallEnterDetails_clock_getres
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_clock_nanosleep = SyscallExitDetails_clock_nanosleep
  { enterDetail :: SyscallEnterDetails_clock_nanosleep
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timer_create = SyscallExitDetails_timer_create
  { enterDetail :: SyscallEnterDetails_timer_create
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timer_gettime = SyscallExitDetails_timer_gettime
  { enterDetail :: SyscallEnterDetails_timer_gettime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timer_getoverrun = SyscallExitDetails_timer_getoverrun
  { enterDetail :: SyscallEnterDetails_timer_getoverrun
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timer_settime = SyscallExitDetails_timer_settime
  { enterDetail :: SyscallEnterDetails_timer_settime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_timer_delete = SyscallExitDetails_timer_delete
  { enterDetail :: SyscallEnterDetails_timer_delete
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_clock_adjtime = SyscallExitDetails_clock_adjtime
  { enterDetail :: SyscallEnterDetails_clock_adjtime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_time = SyscallExitDetails_time
  { enterDetail :: SyscallEnterDetails_time
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_stime = SyscallExitDetails_stime
  { enterDetail :: SyscallEnterDetails_stime
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_gettimeofday = SyscallExitDetails_gettimeofday
  { enterDetail :: SyscallEnterDetails_gettimeofday
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_settimeofday = SyscallExitDetails_settimeofday
  { enterDetail :: SyscallEnterDetails_settimeofday
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_adjtimex = SyscallExitDetails_adjtimex
  { enterDetail :: SyscallEnterDetails_adjtimex
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fadvise64_64 = SyscallExitDetails_fadvise64_64
  { enterDetail :: SyscallEnterDetails_fadvise64_64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_fadvise64 = SyscallExitDetails_fadvise64
  { enterDetail :: SyscallEnterDetails_fadvise64
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_madvise = SyscallExitDetails_madvise
  { enterDetail :: SyscallEnterDetails_madvise
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_memfd_create = SyscallExitDetails_memfd_create
  { enterDetail :: SyscallEnterDetails_memfd_create
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mbind = SyscallExitDetails_mbind
  { enterDetail :: SyscallEnterDetails_mbind
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_set_mempolicy = SyscallExitDetails_set_mempolicy
  { enterDetail :: SyscallEnterDetails_set_mempolicy
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_migrate_pages = SyscallExitDetails_migrate_pages
  { enterDetail :: SyscallEnterDetails_migrate_pages
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_get_mempolicy = SyscallExitDetails_get_mempolicy
  { enterDetail :: SyscallEnterDetails_get_mempolicy
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_move_pages = SyscallExitDetails_move_pages
  { enterDetail :: SyscallEnterDetails_move_pages
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mincore = SyscallExitDetails_mincore
  { enterDetail :: SyscallEnterDetails_mincore
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mlock = SyscallExitDetails_mlock
  { enterDetail :: SyscallEnterDetails_mlock
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mlock2 = SyscallExitDetails_mlock2
  { enterDetail :: SyscallEnterDetails_mlock2
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_munlock = SyscallExitDetails_munlock
  { enterDetail :: SyscallEnterDetails_munlock
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mlockall = SyscallExitDetails_mlockall
  { enterDetail :: SyscallEnterDetails_mlockall
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_munlockall = SyscallExitDetails_munlockall
  { enterDetail :: SyscallEnterDetails_munlockall
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_brk = SyscallExitDetails_brk
  { enterDetail :: SyscallEnterDetails_brk
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_munmap = SyscallExitDetails_munmap
  { enterDetail :: SyscallEnterDetails_munmap
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_remap_file_pages = SyscallExitDetails_remap_file_pages
  { enterDetail :: SyscallEnterDetails_remap_file_pages
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mprotect = SyscallExitDetails_mprotect
  { enterDetail :: SyscallEnterDetails_mprotect
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pkey_mprotect = SyscallExitDetails_pkey_mprotect
  { enterDetail :: SyscallEnterDetails_pkey_mprotect
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pkey_alloc = SyscallExitDetails_pkey_alloc
  { enterDetail :: SyscallEnterDetails_pkey_alloc
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pkey_free = SyscallExitDetails_pkey_free
  { enterDetail :: SyscallEnterDetails_pkey_free
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mremap = SyscallExitDetails_mremap
  { enterDetail :: SyscallEnterDetails_mremap
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_msync = SyscallExitDetails_msync
  { enterDetail :: SyscallEnterDetails_msync
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_process_vm_readv = SyscallExitDetails_process_vm_readv
  { enterDetail :: SyscallEnterDetails_process_vm_readv
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_process_vm_writev = SyscallExitDetails_process_vm_writev
  { enterDetail :: SyscallEnterDetails_process_vm_writev
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_readahead = SyscallExitDetails_readahead
  { enterDetail :: SyscallEnterDetails_readahead
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_swapoff = SyscallExitDetails_swapoff
  { enterDetail :: SyscallEnterDetails_swapoff
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_swapon = SyscallExitDetails_swapon
  { enterDetail :: SyscallEnterDetails_swapon
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_socket = SyscallExitDetails_socket
  { enterDetail :: SyscallEnterDetails_socket
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_socketpair = SyscallExitDetails_socketpair
  { enterDetail :: SyscallEnterDetails_socketpair
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_bind = SyscallExitDetails_bind
  { enterDetail :: SyscallEnterDetails_bind
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_listen = SyscallExitDetails_listen
  { enterDetail :: SyscallEnterDetails_listen
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_accept4 = SyscallExitDetails_accept4
  { enterDetail :: SyscallEnterDetails_accept4
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_accept = SyscallExitDetails_accept
  { enterDetail :: SyscallEnterDetails_accept
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_connect = SyscallExitDetails_connect
  { enterDetail :: SyscallEnterDetails_connect
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getsockname = SyscallExitDetails_getsockname
  { enterDetail :: SyscallEnterDetails_getsockname
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getpeername = SyscallExitDetails_getpeername
  { enterDetail :: SyscallEnterDetails_getpeername
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sendto = SyscallExitDetails_sendto
  { enterDetail :: SyscallEnterDetails_sendto
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_send = SyscallExitDetails_send
  { enterDetail :: SyscallEnterDetails_send
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_recvfrom = SyscallExitDetails_recvfrom
  { enterDetail :: SyscallEnterDetails_recvfrom
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_recv = SyscallExitDetails_recv
  { enterDetail :: SyscallEnterDetails_recv
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_setsockopt = SyscallExitDetails_setsockopt
  { enterDetail :: SyscallEnterDetails_setsockopt
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_getsockopt = SyscallExitDetails_getsockopt
  { enterDetail :: SyscallEnterDetails_getsockopt
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_shutdown = SyscallExitDetails_shutdown
  { enterDetail :: SyscallEnterDetails_shutdown
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sendmsg = SyscallExitDetails_sendmsg
  { enterDetail :: SyscallEnterDetails_sendmsg
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sendmmsg = SyscallExitDetails_sendmmsg
  { enterDetail :: SyscallEnterDetails_sendmmsg
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_recvmsg = SyscallExitDetails_recvmsg
  { enterDetail :: SyscallEnterDetails_recvmsg
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_recvmmsg = SyscallExitDetails_recvmmsg
  { enterDetail :: SyscallEnterDetails_recvmmsg
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_socketcall = SyscallExitDetails_socketcall
  { enterDetail :: SyscallEnterDetails_socketcall
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_add_key = SyscallExitDetails_add_key
  { enterDetail :: SyscallEnterDetails_add_key
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_request_key = SyscallExitDetails_request_key
  { enterDetail :: SyscallEnterDetails_request_key
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_keyctl = SyscallExitDetails_keyctl
  { enterDetail :: SyscallEnterDetails_keyctl
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_select = SyscallExitDetails_select
  { enterDetail :: SyscallEnterDetails_select
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_pselect6 = SyscallExitDetails_pselect6
  { enterDetail :: SyscallEnterDetails_pselect6
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mq_open = SyscallExitDetails_mq_open
  { enterDetail :: SyscallEnterDetails_mq_open
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mq_unlink = SyscallExitDetails_mq_unlink
  { enterDetail :: SyscallEnterDetails_mq_unlink
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_bpf = SyscallExitDetails_bpf
  { enterDetail :: SyscallEnterDetails_bpf
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_capget = SyscallExitDetails_capget
  { enterDetail :: SyscallEnterDetails_capget
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_capset = SyscallExitDetails_capset
  { enterDetail :: SyscallEnterDetails_capset
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigtimedwait = SyscallExitDetails_rt_sigtimedwait
  { enterDetail :: SyscallEnterDetails_rt_sigtimedwait
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_sigqueueinfo = SyscallExitDetails_rt_sigqueueinfo
  { enterDetail :: SyscallEnterDetails_rt_sigqueueinfo
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_rt_tgsigqueueinfo = SyscallExitDetails_rt_tgsigqueueinfo
  { enterDetail :: SyscallEnterDetails_rt_tgsigqueueinfo
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_sigaltstack = SyscallExitDetails_sigaltstack
  { enterDetail :: SyscallEnterDetails_sigaltstack
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mq_timedsend = SyscallExitDetails_mq_timedsend
  { enterDetail :: SyscallEnterDetails_mq_timedsend
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mq_timedreceive = SyscallExitDetails_mq_timedreceive
  { enterDetail :: SyscallEnterDetails_mq_timedreceive
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mq_notify = SyscallExitDetails_mq_notify
  { enterDetail :: SyscallEnterDetails_mq_notify
  , retval :: CInt
  } deriving (Eq, Ord, Show)
data SyscallExitDetails_mq_getsetattr = SyscallExitDetails_mq_getsetattr
  { enterDetail :: SyscallEnterDetails_mq_getsetattr
  , retval :: CInt
  } deriving (Eq, Ord, Show)


data DetailedSyscallEnter
  = DetailedSyscallEnter_open SyscallEnterDetails_open
  | DetailedSyscallEnter_openat SyscallEnterDetails_openat
  | DetailedSyscallEnter_creat SyscallEnterDetails_creat
  | DetailedSyscallEnter_pipe SyscallEnterDetails_pipe
  | DetailedSyscallEnter_pipe2 SyscallEnterDetails_pipe2
  | DetailedSyscallEnter_access SyscallEnterDetails_access
  | DetailedSyscallEnter_faccessat SyscallEnterDetails_faccessat
  | DetailedSyscallEnter_write SyscallEnterDetails_write
  | DetailedSyscallEnter_read SyscallEnterDetails_read
  | DetailedSyscallEnter_execve SyscallEnterDetails_execve
  | DetailedSyscallEnter_close SyscallEnterDetails_close
  | DetailedSyscallEnter_rename SyscallEnterDetails_rename
  | DetailedSyscallEnter_renameat SyscallEnterDetails_renameat
  | DetailedSyscallEnter_renameat2 SyscallEnterDetails_renameat2
  | DetailedSyscallEnter_stat SyscallEnterDetails_stat
  | DetailedSyscallEnter_fstat SyscallEnterDetails_fstat
  | DetailedSyscallEnter_lstat SyscallEnterDetails_lstat
  | DetailedSyscallEnter_newfstatat SyscallEnterDetails_newfstatat
  | DetailedSyscallEnter_exit SyscallEnterDetails_exit
  | DetailedSyscallEnter_exit_group SyscallEnterDetails_exit_group
  | DetailedSyscallEnter_unimplemented Syscall SyscallArgs
  | DetailedSyscallEnter_ioperm SyscallEnterDetails_ioperm
  | DetailedSyscallEnter_iopl SyscallEnterDetails_iopl
  | DetailedSyscallEnter_modify_ldt SyscallEnterDetails_modify_ldt
  | DetailedSyscallEnter_arch_prctl SyscallEnterDetails_arch_prctl
  | DetailedSyscallEnter_sigreturn SyscallEnterDetails_sigreturn
  | DetailedSyscallEnter_rt_sigreturn SyscallEnterDetails_rt_sigreturn
  | DetailedSyscallEnter_mmap SyscallEnterDetails_mmap
  | DetailedSyscallEnter_set_thread_area SyscallEnterDetails_set_thread_area
  | DetailedSyscallEnter_get_thread_area SyscallEnterDetails_get_thread_area
  | DetailedSyscallEnter_vm86old SyscallEnterDetails_vm86old
  | DetailedSyscallEnter_vm86 SyscallEnterDetails_vm86
  | DetailedSyscallEnter_ioprio_set SyscallEnterDetails_ioprio_set
  | DetailedSyscallEnter_ioprio_get SyscallEnterDetails_ioprio_get
  | DetailedSyscallEnter_getrandom SyscallEnterDetails_getrandom
  | DetailedSyscallEnter_pciconfig_read SyscallEnterDetails_pciconfig_read
  | DetailedSyscallEnter_pciconfig_write SyscallEnterDetails_pciconfig_write
  | DetailedSyscallEnter_io_setup SyscallEnterDetails_io_setup
  | DetailedSyscallEnter_io_destroy SyscallEnterDetails_io_destroy
  | DetailedSyscallEnter_io_submit SyscallEnterDetails_io_submit
  | DetailedSyscallEnter_io_cancel SyscallEnterDetails_io_cancel
  | DetailedSyscallEnter_io_getevents SyscallEnterDetails_io_getevents
  | DetailedSyscallEnter_io_pgetevents SyscallEnterDetails_io_pgetevents
  | DetailedSyscallEnter_bdflush SyscallEnterDetails_bdflush
  | DetailedSyscallEnter_getcwd SyscallEnterDetails_getcwd
  | DetailedSyscallEnter_lookup_dcookie SyscallEnterDetails_lookup_dcookie
  | DetailedSyscallEnter_eventfd2 SyscallEnterDetails_eventfd2
  | DetailedSyscallEnter_eventfd SyscallEnterDetails_eventfd
  | DetailedSyscallEnter_epoll_create1 SyscallEnterDetails_epoll_create1
  | DetailedSyscallEnter_epoll_create SyscallEnterDetails_epoll_create
  | DetailedSyscallEnter_epoll_ctl SyscallEnterDetails_epoll_ctl
  | DetailedSyscallEnter_epoll_wait SyscallEnterDetails_epoll_wait
  | DetailedSyscallEnter_epoll_pwait SyscallEnterDetails_epoll_pwait
  | DetailedSyscallEnter_uselib SyscallEnterDetails_uselib
  | DetailedSyscallEnter_execveat SyscallEnterDetails_execveat
  | DetailedSyscallEnter_fcntl SyscallEnterDetails_fcntl
  | DetailedSyscallEnter_fcntl64 SyscallEnterDetails_fcntl64
  | DetailedSyscallEnter_name_to_handle_at SyscallEnterDetails_name_to_handle_at
  | DetailedSyscallEnter_open_by_handle_at SyscallEnterDetails_open_by_handle_at
  | DetailedSyscallEnter_dup3 SyscallEnterDetails_dup3
  | DetailedSyscallEnter_dup2 SyscallEnterDetails_dup2
  | DetailedSyscallEnter_dup SyscallEnterDetails_dup
  | DetailedSyscallEnter_sysfs SyscallEnterDetails_sysfs
  | DetailedSyscallEnter_ioctl SyscallEnterDetails_ioctl
  | DetailedSyscallEnter_flock SyscallEnterDetails_flock
  | DetailedSyscallEnter_mknodat SyscallEnterDetails_mknodat
  | DetailedSyscallEnter_mknod SyscallEnterDetails_mknod
  | DetailedSyscallEnter_mkdirat SyscallEnterDetails_mkdirat
  | DetailedSyscallEnter_mkdir SyscallEnterDetails_mkdir
  | DetailedSyscallEnter_rmdir SyscallEnterDetails_rmdir
  | DetailedSyscallEnter_unlinkat SyscallEnterDetails_unlinkat
  | DetailedSyscallEnter_unlink SyscallEnterDetails_unlink
  | DetailedSyscallEnter_symlinkat SyscallEnterDetails_symlinkat
  | DetailedSyscallEnter_symlink SyscallEnterDetails_symlink
  | DetailedSyscallEnter_linkat SyscallEnterDetails_linkat
  | DetailedSyscallEnter_link SyscallEnterDetails_link
  | DetailedSyscallEnter_umount SyscallEnterDetails_umount
  | DetailedSyscallEnter_oldumount SyscallEnterDetails_oldumount
  | DetailedSyscallEnter_mount SyscallEnterDetails_mount
  | DetailedSyscallEnter_pivot_root SyscallEnterDetails_pivot_root
  | DetailedSyscallEnter_fanotify_init SyscallEnterDetails_fanotify_init
  | DetailedSyscallEnter_fanotify_mark SyscallEnterDetails_fanotify_mark
  | DetailedSyscallEnter_inotify_init1 SyscallEnterDetails_inotify_init1
  | DetailedSyscallEnter_inotify_init SyscallEnterDetails_inotify_init
  | DetailedSyscallEnter_inotify_add_watch SyscallEnterDetails_inotify_add_watch
  | DetailedSyscallEnter_inotify_rm_watch SyscallEnterDetails_inotify_rm_watch
  | DetailedSyscallEnter_truncate SyscallEnterDetails_truncate
  | DetailedSyscallEnter_ftruncate SyscallEnterDetails_ftruncate
  | DetailedSyscallEnter_truncate64 SyscallEnterDetails_truncate64
  | DetailedSyscallEnter_ftruncate64 SyscallEnterDetails_ftruncate64
  | DetailedSyscallEnter_fallocate SyscallEnterDetails_fallocate
  | DetailedSyscallEnter_chdir SyscallEnterDetails_chdir
  | DetailedSyscallEnter_fchdir SyscallEnterDetails_fchdir
  | DetailedSyscallEnter_chroot SyscallEnterDetails_chroot
  | DetailedSyscallEnter_fchmod SyscallEnterDetails_fchmod
  | DetailedSyscallEnter_fchmodat SyscallEnterDetails_fchmodat
  | DetailedSyscallEnter_chmod SyscallEnterDetails_chmod
  | DetailedSyscallEnter_fchownat SyscallEnterDetails_fchownat
  | DetailedSyscallEnter_chown SyscallEnterDetails_chown
  | DetailedSyscallEnter_lchown SyscallEnterDetails_lchown
  | DetailedSyscallEnter_fchown SyscallEnterDetails_fchown
  | DetailedSyscallEnter_vhangup SyscallEnterDetails_vhangup
  | DetailedSyscallEnter_quotactl SyscallEnterDetails_quotactl
  | DetailedSyscallEnter_lseek SyscallEnterDetails_lseek
  | DetailedSyscallEnter_pread64 SyscallEnterDetails_pread64
  | DetailedSyscallEnter_pwrite64 SyscallEnterDetails_pwrite64
  | DetailedSyscallEnter_readv SyscallEnterDetails_readv
  | DetailedSyscallEnter_writev SyscallEnterDetails_writev
  | DetailedSyscallEnter_preadv SyscallEnterDetails_preadv
  | DetailedSyscallEnter_preadv2 SyscallEnterDetails_preadv2
  | DetailedSyscallEnter_pwritev SyscallEnterDetails_pwritev
  | DetailedSyscallEnter_pwritev2 SyscallEnterDetails_pwritev2
  | DetailedSyscallEnter_sendfile SyscallEnterDetails_sendfile
  | DetailedSyscallEnter_sendfile64 SyscallEnterDetails_sendfile64
  | DetailedSyscallEnter_copy_file_range SyscallEnterDetails_copy_file_range
  | DetailedSyscallEnter_getdents SyscallEnterDetails_getdents
  | DetailedSyscallEnter_getdents64 SyscallEnterDetails_getdents64
  | DetailedSyscallEnter_poll SyscallEnterDetails_poll
  | DetailedSyscallEnter_ppoll SyscallEnterDetails_ppoll
  | DetailedSyscallEnter_signalfd4 SyscallEnterDetails_signalfd4
  | DetailedSyscallEnter_signalfd SyscallEnterDetails_signalfd
  | DetailedSyscallEnter_vmsplice SyscallEnterDetails_vmsplice
  | DetailedSyscallEnter_splice SyscallEnterDetails_splice
  | DetailedSyscallEnter_tee SyscallEnterDetails_tee
  | DetailedSyscallEnter_readlinkat SyscallEnterDetails_readlinkat
  | DetailedSyscallEnter_readlink SyscallEnterDetails_readlink
  | DetailedSyscallEnter_stat64 SyscallEnterDetails_stat64
  | DetailedSyscallEnter_lstat64 SyscallEnterDetails_lstat64
  | DetailedSyscallEnter_fstat64 SyscallEnterDetails_fstat64
  | DetailedSyscallEnter_fstatat64 SyscallEnterDetails_fstatat64
  | DetailedSyscallEnter_statx SyscallEnterDetails_statx
  | DetailedSyscallEnter_statfs SyscallEnterDetails_statfs
  | DetailedSyscallEnter_statfs64 SyscallEnterDetails_statfs64
  | DetailedSyscallEnter_fstatfs SyscallEnterDetails_fstatfs
  | DetailedSyscallEnter_fstatfs64 SyscallEnterDetails_fstatfs64
  | DetailedSyscallEnter_ustat SyscallEnterDetails_ustat
  | DetailedSyscallEnter_sync SyscallEnterDetails_sync
  | DetailedSyscallEnter_syncfs SyscallEnterDetails_syncfs
  | DetailedSyscallEnter_fsync SyscallEnterDetails_fsync
  | DetailedSyscallEnter_fdatasync SyscallEnterDetails_fdatasync
  | DetailedSyscallEnter_sync_file_range SyscallEnterDetails_sync_file_range
  | DetailedSyscallEnter_sync_file_range2 SyscallEnterDetails_sync_file_range2
  | DetailedSyscallEnter_timerfd_create SyscallEnterDetails_timerfd_create
  | DetailedSyscallEnter_timerfd_settime SyscallEnterDetails_timerfd_settime
  | DetailedSyscallEnter_timerfd_gettime SyscallEnterDetails_timerfd_gettime
  | DetailedSyscallEnter_userfaultfd SyscallEnterDetails_userfaultfd
  | DetailedSyscallEnter_utimensat SyscallEnterDetails_utimensat
  | DetailedSyscallEnter_futimesat SyscallEnterDetails_futimesat
  | DetailedSyscallEnter_utimes SyscallEnterDetails_utimes
  | DetailedSyscallEnter_utime SyscallEnterDetails_utime
  | DetailedSyscallEnter_setxattr SyscallEnterDetails_setxattr
  | DetailedSyscallEnter_lsetxattr SyscallEnterDetails_lsetxattr
  | DetailedSyscallEnter_fsetxattr SyscallEnterDetails_fsetxattr
  | DetailedSyscallEnter_getxattr SyscallEnterDetails_getxattr
  | DetailedSyscallEnter_lgetxattr SyscallEnterDetails_lgetxattr
  | DetailedSyscallEnter_fgetxattr SyscallEnterDetails_fgetxattr
  | DetailedSyscallEnter_listxattr SyscallEnterDetails_listxattr
  | DetailedSyscallEnter_llistxattr SyscallEnterDetails_llistxattr
  | DetailedSyscallEnter_flistxattr SyscallEnterDetails_flistxattr
  | DetailedSyscallEnter_removexattr SyscallEnterDetails_removexattr
  | DetailedSyscallEnter_lremovexattr SyscallEnterDetails_lremovexattr
  | DetailedSyscallEnter_fremovexattr SyscallEnterDetails_fremovexattr
  | DetailedSyscallEnter_msgget SyscallEnterDetails_msgget
  | DetailedSyscallEnter_msgctl SyscallEnterDetails_msgctl
  | DetailedSyscallEnter_msgsnd SyscallEnterDetails_msgsnd
  | DetailedSyscallEnter_msgrcv SyscallEnterDetails_msgrcv
  | DetailedSyscallEnter_semget SyscallEnterDetails_semget
  | DetailedSyscallEnter_semctl SyscallEnterDetails_semctl
  | DetailedSyscallEnter_semtimedop SyscallEnterDetails_semtimedop
  | DetailedSyscallEnter_semop SyscallEnterDetails_semop
  | DetailedSyscallEnter_shmget SyscallEnterDetails_shmget
  | DetailedSyscallEnter_shmctl SyscallEnterDetails_shmctl
  | DetailedSyscallEnter_shmat SyscallEnterDetails_shmat
  | DetailedSyscallEnter_shmdt SyscallEnterDetails_shmdt
  | DetailedSyscallEnter_ipc SyscallEnterDetails_ipc
  | DetailedSyscallEnter_acct SyscallEnterDetails_acct
  | DetailedSyscallEnter_perf_event_open SyscallEnterDetails_perf_event_open
  | DetailedSyscallEnter_personality SyscallEnterDetails_personality
  | DetailedSyscallEnter_waitid SyscallEnterDetails_waitid
  | DetailedSyscallEnter_wait4 SyscallEnterDetails_wait4
  | DetailedSyscallEnter_waitpid SyscallEnterDetails_waitpid
  | DetailedSyscallEnter_set_tid_address SyscallEnterDetails_set_tid_address
  | DetailedSyscallEnter_fork SyscallEnterDetails_fork
  | DetailedSyscallEnter_vfork SyscallEnterDetails_vfork
  | DetailedSyscallEnter_clone SyscallEnterDetails_clone
  | DetailedSyscallEnter_unshare SyscallEnterDetails_unshare
  | DetailedSyscallEnter_set_robust_list SyscallEnterDetails_set_robust_list
  | DetailedSyscallEnter_get_robust_list SyscallEnterDetails_get_robust_list
  | DetailedSyscallEnter_futex SyscallEnterDetails_futex
  | DetailedSyscallEnter_getgroups SyscallEnterDetails_getgroups
  | DetailedSyscallEnter_setgroups SyscallEnterDetails_setgroups
  | DetailedSyscallEnter_kcmp SyscallEnterDetails_kcmp
  | DetailedSyscallEnter_kexec_load SyscallEnterDetails_kexec_load
  | DetailedSyscallEnter_kexec_file_load SyscallEnterDetails_kexec_file_load
  | DetailedSyscallEnter_delete_module SyscallEnterDetails_delete_module
  | DetailedSyscallEnter_init_module SyscallEnterDetails_init_module
  | DetailedSyscallEnter_finit_module SyscallEnterDetails_finit_module
  | DetailedSyscallEnter_setns SyscallEnterDetails_setns
  | DetailedSyscallEnter_syslog SyscallEnterDetails_syslog
  | DetailedSyscallEnter_ptrace SyscallEnterDetails_ptrace
  | DetailedSyscallEnter_reboot SyscallEnterDetails_reboot
  | DetailedSyscallEnter_rseq SyscallEnterDetails_rseq
  | DetailedSyscallEnter_nice SyscallEnterDetails_nice
  | DetailedSyscallEnter_sched_setscheduler SyscallEnterDetails_sched_setscheduler
  | DetailedSyscallEnter_sched_setparam SyscallEnterDetails_sched_setparam
  | DetailedSyscallEnter_sched_setattr SyscallEnterDetails_sched_setattr
  | DetailedSyscallEnter_sched_getscheduler SyscallEnterDetails_sched_getscheduler
  | DetailedSyscallEnter_sched_getparam SyscallEnterDetails_sched_getparam
  | DetailedSyscallEnter_sched_getattr SyscallEnterDetails_sched_getattr
  | DetailedSyscallEnter_sched_setaffinity SyscallEnterDetails_sched_setaffinity
  | DetailedSyscallEnter_sched_getaffinity SyscallEnterDetails_sched_getaffinity
  | DetailedSyscallEnter_sched_yield SyscallEnterDetails_sched_yield
  | DetailedSyscallEnter_sched_get_priority_max SyscallEnterDetails_sched_get_priority_max
  | DetailedSyscallEnter_sched_get_priority_min SyscallEnterDetails_sched_get_priority_min
  | DetailedSyscallEnter_sched_rr_get_interval SyscallEnterDetails_sched_rr_get_interval
  | DetailedSyscallEnter_membarrier SyscallEnterDetails_membarrier
  | DetailedSyscallEnter_seccomp SyscallEnterDetails_seccomp
  | DetailedSyscallEnter_restart_syscall SyscallEnterDetails_restart_syscall
  | DetailedSyscallEnter_rt_sigprocmask SyscallEnterDetails_rt_sigprocmask
  | DetailedSyscallEnter_rt_sigpending SyscallEnterDetails_rt_sigpending
  | DetailedSyscallEnter_kill SyscallEnterDetails_kill
  | DetailedSyscallEnter_tgkill SyscallEnterDetails_tgkill
  | DetailedSyscallEnter_tkill SyscallEnterDetails_tkill
  | DetailedSyscallEnter_sigpending SyscallEnterDetails_sigpending
  | DetailedSyscallEnter_sigprocmask SyscallEnterDetails_sigprocmask
  | DetailedSyscallEnter_rt_sigaction SyscallEnterDetails_rt_sigaction
  | DetailedSyscallEnter_sigaction SyscallEnterDetails_sigaction
  | DetailedSyscallEnter_sgetmask SyscallEnterDetails_sgetmask
  | DetailedSyscallEnter_ssetmask SyscallEnterDetails_ssetmask
  | DetailedSyscallEnter_signal SyscallEnterDetails_signal
  | DetailedSyscallEnter_pause SyscallEnterDetails_pause
  | DetailedSyscallEnter_rt_sigsuspend SyscallEnterDetails_rt_sigsuspend
  | DetailedSyscallEnter_sigsuspend SyscallEnterDetails_sigsuspend
  | DetailedSyscallEnter_setpriority SyscallEnterDetails_setpriority
  | DetailedSyscallEnter_getpriority SyscallEnterDetails_getpriority
  | DetailedSyscallEnter_setregid SyscallEnterDetails_setregid
  | DetailedSyscallEnter_setgid SyscallEnterDetails_setgid
  | DetailedSyscallEnter_setreuid SyscallEnterDetails_setreuid
  | DetailedSyscallEnter_setuid SyscallEnterDetails_setuid
  | DetailedSyscallEnter_setresuid SyscallEnterDetails_setresuid
  | DetailedSyscallEnter_getresuid SyscallEnterDetails_getresuid
  | DetailedSyscallEnter_setresgid SyscallEnterDetails_setresgid
  | DetailedSyscallEnter_getresgid SyscallEnterDetails_getresgid
  | DetailedSyscallEnter_setfsuid SyscallEnterDetails_setfsuid
  | DetailedSyscallEnter_setfsgid SyscallEnterDetails_setfsgid
  | DetailedSyscallEnter_getpid SyscallEnterDetails_getpid
  | DetailedSyscallEnter_gettid SyscallEnterDetails_gettid
  | DetailedSyscallEnter_getppid SyscallEnterDetails_getppid
  | DetailedSyscallEnter_getuid SyscallEnterDetails_getuid
  | DetailedSyscallEnter_geteuid SyscallEnterDetails_geteuid
  | DetailedSyscallEnter_getgid SyscallEnterDetails_getgid
  | DetailedSyscallEnter_getegid SyscallEnterDetails_getegid
  | DetailedSyscallEnter_times SyscallEnterDetails_times
  | DetailedSyscallEnter_setpgid SyscallEnterDetails_setpgid
  | DetailedSyscallEnter_getpgid SyscallEnterDetails_getpgid
  | DetailedSyscallEnter_getpgrp SyscallEnterDetails_getpgrp
  | DetailedSyscallEnter_getsid SyscallEnterDetails_getsid
  | DetailedSyscallEnter_setsid SyscallEnterDetails_setsid
  | DetailedSyscallEnter_uname SyscallEnterDetails_uname
  | DetailedSyscallEnter_olduname SyscallEnterDetails_olduname
  | DetailedSyscallEnter_sethostname SyscallEnterDetails_sethostname
  | DetailedSyscallEnter_gethostname SyscallEnterDetails_gethostname
  | DetailedSyscallEnter_setdomainname SyscallEnterDetails_setdomainname
  | DetailedSyscallEnter_getrlimit SyscallEnterDetails_getrlimit
  | DetailedSyscallEnter_prlimit64 SyscallEnterDetails_prlimit64
  | DetailedSyscallEnter_setrlimit SyscallEnterDetails_setrlimit
  | DetailedSyscallEnter_getrusage SyscallEnterDetails_getrusage
  | DetailedSyscallEnter_umask SyscallEnterDetails_umask
  | DetailedSyscallEnter_prctl SyscallEnterDetails_prctl
  | DetailedSyscallEnter_getcpu SyscallEnterDetails_getcpu
  | DetailedSyscallEnter_sysinfo SyscallEnterDetails_sysinfo
  | DetailedSyscallEnter_nanosleep SyscallEnterDetails_nanosleep
  | DetailedSyscallEnter_getitimer SyscallEnterDetails_getitimer
  | DetailedSyscallEnter_alarm SyscallEnterDetails_alarm
  | DetailedSyscallEnter_setitimer SyscallEnterDetails_setitimer
  | DetailedSyscallEnter_clock_settime SyscallEnterDetails_clock_settime
  | DetailedSyscallEnter_clock_gettime SyscallEnterDetails_clock_gettime
  | DetailedSyscallEnter_clock_getres SyscallEnterDetails_clock_getres
  | DetailedSyscallEnter_clock_nanosleep SyscallEnterDetails_clock_nanosleep
  | DetailedSyscallEnter_timer_create SyscallEnterDetails_timer_create
  | DetailedSyscallEnter_timer_gettime SyscallEnterDetails_timer_gettime
  | DetailedSyscallEnter_timer_getoverrun SyscallEnterDetails_timer_getoverrun
  | DetailedSyscallEnter_timer_settime SyscallEnterDetails_timer_settime
  | DetailedSyscallEnter_timer_delete SyscallEnterDetails_timer_delete
  | DetailedSyscallEnter_clock_adjtime SyscallEnterDetails_clock_adjtime
  | DetailedSyscallEnter_time SyscallEnterDetails_time
  | DetailedSyscallEnter_stime SyscallEnterDetails_stime
  | DetailedSyscallEnter_gettimeofday SyscallEnterDetails_gettimeofday
  | DetailedSyscallEnter_settimeofday SyscallEnterDetails_settimeofday
  | DetailedSyscallEnter_adjtimex SyscallEnterDetails_adjtimex
  | DetailedSyscallEnter_fadvise64_64 SyscallEnterDetails_fadvise64_64
  | DetailedSyscallEnter_fadvise64 SyscallEnterDetails_fadvise64
  | DetailedSyscallEnter_madvise SyscallEnterDetails_madvise
  | DetailedSyscallEnter_memfd_create SyscallEnterDetails_memfd_create
  | DetailedSyscallEnter_mbind SyscallEnterDetails_mbind
  | DetailedSyscallEnter_set_mempolicy SyscallEnterDetails_set_mempolicy
  | DetailedSyscallEnter_migrate_pages SyscallEnterDetails_migrate_pages
  | DetailedSyscallEnter_get_mempolicy SyscallEnterDetails_get_mempolicy
  | DetailedSyscallEnter_move_pages SyscallEnterDetails_move_pages
  | DetailedSyscallEnter_mincore SyscallEnterDetails_mincore
  | DetailedSyscallEnter_mlock SyscallEnterDetails_mlock
  | DetailedSyscallEnter_mlock2 SyscallEnterDetails_mlock2
  | DetailedSyscallEnter_munlock SyscallEnterDetails_munlock
  | DetailedSyscallEnter_mlockall SyscallEnterDetails_mlockall
  | DetailedSyscallEnter_munlockall SyscallEnterDetails_munlockall
  | DetailedSyscallEnter_brk SyscallEnterDetails_brk
  | DetailedSyscallEnter_munmap SyscallEnterDetails_munmap
  | DetailedSyscallEnter_remap_file_pages SyscallEnterDetails_remap_file_pages
  | DetailedSyscallEnter_mprotect SyscallEnterDetails_mprotect
  | DetailedSyscallEnter_pkey_mprotect SyscallEnterDetails_pkey_mprotect
  | DetailedSyscallEnter_pkey_alloc SyscallEnterDetails_pkey_alloc
  | DetailedSyscallEnter_pkey_free SyscallEnterDetails_pkey_free
  | DetailedSyscallEnter_mremap SyscallEnterDetails_mremap
  | DetailedSyscallEnter_msync SyscallEnterDetails_msync
  | DetailedSyscallEnter_process_vm_readv SyscallEnterDetails_process_vm_readv
  | DetailedSyscallEnter_process_vm_writev SyscallEnterDetails_process_vm_writev
  | DetailedSyscallEnter_readahead SyscallEnterDetails_readahead
  | DetailedSyscallEnter_swapoff SyscallEnterDetails_swapoff
  | DetailedSyscallEnter_swapon SyscallEnterDetails_swapon
  | DetailedSyscallEnter_socket SyscallEnterDetails_socket
  | DetailedSyscallEnter_socketpair SyscallEnterDetails_socketpair
  | DetailedSyscallEnter_bind SyscallEnterDetails_bind
  | DetailedSyscallEnter_listen SyscallEnterDetails_listen
  | DetailedSyscallEnter_accept4 SyscallEnterDetails_accept4
  | DetailedSyscallEnter_accept SyscallEnterDetails_accept
  | DetailedSyscallEnter_connect SyscallEnterDetails_connect
  | DetailedSyscallEnter_getsockname SyscallEnterDetails_getsockname
  | DetailedSyscallEnter_getpeername SyscallEnterDetails_getpeername
  | DetailedSyscallEnter_sendto SyscallEnterDetails_sendto
  | DetailedSyscallEnter_send SyscallEnterDetails_send
  | DetailedSyscallEnter_recvfrom SyscallEnterDetails_recvfrom
  | DetailedSyscallEnter_recv SyscallEnterDetails_recv
  | DetailedSyscallEnter_setsockopt SyscallEnterDetails_setsockopt
  | DetailedSyscallEnter_getsockopt SyscallEnterDetails_getsockopt
  | DetailedSyscallEnter_shutdown SyscallEnterDetails_shutdown
  | DetailedSyscallEnter_sendmsg SyscallEnterDetails_sendmsg
  | DetailedSyscallEnter_sendmmsg SyscallEnterDetails_sendmmsg
  | DetailedSyscallEnter_recvmsg SyscallEnterDetails_recvmsg
  | DetailedSyscallEnter_recvmmsg SyscallEnterDetails_recvmmsg
  | DetailedSyscallEnter_socketcall SyscallEnterDetails_socketcall
  | DetailedSyscallEnter_add_key SyscallEnterDetails_add_key
  | DetailedSyscallEnter_request_key SyscallEnterDetails_request_key
  | DetailedSyscallEnter_keyctl SyscallEnterDetails_keyctl
  | DetailedSyscallEnter_select SyscallEnterDetails_select
  | DetailedSyscallEnter_pselect6 SyscallEnterDetails_pselect6
  | DetailedSyscallEnter_mq_open SyscallEnterDetails_mq_open
  | DetailedSyscallEnter_mq_unlink SyscallEnterDetails_mq_unlink
  | DetailedSyscallEnter_bpf SyscallEnterDetails_bpf
  | DetailedSyscallEnter_capget SyscallEnterDetails_capget
  | DetailedSyscallEnter_capset SyscallEnterDetails_capset
  | DetailedSyscallEnter_rt_sigtimedwait SyscallEnterDetails_rt_sigtimedwait
  | DetailedSyscallEnter_rt_sigqueueinfo SyscallEnterDetails_rt_sigqueueinfo
  | DetailedSyscallEnter_rt_tgsigqueueinfo SyscallEnterDetails_rt_tgsigqueueinfo
  | DetailedSyscallEnter_sigaltstack SyscallEnterDetails_sigaltstack
  | DetailedSyscallEnter_mq_timedsend SyscallEnterDetails_mq_timedsend
  | DetailedSyscallEnter_mq_timedreceive SyscallEnterDetails_mq_timedreceive
  | DetailedSyscallEnter_mq_notify SyscallEnterDetails_mq_notify
  | DetailedSyscallEnter_mq_getsetattr SyscallEnterDetails_mq_getsetattr
  deriving (Eq, Ord, Show)


data DetailedSyscallExit
  = DetailedSyscallExit_open SyscallExitDetails_open
  | DetailedSyscallExit_openat SyscallExitDetails_openat
  | DetailedSyscallExit_creat SyscallExitDetails_creat
  | DetailedSyscallExit_pipe SyscallExitDetails_pipe
  | DetailedSyscallExit_pipe2 SyscallExitDetails_pipe2
  | DetailedSyscallExit_access SyscallExitDetails_access
  | DetailedSyscallExit_faccessat SyscallExitDetails_faccessat
  | DetailedSyscallExit_write SyscallExitDetails_write
  | DetailedSyscallExit_read SyscallExitDetails_read
  | DetailedSyscallExit_execve SyscallExitDetails_execve
  | DetailedSyscallExit_close SyscallExitDetails_close
  | DetailedSyscallExit_rename SyscallExitDetails_rename
  | DetailedSyscallExit_renameat SyscallExitDetails_renameat
  | DetailedSyscallExit_renameat2 SyscallExitDetails_renameat2
  | DetailedSyscallExit_stat SyscallExitDetails_stat
  | DetailedSyscallExit_fstat SyscallExitDetails_fstat
  | DetailedSyscallExit_lstat SyscallExitDetails_lstat
  | DetailedSyscallExit_newfstatat SyscallExitDetails_newfstatat
  | DetailedSyscallExit_exit SyscallExitDetails_exit
  | DetailedSyscallExit_exit_group SyscallExitDetails_exit_group
  | DetailedSyscallExit_unimplemented Syscall SyscallArgs Word64
  | DetailedSyscallExit_ioperm SyscallExitDetails_ioperm
  | DetailedSyscallExit_iopl SyscallExitDetails_iopl
  | DetailedSyscallExit_modify_ldt SyscallExitDetails_modify_ldt
  | DetailedSyscallExit_arch_prctl SyscallExitDetails_arch_prctl
  | DetailedSyscallExit_sigreturn SyscallExitDetails_sigreturn
  | DetailedSyscallExit_rt_sigreturn SyscallExitDetails_rt_sigreturn
  | DetailedSyscallExit_mmap SyscallExitDetails_mmap
  | DetailedSyscallExit_set_thread_area SyscallExitDetails_set_thread_area
  | DetailedSyscallExit_get_thread_area SyscallExitDetails_get_thread_area
  | DetailedSyscallExit_vm86old SyscallExitDetails_vm86old
  | DetailedSyscallExit_vm86 SyscallExitDetails_vm86
  | DetailedSyscallExit_ioprio_set SyscallExitDetails_ioprio_set
  | DetailedSyscallExit_ioprio_get SyscallExitDetails_ioprio_get
  | DetailedSyscallExit_getrandom SyscallExitDetails_getrandom
  | DetailedSyscallExit_pciconfig_read SyscallExitDetails_pciconfig_read
  | DetailedSyscallExit_pciconfig_write SyscallExitDetails_pciconfig_write
  | DetailedSyscallExit_io_setup SyscallExitDetails_io_setup
  | DetailedSyscallExit_io_destroy SyscallExitDetails_io_destroy
  | DetailedSyscallExit_io_submit SyscallExitDetails_io_submit
  | DetailedSyscallExit_io_cancel SyscallExitDetails_io_cancel
  | DetailedSyscallExit_io_getevents SyscallExitDetails_io_getevents
  | DetailedSyscallExit_io_pgetevents SyscallExitDetails_io_pgetevents
  | DetailedSyscallExit_bdflush SyscallExitDetails_bdflush
  | DetailedSyscallExit_getcwd SyscallExitDetails_getcwd
  | DetailedSyscallExit_lookup_dcookie SyscallExitDetails_lookup_dcookie
  | DetailedSyscallExit_eventfd2 SyscallExitDetails_eventfd2
  | DetailedSyscallExit_eventfd SyscallExitDetails_eventfd
  | DetailedSyscallExit_epoll_create1 SyscallExitDetails_epoll_create1
  | DetailedSyscallExit_epoll_create SyscallExitDetails_epoll_create
  | DetailedSyscallExit_epoll_ctl SyscallExitDetails_epoll_ctl
  | DetailedSyscallExit_epoll_wait SyscallExitDetails_epoll_wait
  | DetailedSyscallExit_epoll_pwait SyscallExitDetails_epoll_pwait
  | DetailedSyscallExit_uselib SyscallExitDetails_uselib
  | DetailedSyscallExit_execveat SyscallExitDetails_execveat
  | DetailedSyscallExit_fcntl SyscallExitDetails_fcntl
  | DetailedSyscallExit_fcntl64 SyscallExitDetails_fcntl64
  | DetailedSyscallExit_name_to_handle_at SyscallExitDetails_name_to_handle_at
  | DetailedSyscallExit_open_by_handle_at SyscallExitDetails_open_by_handle_at
  | DetailedSyscallExit_dup3 SyscallExitDetails_dup3
  | DetailedSyscallExit_dup2 SyscallExitDetails_dup2
  | DetailedSyscallExit_dup SyscallExitDetails_dup
  | DetailedSyscallExit_sysfs SyscallExitDetails_sysfs
  | DetailedSyscallExit_ioctl SyscallExitDetails_ioctl
  | DetailedSyscallExit_flock SyscallExitDetails_flock
  | DetailedSyscallExit_mknodat SyscallExitDetails_mknodat
  | DetailedSyscallExit_mknod SyscallExitDetails_mknod
  | DetailedSyscallExit_mkdirat SyscallExitDetails_mkdirat
  | DetailedSyscallExit_mkdir SyscallExitDetails_mkdir
  | DetailedSyscallExit_rmdir SyscallExitDetails_rmdir
  | DetailedSyscallExit_unlinkat SyscallExitDetails_unlinkat
  | DetailedSyscallExit_unlink SyscallExitDetails_unlink
  | DetailedSyscallExit_symlinkat SyscallExitDetails_symlinkat
  | DetailedSyscallExit_symlink SyscallExitDetails_symlink
  | DetailedSyscallExit_linkat SyscallExitDetails_linkat
  | DetailedSyscallExit_link SyscallExitDetails_link
  | DetailedSyscallExit_umount SyscallExitDetails_umount
  | DetailedSyscallExit_oldumount SyscallExitDetails_oldumount
  | DetailedSyscallExit_mount SyscallExitDetails_mount
  | DetailedSyscallExit_pivot_root SyscallExitDetails_pivot_root
  | DetailedSyscallExit_fanotify_init SyscallExitDetails_fanotify_init
  | DetailedSyscallExit_fanotify_mark SyscallExitDetails_fanotify_mark
  | DetailedSyscallExit_inotify_init1 SyscallExitDetails_inotify_init1
  | DetailedSyscallExit_inotify_init SyscallExitDetails_inotify_init
  | DetailedSyscallExit_inotify_add_watch SyscallExitDetails_inotify_add_watch
  | DetailedSyscallExit_inotify_rm_watch SyscallExitDetails_inotify_rm_watch
  | DetailedSyscallExit_truncate SyscallExitDetails_truncate
  | DetailedSyscallExit_ftruncate SyscallExitDetails_ftruncate
  | DetailedSyscallExit_truncate64 SyscallExitDetails_truncate64
  | DetailedSyscallExit_ftruncate64 SyscallExitDetails_ftruncate64
  | DetailedSyscallExit_fallocate SyscallExitDetails_fallocate
  | DetailedSyscallExit_chdir SyscallExitDetails_chdir
  | DetailedSyscallExit_fchdir SyscallExitDetails_fchdir
  | DetailedSyscallExit_chroot SyscallExitDetails_chroot
  | DetailedSyscallExit_fchmod SyscallExitDetails_fchmod
  | DetailedSyscallExit_fchmodat SyscallExitDetails_fchmodat
  | DetailedSyscallExit_chmod SyscallExitDetails_chmod
  | DetailedSyscallExit_fchownat SyscallExitDetails_fchownat
  | DetailedSyscallExit_chown SyscallExitDetails_chown
  | DetailedSyscallExit_lchown SyscallExitDetails_lchown
  | DetailedSyscallExit_fchown SyscallExitDetails_fchown
  | DetailedSyscallExit_vhangup SyscallExitDetails_vhangup
  | DetailedSyscallExit_quotactl SyscallExitDetails_quotactl
  | DetailedSyscallExit_lseek SyscallExitDetails_lseek
  | DetailedSyscallExit_pread64 SyscallExitDetails_pread64
  | DetailedSyscallExit_pwrite64 SyscallExitDetails_pwrite64
  | DetailedSyscallExit_readv SyscallExitDetails_readv
  | DetailedSyscallExit_writev SyscallExitDetails_writev
  | DetailedSyscallExit_preadv SyscallExitDetails_preadv
  | DetailedSyscallExit_preadv2 SyscallExitDetails_preadv2
  | DetailedSyscallExit_pwritev SyscallExitDetails_pwritev
  | DetailedSyscallExit_pwritev2 SyscallExitDetails_pwritev2
  | DetailedSyscallExit_sendfile SyscallExitDetails_sendfile
  | DetailedSyscallExit_sendfile64 SyscallExitDetails_sendfile64
  | DetailedSyscallExit_copy_file_range SyscallExitDetails_copy_file_range
  | DetailedSyscallExit_getdents SyscallExitDetails_getdents
  | DetailedSyscallExit_getdents64 SyscallExitDetails_getdents64
  | DetailedSyscallExit_poll SyscallExitDetails_poll
  | DetailedSyscallExit_ppoll SyscallExitDetails_ppoll
  | DetailedSyscallExit_signalfd4 SyscallExitDetails_signalfd4
  | DetailedSyscallExit_signalfd SyscallExitDetails_signalfd
  | DetailedSyscallExit_vmsplice SyscallExitDetails_vmsplice
  | DetailedSyscallExit_splice SyscallExitDetails_splice
  | DetailedSyscallExit_tee SyscallExitDetails_tee
  | DetailedSyscallExit_readlinkat SyscallExitDetails_readlinkat
  | DetailedSyscallExit_readlink SyscallExitDetails_readlink
  | DetailedSyscallExit_stat64 SyscallExitDetails_stat64
  | DetailedSyscallExit_lstat64 SyscallExitDetails_lstat64
  | DetailedSyscallExit_fstat64 SyscallExitDetails_fstat64
  | DetailedSyscallExit_fstatat64 SyscallExitDetails_fstatat64
  | DetailedSyscallExit_statx SyscallExitDetails_statx
  | DetailedSyscallExit_statfs SyscallExitDetails_statfs
  | DetailedSyscallExit_statfs64 SyscallExitDetails_statfs64
  | DetailedSyscallExit_fstatfs SyscallExitDetails_fstatfs
  | DetailedSyscallExit_fstatfs64 SyscallExitDetails_fstatfs64
  | DetailedSyscallExit_ustat SyscallExitDetails_ustat
  | DetailedSyscallExit_sync SyscallExitDetails_sync
  | DetailedSyscallExit_syncfs SyscallExitDetails_syncfs
  | DetailedSyscallExit_fsync SyscallExitDetails_fsync
  | DetailedSyscallExit_fdatasync SyscallExitDetails_fdatasync
  | DetailedSyscallExit_sync_file_range SyscallExitDetails_sync_file_range
  | DetailedSyscallExit_sync_file_range2 SyscallExitDetails_sync_file_range2
  | DetailedSyscallExit_timerfd_create SyscallExitDetails_timerfd_create
  | DetailedSyscallExit_timerfd_settime SyscallExitDetails_timerfd_settime
  | DetailedSyscallExit_timerfd_gettime SyscallExitDetails_timerfd_gettime
  | DetailedSyscallExit_userfaultfd SyscallExitDetails_userfaultfd
  | DetailedSyscallExit_utimensat SyscallExitDetails_utimensat
  | DetailedSyscallExit_futimesat SyscallExitDetails_futimesat
  | DetailedSyscallExit_utimes SyscallExitDetails_utimes
  | DetailedSyscallExit_utime SyscallExitDetails_utime
  | DetailedSyscallExit_setxattr SyscallExitDetails_setxattr
  | DetailedSyscallExit_lsetxattr SyscallExitDetails_lsetxattr
  | DetailedSyscallExit_fsetxattr SyscallExitDetails_fsetxattr
  | DetailedSyscallExit_getxattr SyscallExitDetails_getxattr
  | DetailedSyscallExit_lgetxattr SyscallExitDetails_lgetxattr
  | DetailedSyscallExit_fgetxattr SyscallExitDetails_fgetxattr
  | DetailedSyscallExit_listxattr SyscallExitDetails_listxattr
  | DetailedSyscallExit_llistxattr SyscallExitDetails_llistxattr
  | DetailedSyscallExit_flistxattr SyscallExitDetails_flistxattr
  | DetailedSyscallExit_removexattr SyscallExitDetails_removexattr
  | DetailedSyscallExit_lremovexattr SyscallExitDetails_lremovexattr
  | DetailedSyscallExit_fremovexattr SyscallExitDetails_fremovexattr
  | DetailedSyscallExit_msgget SyscallExitDetails_msgget
  | DetailedSyscallExit_msgctl SyscallExitDetails_msgctl
  | DetailedSyscallExit_msgsnd SyscallExitDetails_msgsnd
  | DetailedSyscallExit_msgrcv SyscallExitDetails_msgrcv
  | DetailedSyscallExit_semget SyscallExitDetails_semget
  | DetailedSyscallExit_semctl SyscallExitDetails_semctl
  | DetailedSyscallExit_semtimedop SyscallExitDetails_semtimedop
  | DetailedSyscallExit_semop SyscallExitDetails_semop
  | DetailedSyscallExit_shmget SyscallExitDetails_shmget
  | DetailedSyscallExit_shmctl SyscallExitDetails_shmctl
  | DetailedSyscallExit_shmat SyscallExitDetails_shmat
  | DetailedSyscallExit_shmdt SyscallExitDetails_shmdt
  | DetailedSyscallExit_ipc SyscallExitDetails_ipc
  | DetailedSyscallExit_acct SyscallExitDetails_acct
  | DetailedSyscallExit_perf_event_open SyscallExitDetails_perf_event_open
  | DetailedSyscallExit_personality SyscallExitDetails_personality
  | DetailedSyscallExit_waitid SyscallExitDetails_waitid
  | DetailedSyscallExit_wait4 SyscallExitDetails_wait4
  | DetailedSyscallExit_waitpid SyscallExitDetails_waitpid
  | DetailedSyscallExit_set_tid_address SyscallExitDetails_set_tid_address
  | DetailedSyscallExit_fork SyscallExitDetails_fork
  | DetailedSyscallExit_vfork SyscallExitDetails_vfork
  | DetailedSyscallExit_clone SyscallExitDetails_clone
  | DetailedSyscallExit_unshare SyscallExitDetails_unshare
  | DetailedSyscallExit_set_robust_list SyscallExitDetails_set_robust_list
  | DetailedSyscallExit_get_robust_list SyscallExitDetails_get_robust_list
  | DetailedSyscallExit_futex SyscallExitDetails_futex
  | DetailedSyscallExit_getgroups SyscallExitDetails_getgroups
  | DetailedSyscallExit_setgroups SyscallExitDetails_setgroups
  | DetailedSyscallExit_kcmp SyscallExitDetails_kcmp
  | DetailedSyscallExit_kexec_load SyscallExitDetails_kexec_load
  | DetailedSyscallExit_kexec_file_load SyscallExitDetails_kexec_file_load
  | DetailedSyscallExit_delete_module SyscallExitDetails_delete_module
  | DetailedSyscallExit_init_module SyscallExitDetails_init_module
  | DetailedSyscallExit_finit_module SyscallExitDetails_finit_module
  | DetailedSyscallExit_setns SyscallExitDetails_setns
  | DetailedSyscallExit_syslog SyscallExitDetails_syslog
  | DetailedSyscallExit_ptrace SyscallExitDetails_ptrace
  | DetailedSyscallExit_reboot SyscallExitDetails_reboot
  | DetailedSyscallExit_rseq SyscallExitDetails_rseq
  | DetailedSyscallExit_nice SyscallExitDetails_nice
  | DetailedSyscallExit_sched_setscheduler SyscallExitDetails_sched_setscheduler
  | DetailedSyscallExit_sched_setparam SyscallExitDetails_sched_setparam
  | DetailedSyscallExit_sched_setattr SyscallExitDetails_sched_setattr
  | DetailedSyscallExit_sched_getscheduler SyscallExitDetails_sched_getscheduler
  | DetailedSyscallExit_sched_getparam SyscallExitDetails_sched_getparam
  | DetailedSyscallExit_sched_getattr SyscallExitDetails_sched_getattr
  | DetailedSyscallExit_sched_setaffinity SyscallExitDetails_sched_setaffinity
  | DetailedSyscallExit_sched_getaffinity SyscallExitDetails_sched_getaffinity
  | DetailedSyscallExit_sched_yield SyscallExitDetails_sched_yield
  | DetailedSyscallExit_sched_get_priority_max SyscallExitDetails_sched_get_priority_max
  | DetailedSyscallExit_sched_get_priority_min SyscallExitDetails_sched_get_priority_min
  | DetailedSyscallExit_sched_rr_get_interval SyscallExitDetails_sched_rr_get_interval
  | DetailedSyscallExit_membarrier SyscallExitDetails_membarrier
  | DetailedSyscallExit_seccomp SyscallExitDetails_seccomp
  | DetailedSyscallExit_restart_syscall SyscallExitDetails_restart_syscall
  | DetailedSyscallExit_rt_sigprocmask SyscallExitDetails_rt_sigprocmask
  | DetailedSyscallExit_rt_sigpending SyscallExitDetails_rt_sigpending
  | DetailedSyscallExit_kill SyscallExitDetails_kill
  | DetailedSyscallExit_tgkill SyscallExitDetails_tgkill
  | DetailedSyscallExit_tkill SyscallExitDetails_tkill
  | DetailedSyscallExit_sigpending SyscallExitDetails_sigpending
  | DetailedSyscallExit_sigprocmask SyscallExitDetails_sigprocmask
  | DetailedSyscallExit_rt_sigaction SyscallExitDetails_rt_sigaction
  | DetailedSyscallExit_sigaction SyscallExitDetails_sigaction
  | DetailedSyscallExit_sgetmask SyscallExitDetails_sgetmask
  | DetailedSyscallExit_ssetmask SyscallExitDetails_ssetmask
  | DetailedSyscallExit_signal SyscallExitDetails_signal
  | DetailedSyscallExit_pause SyscallExitDetails_pause
  | DetailedSyscallExit_rt_sigsuspend SyscallExitDetails_rt_sigsuspend
  | DetailedSyscallExit_sigsuspend SyscallExitDetails_sigsuspend
  | DetailedSyscallExit_setpriority SyscallExitDetails_setpriority
  | DetailedSyscallExit_getpriority SyscallExitDetails_getpriority
  | DetailedSyscallExit_setregid SyscallExitDetails_setregid
  | DetailedSyscallExit_setgid SyscallExitDetails_setgid
  | DetailedSyscallExit_setreuid SyscallExitDetails_setreuid
  | DetailedSyscallExit_setuid SyscallExitDetails_setuid
  | DetailedSyscallExit_setresuid SyscallExitDetails_setresuid
  | DetailedSyscallExit_getresuid SyscallExitDetails_getresuid
  | DetailedSyscallExit_setresgid SyscallExitDetails_setresgid
  | DetailedSyscallExit_getresgid SyscallExitDetails_getresgid
  | DetailedSyscallExit_setfsuid SyscallExitDetails_setfsuid
  | DetailedSyscallExit_setfsgid SyscallExitDetails_setfsgid
  | DetailedSyscallExit_getpid SyscallExitDetails_getpid
  | DetailedSyscallExit_gettid SyscallExitDetails_gettid
  | DetailedSyscallExit_getppid SyscallExitDetails_getppid
  | DetailedSyscallExit_getuid SyscallExitDetails_getuid
  | DetailedSyscallExit_geteuid SyscallExitDetails_geteuid
  | DetailedSyscallExit_getgid SyscallExitDetails_getgid
  | DetailedSyscallExit_getegid SyscallExitDetails_getegid
  | DetailedSyscallExit_times SyscallExitDetails_times
  | DetailedSyscallExit_setpgid SyscallExitDetails_setpgid
  | DetailedSyscallExit_getpgid SyscallExitDetails_getpgid
  | DetailedSyscallExit_getpgrp SyscallExitDetails_getpgrp
  | DetailedSyscallExit_getsid SyscallExitDetails_getsid
  | DetailedSyscallExit_setsid SyscallExitDetails_setsid
  | DetailedSyscallExit_uname SyscallExitDetails_uname
  | DetailedSyscallExit_olduname SyscallExitDetails_olduname
  | DetailedSyscallExit_sethostname SyscallExitDetails_sethostname
  | DetailedSyscallExit_gethostname SyscallExitDetails_gethostname
  | DetailedSyscallExit_setdomainname SyscallExitDetails_setdomainname
  | DetailedSyscallExit_getrlimit SyscallExitDetails_getrlimit
  | DetailedSyscallExit_prlimit64 SyscallExitDetails_prlimit64
  | DetailedSyscallExit_setrlimit SyscallExitDetails_setrlimit
  | DetailedSyscallExit_getrusage SyscallExitDetails_getrusage
  | DetailedSyscallExit_umask SyscallExitDetails_umask
  | DetailedSyscallExit_prctl SyscallExitDetails_prctl
  | DetailedSyscallExit_getcpu SyscallExitDetails_getcpu
  | DetailedSyscallExit_sysinfo SyscallExitDetails_sysinfo
  | DetailedSyscallExit_nanosleep SyscallExitDetails_nanosleep
  | DetailedSyscallExit_getitimer SyscallExitDetails_getitimer
  | DetailedSyscallExit_alarm SyscallExitDetails_alarm
  | DetailedSyscallExit_setitimer SyscallExitDetails_setitimer
  | DetailedSyscallExit_clock_settime SyscallExitDetails_clock_settime
  | DetailedSyscallExit_clock_gettime SyscallExitDetails_clock_gettime
  | DetailedSyscallExit_clock_getres SyscallExitDetails_clock_getres
  | DetailedSyscallExit_clock_nanosleep SyscallExitDetails_clock_nanosleep
  | DetailedSyscallExit_timer_create SyscallExitDetails_timer_create
  | DetailedSyscallExit_timer_gettime SyscallExitDetails_timer_gettime
  | DetailedSyscallExit_timer_getoverrun SyscallExitDetails_timer_getoverrun
  | DetailedSyscallExit_timer_settime SyscallExitDetails_timer_settime
  | DetailedSyscallExit_timer_delete SyscallExitDetails_timer_delete
  | DetailedSyscallExit_clock_adjtime SyscallExitDetails_clock_adjtime
  | DetailedSyscallExit_time SyscallExitDetails_time
  | DetailedSyscallExit_stime SyscallExitDetails_stime
  | DetailedSyscallExit_gettimeofday SyscallExitDetails_gettimeofday
  | DetailedSyscallExit_settimeofday SyscallExitDetails_settimeofday
  | DetailedSyscallExit_adjtimex SyscallExitDetails_adjtimex
  | DetailedSyscallExit_fadvise64_64 SyscallExitDetails_fadvise64_64
  | DetailedSyscallExit_fadvise64 SyscallExitDetails_fadvise64
  | DetailedSyscallExit_madvise SyscallExitDetails_madvise
  | DetailedSyscallExit_memfd_create SyscallExitDetails_memfd_create
  | DetailedSyscallExit_mbind SyscallExitDetails_mbind
  | DetailedSyscallExit_set_mempolicy SyscallExitDetails_set_mempolicy
  | DetailedSyscallExit_migrate_pages SyscallExitDetails_migrate_pages
  | DetailedSyscallExit_get_mempolicy SyscallExitDetails_get_mempolicy
  | DetailedSyscallExit_move_pages SyscallExitDetails_move_pages
  | DetailedSyscallExit_mincore SyscallExitDetails_mincore
  | DetailedSyscallExit_mlock SyscallExitDetails_mlock
  | DetailedSyscallExit_mlock2 SyscallExitDetails_mlock2
  | DetailedSyscallExit_munlock SyscallExitDetails_munlock
  | DetailedSyscallExit_mlockall SyscallExitDetails_mlockall
  | DetailedSyscallExit_munlockall SyscallExitDetails_munlockall
  | DetailedSyscallExit_brk SyscallExitDetails_brk
  | DetailedSyscallExit_munmap SyscallExitDetails_munmap
  | DetailedSyscallExit_remap_file_pages SyscallExitDetails_remap_file_pages
  | DetailedSyscallExit_mprotect SyscallExitDetails_mprotect
  | DetailedSyscallExit_pkey_mprotect SyscallExitDetails_pkey_mprotect
  | DetailedSyscallExit_pkey_alloc SyscallExitDetails_pkey_alloc
  | DetailedSyscallExit_pkey_free SyscallExitDetails_pkey_free
  | DetailedSyscallExit_mremap SyscallExitDetails_mremap
  | DetailedSyscallExit_msync SyscallExitDetails_msync
  | DetailedSyscallExit_process_vm_readv SyscallExitDetails_process_vm_readv
  | DetailedSyscallExit_process_vm_writev SyscallExitDetails_process_vm_writev
  | DetailedSyscallExit_readahead SyscallExitDetails_readahead
  | DetailedSyscallExit_swapoff SyscallExitDetails_swapoff
  | DetailedSyscallExit_swapon SyscallExitDetails_swapon
  | DetailedSyscallExit_socket SyscallExitDetails_socket
  | DetailedSyscallExit_socketpair SyscallExitDetails_socketpair
  | DetailedSyscallExit_bind SyscallExitDetails_bind
  | DetailedSyscallExit_listen SyscallExitDetails_listen
  | DetailedSyscallExit_accept4 SyscallExitDetails_accept4
  | DetailedSyscallExit_accept SyscallExitDetails_accept
  | DetailedSyscallExit_connect SyscallExitDetails_connect
  | DetailedSyscallExit_getsockname SyscallExitDetails_getsockname
  | DetailedSyscallExit_getpeername SyscallExitDetails_getpeername
  | DetailedSyscallExit_sendto SyscallExitDetails_sendto
  | DetailedSyscallExit_send SyscallExitDetails_send
  | DetailedSyscallExit_recvfrom SyscallExitDetails_recvfrom
  | DetailedSyscallExit_recv SyscallExitDetails_recv
  | DetailedSyscallExit_setsockopt SyscallExitDetails_setsockopt
  | DetailedSyscallExit_getsockopt SyscallExitDetails_getsockopt
  | DetailedSyscallExit_shutdown SyscallExitDetails_shutdown
  | DetailedSyscallExit_sendmsg SyscallExitDetails_sendmsg
  | DetailedSyscallExit_sendmmsg SyscallExitDetails_sendmmsg
  | DetailedSyscallExit_recvmsg SyscallExitDetails_recvmsg
  | DetailedSyscallExit_recvmmsg SyscallExitDetails_recvmmsg
  | DetailedSyscallExit_socketcall SyscallExitDetails_socketcall
  | DetailedSyscallExit_add_key SyscallExitDetails_add_key
  | DetailedSyscallExit_request_key SyscallExitDetails_request_key
  | DetailedSyscallExit_keyctl SyscallExitDetails_keyctl
  | DetailedSyscallExit_select SyscallExitDetails_select
  | DetailedSyscallExit_pselect6 SyscallExitDetails_pselect6
  | DetailedSyscallExit_mq_open SyscallExitDetails_mq_open
  | DetailedSyscallExit_mq_unlink SyscallExitDetails_mq_unlink
  | DetailedSyscallExit_bpf SyscallExitDetails_bpf
  | DetailedSyscallExit_capget SyscallExitDetails_capget
  | DetailedSyscallExit_capset SyscallExitDetails_capset
  | DetailedSyscallExit_rt_sigtimedwait SyscallExitDetails_rt_sigtimedwait
  | DetailedSyscallExit_rt_sigqueueinfo SyscallExitDetails_rt_sigqueueinfo
  | DetailedSyscallExit_rt_tgsigqueueinfo SyscallExitDetails_rt_tgsigqueueinfo
  | DetailedSyscallExit_sigaltstack SyscallExitDetails_sigaltstack
  | DetailedSyscallExit_mq_timedsend SyscallExitDetails_mq_timedsend
  | DetailedSyscallExit_mq_timedreceive SyscallExitDetails_mq_timedreceive
  | DetailedSyscallExit_mq_notify SyscallExitDetails_mq_notify
  | DetailedSyscallExit_mq_getsetattr SyscallExitDetails_mq_getsetattr
  deriving (Eq, Ord, Show)


getSyscallEnterDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO DetailedSyscallEnter
getSyscallEnterDetails syscall syscallArgs pid = let proc = TracedProcess pid in case syscall of
  Syscall_open -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = flags, arg2 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_open $ SyscallEnterDetails_open
      { pathname = pathnamePtr
      , flags = fromIntegral flags
      , mode = fromIntegral mode
      , pathnameBS
      }
  Syscall_openat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathnameAddr, arg2 = flags, arg3 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_openat $ SyscallEnterDetails_openat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , flags = fromIntegral flags
      , mode = fromIntegral mode
      , pathnameBS
      }
  Syscall_creat -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_creat $ SyscallEnterDetails_creat
      { pathname = pathnamePtr
      , mode = fromIntegral mode
      , pathnameBS
      }
  Syscall_pipe -> do
    let SyscallArgs{ arg0 = pipefdAddr } = syscallArgs
    let pipefdPtr = word64ToPtr pipefdAddr
    pure $ DetailedSyscallEnter_pipe $ SyscallEnterDetails_pipe
      { pipefd = pipefdPtr
      }
  Syscall_pipe2 -> do
    let SyscallArgs{ arg0 = pipefdAddr, arg1 = flags } = syscallArgs
    let pipefdPtr = word64ToPtr pipefdAddr
    pure $ DetailedSyscallEnter_pipe2 $ SyscallEnterDetails_pipe2
      { pipefd = pipefdPtr
      , flags = fromIntegral flags
      }
  Syscall_access -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_access $ SyscallEnterDetails_access
      { pathname = pathnamePtr
      , mode = fromIntegral mode
      , accessMode = fromCInt (fromIntegral mode)
      , pathnameBS
      }
  Syscall_faccessat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathnameAddr, arg2 = mode, arg3 = flags } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_faccessat $ SyscallEnterDetails_faccessat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , mode = fromIntegral mode
      , accessMode = fromCInt (fromIntegral mode)
      , pathnameBS
      , flags = fromIntegral flags
      }
  Syscall_write -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufContents <- peekBytes proc bufPtr (fromIntegral count)
    pure $ DetailedSyscallEnter_write $ SyscallEnterDetails_write
      { fd = fromIntegral fd
      , buf = bufPtr
      , count = fromIntegral count
      , bufContents
      }
  Syscall_read -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_read $ SyscallEnterDetails_read
      { fd = fromIntegral fd
      , buf = bufPtr
      , count = fromIntegral count
      }
  Syscall_execve -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = argvPtrsAddr, arg2 = envpPtrsAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let argvPtrsPtr = word64ToPtr argvPtrsAddr
    let envpPtrsPtr = word64ToPtr envpPtrsAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    -- Per `man 2 execve`:
    --     On Linux, argv and envp can be specified as NULL.
    --     In both cases, this has the same effect as specifying the argument
    --     as a pointer to a list containing a single null pointer.
    --     Do not take advantage of this nonstandard and nonportable misfeature!
    --     On many other UNIX systems, specifying argv as NULL will result in
    --     an error (EFAULT).
    --     Some other UNIX systems treat the envp==NULL case the same as Linux.
    -- We handle the case that `argv` or `envp` are NULL below.

    argvPtrs <-
      if argvPtrsPtr == nullPtr
        then pure []
        else peekNullWordTerminatedWords proc argvPtrsPtr
    envpPtrs <-
      if envpPtrsPtr == nullPtr
        then pure []
        else peekNullWordTerminatedWords proc envpPtrsPtr

    argvList <- mapM (peekNullTerminatedBytes proc . wordToPtr) argvPtrs
    envpList <- mapM (peekNullTerminatedBytes proc . wordToPtr) envpPtrs

    pure $ DetailedSyscallEnter_execve $ SyscallEnterDetails_execve
      { filename = filenamePtr
      , argv = argvPtrsPtr
      , envp = envpPtrsPtr
      , filenameBS
      , argvList
      , envpList
      }
  Syscall_close -> do
    let SyscallArgs{ arg0 = fd } = syscallArgs
    pure $ DetailedSyscallEnter_close $ SyscallEnterDetails_close
      { fd = fromIntegral fd
      }
  Syscall_rename -> do
    let SyscallArgs{ arg0 = oldpathAddr, arg1 = newpathAddr } = syscallArgs
    let oldpathPtr = word64ToPtr oldpathAddr
    let newpathPtr = word64ToPtr newpathAddr
    oldpathBS <- peekNullTerminatedBytes proc oldpathPtr
    newpathBS <- peekNullTerminatedBytes proc newpathPtr
    pure $ DetailedSyscallEnter_rename $ SyscallEnterDetails_rename
      { oldpath = oldpathPtr
      , newpath = newpathPtr
      , oldpathBS
      , newpathBS
      }
  Syscall_renameat -> do
    let SyscallArgs{ arg0 = olddirfd, arg1 = oldpathAddr, arg2 =newdirfd, arg3 = newpathAddr } = syscallArgs
    let oldpathPtr = word64ToPtr oldpathAddr
    let newpathPtr = word64ToPtr newpathAddr
    oldpathBS <- peekNullTerminatedBytes proc oldpathPtr
    newpathBS <- peekNullTerminatedBytes proc newpathPtr
    pure $ DetailedSyscallEnter_renameat $ SyscallEnterDetails_renameat
      { olddirfd = fromIntegral olddirfd
      , oldpath = oldpathPtr
      , newdirfd = fromIntegral newdirfd
      , newpath = newpathPtr
      , oldpathBS
      , newpathBS
      }
  Syscall_renameat2 -> do
    let SyscallArgs{ arg0 = olddirfd, arg1 = oldpathAddr
                   , arg2 =newdirfd, arg3 = newpathAddr, arg4 = flags } = syscallArgs
    let oldpathPtr = word64ToPtr oldpathAddr
    let newpathPtr = word64ToPtr newpathAddr
    oldpathBS <- peekNullTerminatedBytes proc oldpathPtr
    newpathBS <- peekNullTerminatedBytes proc newpathPtr
    pure $ DetailedSyscallEnter_renameat2 $ SyscallEnterDetails_renameat2
      { olddirfd = fromIntegral olddirfd
      , oldpath = oldpathPtr
      , newdirfd = fromIntegral newdirfd
      , newpath = newpathPtr
      , oldpathBS
      , newpathBS
      , flags = fromIntegral flags
      }
  Syscall_stat -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = statbufAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let statbufPtr = word64ToPtr statbufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_stat $ SyscallEnterDetails_stat
      { pathname = pathnamePtr
      , statbuf = statbufPtr
      , pathnameBS
      }
  Syscall_fstat -> do
    let SyscallArgs{ arg0 = fd, arg1 = statbufAddr } = syscallArgs
    let statbufPtr = word64ToPtr statbufAddr
    pure $ DetailedSyscallEnter_fstat $ SyscallEnterDetails_fstat
      { fd = fromIntegral fd
      , statbuf = statbufPtr
      }
  Syscall_lstat -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = statbufAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let statbufPtr = word64ToPtr statbufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_lstat $ SyscallEnterDetails_lstat
      { pathname = pathnamePtr
      , statbuf = statbufPtr
      , pathnameBS
      }
  Syscall_newfstatat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathnameAddr, arg2 = statbufAddr, arg3 = flags } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let statbufPtr = word64ToPtr statbufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_newfstatat $ SyscallEnterDetails_newfstatat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , statbuf = statbufPtr
      , flags = fromIntegral flags
      , pathnameBS
      }
  Syscall_exit -> do
    let SyscallArgs{ arg0 = status } = syscallArgs
    pure $ DetailedSyscallEnter_exit $ SyscallEnterDetails_exit { status = fromIntegral status }
  Syscall_exit_group -> do
    let SyscallArgs{ arg0 = status } = syscallArgs
    pure $ DetailedSyscallEnter_exit_group $ SyscallEnterDetails_exit_group { status = fromIntegral status }
  Syscall_ioperm -> do
    let SyscallArgs{ arg0 = from, arg1 = num, arg2 = turn_on } = syscallArgs
    pure $ DetailedSyscallEnter_ioperm $ SyscallEnterDetails_ioperm
      { from = fromIntegral from
      , num = fromIntegral num
      , turn_on = fromIntegral turn_on
      }
  Syscall_iopl -> do
    let SyscallArgs{ arg0 = level } = syscallArgs
    pure $ DetailedSyscallEnter_iopl $ SyscallEnterDetails_iopl
      { level = fromIntegral level
      }
  Syscall_modify_ldt -> do
    let SyscallArgs{ arg0 = func, arg1 = ptrAddr, arg2 = bytecount } = syscallArgs
    let ptrPtr = word64ToPtr ptrAddr
    pure $ DetailedSyscallEnter_modify_ldt $ SyscallEnterDetails_modify_ldt
      { func = fromIntegral func
      , ptr = ptrPtr
      , bytecount = fromIntegral bytecount
      }
  Syscall_arch_prctl -> do
    let SyscallArgs{ arg0 = option, arg1 = arg2 } = syscallArgs
    pure $ DetailedSyscallEnter_arch_prctl $ SyscallEnterDetails_arch_prctl
      { option = fromIntegral option
      , arg2 = fromIntegral arg2
      }
  Syscall_sigreturn -> do
    pure $ DetailedSyscallEnter_sigreturn $ SyscallEnterDetails_sigreturn
      { 
      }
  Syscall_rt_sigreturn -> do
    pure $ DetailedSyscallEnter_rt_sigreturn $ SyscallEnterDetails_rt_sigreturn
      { 
      }
  Syscall_mmap -> do
    let SyscallArgs{ arg0 = addr, arg1 = len, arg2 = prot, arg3 = flags, arg4 = fd, arg5 = off } = syscallArgs
    pure $ DetailedSyscallEnter_mmap $ SyscallEnterDetails_mmap
      { addr = fromIntegral addr
      , len = fromIntegral len
      , prot = fromIntegral prot
      , flags = fromIntegral flags
      , fd = fromIntegral fd
      , off = fromIntegral off
      }
  Syscall_set_thread_area -> do
    let SyscallArgs{ arg0 = u_infoAddr } = syscallArgs
    let u_infoPtr = word64ToPtr u_infoAddr
    pure $ DetailedSyscallEnter_set_thread_area $ SyscallEnterDetails_set_thread_area
      { u_info = u_infoPtr
      }
  Syscall_get_thread_area -> do
    let SyscallArgs{ arg0 = u_infoAddr } = syscallArgs
    let u_infoPtr = word64ToPtr u_infoAddr
    pure $ DetailedSyscallEnter_get_thread_area $ SyscallEnterDetails_get_thread_area
      { u_info = u_infoPtr
      }
  Syscall_vm86old -> do
    let SyscallArgs{ arg0 = user_vm86Addr } = syscallArgs
    let user_vm86Ptr = word64ToPtr user_vm86Addr
    pure $ DetailedSyscallEnter_vm86old $ SyscallEnterDetails_vm86old
      { user_vm86 = user_vm86Ptr
      }
  Syscall_vm86 -> do
    let SyscallArgs{ arg0 = cmd, arg1 = arg } = syscallArgs
    pure $ DetailedSyscallEnter_vm86 $ SyscallEnterDetails_vm86
      { cmd = fromIntegral cmd
      , arg = fromIntegral arg
      }
  Syscall_ioprio_set -> do
    let SyscallArgs{ arg0 = which, arg1 = who, arg2 = ioprio } = syscallArgs
    pure $ DetailedSyscallEnter_ioprio_set $ SyscallEnterDetails_ioprio_set
      { which = fromIntegral which
      , who = fromIntegral who
      , ioprio = fromIntegral ioprio
      }
  Syscall_ioprio_get -> do
    let SyscallArgs{ arg0 = which, arg1 = who } = syscallArgs
    pure $ DetailedSyscallEnter_ioprio_get $ SyscallEnterDetails_ioprio_get
      { which = fromIntegral which
      , who = fromIntegral who
      }
  Syscall_getrandom -> do
    let SyscallArgs{ arg0 = bufAddr, arg1 = count, arg2 = flags } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_getrandom $ SyscallEnterDetails_getrandom
      { buf = bufPtr
      , bufBS
      , count = fromIntegral count
      , flags = fromIntegral flags
      }
  Syscall_pciconfig_read -> do
    let SyscallArgs{ arg0 = bus, arg1 = dfn, arg2 = off, arg3 = len, arg4 = bufAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_pciconfig_read $ SyscallEnterDetails_pciconfig_read
      { bus = fromIntegral bus
      , dfn = fromIntegral dfn
      , off = fromIntegral off
      , len = fromIntegral len
      , buf = bufPtr
      }
  Syscall_pciconfig_write -> do
    let SyscallArgs{ arg0 = bus, arg1 = dfn, arg2 = off, arg3 = len, arg4 = bufAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_pciconfig_write $ SyscallEnterDetails_pciconfig_write
      { bus = fromIntegral bus
      , dfn = fromIntegral dfn
      , off = fromIntegral off
      , len = fromIntegral len
      , buf = bufPtr
      }
  Syscall_io_setup -> do
    let SyscallArgs{ arg0 = nr_events, arg1 = ctxpAddr } = syscallArgs
    let ctxpPtr = word64ToPtr ctxpAddr
    pure $ DetailedSyscallEnter_io_setup $ SyscallEnterDetails_io_setup
      { nr_events = fromIntegral nr_events
      , ctxp = ctxpPtr
      }
  Syscall_io_destroy -> do
    let SyscallArgs{ arg0 = ctx } = syscallArgs
    pure $ DetailedSyscallEnter_io_destroy $ SyscallEnterDetails_io_destroy
      { ctx = fromIntegral ctx
      }
  Syscall_io_submit -> do
    let SyscallArgs{ arg0 = ctx_id, arg1 = nr, arg2 = iocbppAddr } = syscallArgs
    let iocbppPtr = word64ToPtr iocbppAddr
    pure $ DetailedSyscallEnter_io_submit $ SyscallEnterDetails_io_submit
      { ctx_id = fromIntegral ctx_id
      , nr = fromIntegral nr
      , iocbpp = iocbppPtr
      }
  Syscall_io_cancel -> do
    let SyscallArgs{ arg0 = ctx_id, arg1 = iocbAddr, arg2 = resultAddr } = syscallArgs
    let iocbPtr = word64ToPtr iocbAddr
    let resultPtr = word64ToPtr resultAddr
    pure $ DetailedSyscallEnter_io_cancel $ SyscallEnterDetails_io_cancel
      { ctx_id = fromIntegral ctx_id
      , iocb = iocbPtr
      , result = resultPtr
      }
  Syscall_io_getevents -> do
    let SyscallArgs{ arg0 = ctx_id, arg1 = min_nr, arg2 = nr, arg3 = eventsAddr, arg4 = timeoutAddr } = syscallArgs
    let eventsPtr = word64ToPtr eventsAddr
    let timeoutPtr = word64ToPtr timeoutAddr
    pure $ DetailedSyscallEnter_io_getevents $ SyscallEnterDetails_io_getevents
      { ctx_id = fromIntegral ctx_id
      , min_nr = fromIntegral min_nr
      , nr = fromIntegral nr
      , events = eventsPtr
      , timeout = timeoutPtr
      }
  Syscall_io_pgetevents -> do
    let SyscallArgs{ arg0 = ctx_id, arg1 = min_nr, arg2 = nr, arg3 = eventsAddr, arg4 = timeoutAddr, arg5 = usigAddr } = syscallArgs
    let eventsPtr = word64ToPtr eventsAddr
    let timeoutPtr = word64ToPtr timeoutAddr
    let usigPtr = word64ToPtr usigAddr
    pure $ DetailedSyscallEnter_io_pgetevents $ SyscallEnterDetails_io_pgetevents
      { ctx_id = fromIntegral ctx_id
      , min_nr = fromIntegral min_nr
      , nr = fromIntegral nr
      , events = eventsPtr
      , timeout = timeoutPtr
      , usig = usigPtr
      }
  Syscall_bdflush -> do
    let SyscallArgs{ arg0 = func, arg1 = data_ } = syscallArgs
    pure $ DetailedSyscallEnter_bdflush $ SyscallEnterDetails_bdflush
      { func = fromIntegral func
      , data_ = fromIntegral data_
      }
  Syscall_getcwd -> do
    let SyscallArgs{ arg0 = bufAddr, arg1 = size } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_getcwd $ SyscallEnterDetails_getcwd
      { buf = bufPtr
      , bufBS
      , size = fromIntegral size
      }
  Syscall_lookup_dcookie -> do
    let SyscallArgs{ arg0 = cookie64, arg1 = bufAddr, arg2 = len } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_lookup_dcookie $ SyscallEnterDetails_lookup_dcookie
      { cookie64 = fromIntegral cookie64
      , buf = bufPtr
      , bufBS
      , len = fromIntegral len
      }
  Syscall_eventfd2 -> do
    let SyscallArgs{ arg0 = count, arg1 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_eventfd2 $ SyscallEnterDetails_eventfd2
      { count = fromIntegral count
      , flags = fromIntegral flags
      }
  Syscall_eventfd -> do
    let SyscallArgs{ arg0 = count } = syscallArgs
    pure $ DetailedSyscallEnter_eventfd $ SyscallEnterDetails_eventfd
      { count = fromIntegral count
      }
  Syscall_epoll_create1 -> do
    let SyscallArgs{ arg0 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_epoll_create1 $ SyscallEnterDetails_epoll_create1
      { flags = fromIntegral flags
      }
  Syscall_epoll_create -> do
    let SyscallArgs{ arg0 = size } = syscallArgs
    pure $ DetailedSyscallEnter_epoll_create $ SyscallEnterDetails_epoll_create
      { size = fromIntegral size
      }
  Syscall_epoll_ctl -> do
    let SyscallArgs{ arg0 = epfd, arg1 = op, arg2 = fd, arg3 = eventAddr } = syscallArgs
    let eventPtr = word64ToPtr eventAddr
    pure $ DetailedSyscallEnter_epoll_ctl $ SyscallEnterDetails_epoll_ctl
      { epfd = fromIntegral epfd
      , op = fromIntegral op
      , fd = fromIntegral fd
      , event = eventPtr
      }
  Syscall_epoll_wait -> do
    let SyscallArgs{ arg0 = epfd, arg1 = eventsAddr, arg2 = maxevents, arg3 = timeout } = syscallArgs
    let eventsPtr = word64ToPtr eventsAddr
    pure $ DetailedSyscallEnter_epoll_wait $ SyscallEnterDetails_epoll_wait
      { epfd = fromIntegral epfd
      , events = eventsPtr
      , maxevents = fromIntegral maxevents
      , timeout = fromIntegral timeout
      }
  Syscall_epoll_pwait -> do
    let SyscallArgs{ arg0 = epfd, arg1 = eventsAddr, arg2 = maxevents, arg3 = timeout, arg4 = sigmaskAddr, arg5 = sigsetsize } = syscallArgs
    let eventsPtr = word64ToPtr eventsAddr
    let sigmaskPtr = word64ToPtr sigmaskAddr
    pure $ DetailedSyscallEnter_epoll_pwait $ SyscallEnterDetails_epoll_pwait
      { epfd = fromIntegral epfd
      , events = eventsPtr
      , maxevents = fromIntegral maxevents
      , timeout = fromIntegral timeout
      , sigmask = sigmaskPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_uselib -> do
    let SyscallArgs{ arg0 = libraryAddr } = syscallArgs
    let libraryPtr = word64ToPtr libraryAddr
    libraryBS <- peekNullTerminatedBytes proc libraryPtr
    pure $ DetailedSyscallEnter_uselib $ SyscallEnterDetails_uselib
      { library = libraryPtr
      , libraryBS
      }
  Syscall_execveat -> do
    let SyscallArgs{ arg0 = fd, arg1 = filenameAddr, arg2 = argvAddr, arg3 = envpAddr, arg4 = flags } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let argvPtr = word64ToPtr argvAddr
    let envpPtr = word64ToPtr envpAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_execveat $ SyscallEnterDetails_execveat
      { fd = fromIntegral fd
      , filename = filenamePtr
      , filenameBS
      , argv = argvPtr
      , envp = envpPtr
      , flags = fromIntegral flags
      }
  Syscall_fcntl -> do
    let SyscallArgs{ arg0 = fd, arg1 = cmd, arg2 = arg } = syscallArgs
    pure $ DetailedSyscallEnter_fcntl $ SyscallEnterDetails_fcntl
      { fd = fromIntegral fd
      , cmd = fromIntegral cmd
      , arg = fromIntegral arg
      }
  Syscall_fcntl64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = cmd, arg2 = arg } = syscallArgs
    pure $ DetailedSyscallEnter_fcntl64 $ SyscallEnterDetails_fcntl64
      { fd = fromIntegral fd
      , cmd = fromIntegral cmd
      , arg = fromIntegral arg
      }
  Syscall_name_to_handle_at -> do
    let SyscallArgs{ arg0 = dfd, arg1 = nameAddr, arg2 = handleAddr, arg3 = mnt_idAddr, arg4 = flag } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    let handlePtr = word64ToPtr handleAddr
    let mnt_idPtr = word64ToPtr mnt_idAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_name_to_handle_at $ SyscallEnterDetails_name_to_handle_at
      { dfd = fromIntegral dfd
      , name = namePtr
      , nameBS
      , handle = handlePtr
      , mnt_id = mnt_idPtr
      , flag = fromIntegral flag
      }
  Syscall_open_by_handle_at -> do
    let SyscallArgs{ arg0 = mountdirfd, arg1 = handleAddr, arg2 = flags } = syscallArgs
    let handlePtr = word64ToPtr handleAddr
    pure $ DetailedSyscallEnter_open_by_handle_at $ SyscallEnterDetails_open_by_handle_at
      { mountdirfd = fromIntegral mountdirfd
      , handle = handlePtr
      , flags = fromIntegral flags
      }
  Syscall_dup3 -> do
    let SyscallArgs{ arg0 = oldfd, arg1 = newfd, arg2 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_dup3 $ SyscallEnterDetails_dup3
      { oldfd = fromIntegral oldfd
      , newfd = fromIntegral newfd
      , flags = fromIntegral flags
      }
  Syscall_dup2 -> do
    let SyscallArgs{ arg0 = oldfd, arg1 = newfd } = syscallArgs
    pure $ DetailedSyscallEnter_dup2 $ SyscallEnterDetails_dup2
      { oldfd = fromIntegral oldfd
      , newfd = fromIntegral newfd
      }
  Syscall_dup -> do
    let SyscallArgs{ arg0 = fildes } = syscallArgs
    pure $ DetailedSyscallEnter_dup $ SyscallEnterDetails_dup
      { fildes = fromIntegral fildes
      }
  Syscall_sysfs -> do
    let SyscallArgs{ arg0 = option, arg1 = arg1, arg2 = arg2 } = syscallArgs
    pure $ DetailedSyscallEnter_sysfs $ SyscallEnterDetails_sysfs
      { option = fromIntegral option
      , arg1 = fromIntegral arg1
      , arg2 = fromIntegral arg2
      }
  Syscall_ioctl -> do
    let SyscallArgs{ arg0 = fd, arg1 = cmd, arg2 = arg } = syscallArgs
    pure $ DetailedSyscallEnter_ioctl $ SyscallEnterDetails_ioctl
      { fd = fromIntegral fd
      , cmd = fromIntegral cmd
      , arg = fromIntegral arg
      }
  Syscall_flock -> do
    let SyscallArgs{ arg0 = fd, arg1 = cmd } = syscallArgs
    pure $ DetailedSyscallEnter_flock $ SyscallEnterDetails_flock
      { fd = fromIntegral fd
      , cmd = fromIntegral cmd
      }
  Syscall_mknodat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = mode, arg3 = dev } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_mknodat $ SyscallEnterDetails_mknodat
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , mode = fromIntegral mode
      , dev = fromIntegral dev
      }
  Syscall_mknod -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = mode, arg2 = dev } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_mknod $ SyscallEnterDetails_mknod
      { filename = filenamePtr
      , filenameBS
      , mode = fromIntegral mode
      , dev = fromIntegral dev
      }
  Syscall_mkdirat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = pathnameAddr, arg2 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_mkdirat $ SyscallEnterDetails_mkdirat
      { dfd = fromIntegral dfd
      , pathname = pathnamePtr
      , pathnameBS
      , mode = fromIntegral mode
      }
  Syscall_mkdir -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_mkdir $ SyscallEnterDetails_mkdir
      { pathname = pathnamePtr
      , pathnameBS
      , mode = fromIntegral mode
      }
  Syscall_rmdir -> do
    let SyscallArgs{ arg0 = pathnameAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_rmdir $ SyscallEnterDetails_rmdir
      { pathname = pathnamePtr
      , pathnameBS
      }
  Syscall_unlinkat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = pathnameAddr, arg2 = flag } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_unlinkat $ SyscallEnterDetails_unlinkat
      { dfd = fromIntegral dfd
      , pathname = pathnamePtr
      , pathnameBS
      , flag = fromIntegral flag
      }
  Syscall_unlink -> do
    let SyscallArgs{ arg0 = pathnameAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_unlink $ SyscallEnterDetails_unlink
      { pathname = pathnamePtr
      , pathnameBS
      }
  Syscall_symlinkat -> do
    let SyscallArgs{ arg0 = oldnameAddr, arg1 = newdfd, arg2 = newnameAddr } = syscallArgs
    let oldnamePtr = word64ToPtr oldnameAddr
    let newnamePtr = word64ToPtr newnameAddr
    oldnameBS <- peekNullTerminatedBytes proc oldnamePtr
    newnameBS <- peekNullTerminatedBytes proc newnamePtr
    pure $ DetailedSyscallEnter_symlinkat $ SyscallEnterDetails_symlinkat
      { oldname = oldnamePtr
      , oldnameBS
      , newdfd = fromIntegral newdfd
      , newname = newnamePtr
      , newnameBS
      }
  Syscall_symlink -> do
    let SyscallArgs{ arg0 = oldnameAddr, arg1 = newnameAddr } = syscallArgs
    let oldnamePtr = word64ToPtr oldnameAddr
    let newnamePtr = word64ToPtr newnameAddr
    oldnameBS <- peekNullTerminatedBytes proc oldnamePtr
    newnameBS <- peekNullTerminatedBytes proc newnamePtr
    pure $ DetailedSyscallEnter_symlink $ SyscallEnterDetails_symlink
      { oldname = oldnamePtr
      , oldnameBS
      , newname = newnamePtr
      , newnameBS
      }
  Syscall_linkat -> do
    let SyscallArgs{ arg0 = olddfd, arg1 = oldnameAddr, arg2 = newdfd, arg3 = newnameAddr, arg4 = flags } = syscallArgs
    let oldnamePtr = word64ToPtr oldnameAddr
    let newnamePtr = word64ToPtr newnameAddr
    oldnameBS <- peekNullTerminatedBytes proc oldnamePtr
    newnameBS <- peekNullTerminatedBytes proc newnamePtr
    pure $ DetailedSyscallEnter_linkat $ SyscallEnterDetails_linkat
      { olddfd = fromIntegral olddfd
      , oldname = oldnamePtr
      , oldnameBS
      , newdfd = fromIntegral newdfd
      , newname = newnamePtr
      , newnameBS
      , flags = fromIntegral flags
      }
  Syscall_link -> do
    let SyscallArgs{ arg0 = oldnameAddr, arg1 = newnameAddr } = syscallArgs
    let oldnamePtr = word64ToPtr oldnameAddr
    let newnamePtr = word64ToPtr newnameAddr
    oldnameBS <- peekNullTerminatedBytes proc oldnamePtr
    newnameBS <- peekNullTerminatedBytes proc newnamePtr
    pure $ DetailedSyscallEnter_link $ SyscallEnterDetails_link
      { oldname = oldnamePtr
      , oldnameBS
      , newname = newnamePtr
      , newnameBS
      }
  Syscall_umount -> do
    let SyscallArgs{ arg0 = nameAddr, arg1 = flags } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_umount $ SyscallEnterDetails_umount
      { name = namePtr
      , nameBS
      , flags = fromIntegral flags
      }
  Syscall_oldumount -> do
    let SyscallArgs{ arg0 = nameAddr } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_oldumount $ SyscallEnterDetails_oldumount
      { name = namePtr
      , nameBS
      }
  Syscall_mount -> do
    let SyscallArgs{ arg0 = dev_nameAddr, arg1 = dir_nameAddr, arg2 = type_Addr, arg3 = flags, arg4 = data_Addr } = syscallArgs
    let dev_namePtr = word64ToPtr dev_nameAddr
    let dir_namePtr = word64ToPtr dir_nameAddr
    let type_Ptr = word64ToPtr type_Addr
    let data_Ptr = word64ToPtr data_Addr
    dev_nameBS <- peekNullTerminatedBytes proc dev_namePtr
    dir_nameBS <- peekNullTerminatedBytes proc dir_namePtr
    type_BS <- peekNullTerminatedBytes proc type_Ptr
    pure $ DetailedSyscallEnter_mount $ SyscallEnterDetails_mount
      { dev_name = dev_namePtr
      , dev_nameBS
      , dir_name = dir_namePtr
      , dir_nameBS
      , type_ = type_Ptr
      , type_BS
      , flags = fromIntegral flags
      , data_ = data_Ptr
      }
  Syscall_pivot_root -> do
    let SyscallArgs{ arg0 = new_rootAddr, arg1 = put_oldAddr } = syscallArgs
    let new_rootPtr = word64ToPtr new_rootAddr
    let put_oldPtr = word64ToPtr put_oldAddr
    new_rootBS <- peekNullTerminatedBytes proc new_rootPtr
    put_oldBS <- peekNullTerminatedBytes proc put_oldPtr
    pure $ DetailedSyscallEnter_pivot_root $ SyscallEnterDetails_pivot_root
      { new_root = new_rootPtr
      , new_rootBS
      , put_old = put_oldPtr
      , put_oldBS
      }
  Syscall_fanotify_init -> do
    let SyscallArgs{ arg0 = flags, arg1 = event_f_flags } = syscallArgs
    pure $ DetailedSyscallEnter_fanotify_init $ SyscallEnterDetails_fanotify_init
      { flags = fromIntegral flags
      , event_f_flags = fromIntegral event_f_flags
      }
  Syscall_fanotify_mark -> do
    let SyscallArgs{ arg0 = fanotify_fd, arg1 = flags, arg2 = mask, arg3 = dfd, arg4 = pathnameAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_fanotify_mark $ SyscallEnterDetails_fanotify_mark
      { fanotify_fd = fromIntegral fanotify_fd
      , flags = fromIntegral flags
      , mask = fromIntegral mask
      , dfd = fromIntegral dfd
      , pathname = pathnamePtr
      , pathnameBS
      }
  Syscall_inotify_init1 -> do
    let SyscallArgs{ arg0 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_inotify_init1 $ SyscallEnterDetails_inotify_init1
      { flags = fromIntegral flags
      }
  Syscall_inotify_init -> do
    pure $ DetailedSyscallEnter_inotify_init $ SyscallEnterDetails_inotify_init
      { 
      }
  Syscall_inotify_add_watch -> do
    let SyscallArgs{ arg0 = fd, arg1 = pathnameAddr, arg2 = mask } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_inotify_add_watch $ SyscallEnterDetails_inotify_add_watch
      { fd = fromIntegral fd
      , pathname = pathnamePtr
      , pathnameBS
      , mask = fromIntegral mask
      }
  Syscall_inotify_rm_watch -> do
    let SyscallArgs{ arg0 = fd, arg1 = wd } = syscallArgs
    pure $ DetailedSyscallEnter_inotify_rm_watch $ SyscallEnterDetails_inotify_rm_watch
      { fd = fromIntegral fd
      , wd = fromIntegral wd
      }
  Syscall_truncate -> do
    let SyscallArgs{ arg0 = pathAddr, arg1 = length_ } = syscallArgs
    let pathPtr = word64ToPtr pathAddr
    pathBS <- peekNullTerminatedBytes proc pathPtr
    pure $ DetailedSyscallEnter_truncate $ SyscallEnterDetails_truncate
      { path = pathPtr
      , pathBS
      , length_ = fromIntegral length_
      }
  Syscall_ftruncate -> do
    let SyscallArgs{ arg0 = fd, arg1 = length_ } = syscallArgs
    pure $ DetailedSyscallEnter_ftruncate $ SyscallEnterDetails_ftruncate
      { fd = fromIntegral fd
      , length_ = fromIntegral length_
      }
  Syscall_truncate64 -> do
    let SyscallArgs{ arg0 = pathAddr, arg1 = length_ } = syscallArgs
    let pathPtr = word64ToPtr pathAddr
    pathBS <- peekNullTerminatedBytes proc pathPtr
    pure $ DetailedSyscallEnter_truncate64 $ SyscallEnterDetails_truncate64
      { path = pathPtr
      , pathBS
      , length_ = fromIntegral length_
      }
  Syscall_ftruncate64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = length_ } = syscallArgs
    pure $ DetailedSyscallEnter_ftruncate64 $ SyscallEnterDetails_ftruncate64
      { fd = fromIntegral fd
      , length_ = fromIntegral length_
      }
  Syscall_fallocate -> do
    let SyscallArgs{ arg0 = fd, arg1 = mode, arg2 = offset, arg3 = len } = syscallArgs
    pure $ DetailedSyscallEnter_fallocate $ SyscallEnterDetails_fallocate
      { fd = fromIntegral fd
      , mode = fromIntegral mode
      , offset = fromIntegral offset
      , len = fromIntegral len
      }
  Syscall_chdir -> do
    let SyscallArgs{ arg0 = filenameAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_chdir $ SyscallEnterDetails_chdir
      { filename = filenamePtr
      , filenameBS
      }
  Syscall_fchdir -> do
    let SyscallArgs{ arg0 = fd } = syscallArgs
    pure $ DetailedSyscallEnter_fchdir $ SyscallEnterDetails_fchdir
      { fd = fromIntegral fd
      }
  Syscall_chroot -> do
    let SyscallArgs{ arg0 = filenameAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_chroot $ SyscallEnterDetails_chroot
      { filename = filenamePtr
      , filenameBS
      }
  Syscall_fchmod -> do
    let SyscallArgs{ arg0 = fd, arg1 = mode } = syscallArgs
    pure $ DetailedSyscallEnter_fchmod $ SyscallEnterDetails_fchmod
      { fd = fromIntegral fd
      , mode = fromIntegral mode
      }
  Syscall_fchmodat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = mode } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_fchmodat $ SyscallEnterDetails_fchmodat
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , mode = fromIntegral mode
      }
  Syscall_chmod -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = mode } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_chmod $ SyscallEnterDetails_chmod
      { filename = filenamePtr
      , filenameBS
      , mode = fromIntegral mode
      }
  Syscall_fchownat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = user, arg3 = group, arg4 = flag } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_fchownat $ SyscallEnterDetails_fchownat
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , user = fromIntegral user
      , group = fromIntegral group
      , flag = fromIntegral flag
      }
  Syscall_chown -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = user, arg2 = group } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_chown $ SyscallEnterDetails_chown
      { filename = filenamePtr
      , filenameBS
      , user = fromIntegral user
      , group = fromIntegral group
      }
  Syscall_lchown -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = user, arg2 = group } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_lchown $ SyscallEnterDetails_lchown
      { filename = filenamePtr
      , filenameBS
      , user = fromIntegral user
      , group = fromIntegral group
      }
  Syscall_fchown -> do
    let SyscallArgs{ arg0 = fd, arg1 = user, arg2 = group } = syscallArgs
    pure $ DetailedSyscallEnter_fchown $ SyscallEnterDetails_fchown
      { fd = fromIntegral fd
      , user = fromIntegral user
      , group = fromIntegral group
      }
  Syscall_vhangup -> do
    pure $ DetailedSyscallEnter_vhangup $ SyscallEnterDetails_vhangup
      { 
      }
  Syscall_quotactl -> do
    let SyscallArgs{ arg0 = cmd, arg1 = specialAddr, arg2 = id_, arg3 = addrAddr } = syscallArgs
    let specialPtr = word64ToPtr specialAddr
    let addrPtr = word64ToPtr addrAddr
    specialBS <- peekNullTerminatedBytes proc specialPtr
    pure $ DetailedSyscallEnter_quotactl $ SyscallEnterDetails_quotactl
      { cmd = fromIntegral cmd
      , special = specialPtr
      , specialBS
      , id_ = fromIntegral id_
      , addr = addrPtr
      }
  Syscall_lseek -> do
    let SyscallArgs{ arg0 = fd, arg1 = offset, arg2 = whence } = syscallArgs
    pure $ DetailedSyscallEnter_lseek $ SyscallEnterDetails_lseek
      { fd = fromIntegral fd
      , offset = fromIntegral offset
      , whence = fromIntegral whence
      }
  Syscall_pread64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count, arg3 = pos } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_pread64 $ SyscallEnterDetails_pread64
      { fd = fromIntegral fd
      , buf = bufPtr
      , bufBS
      , count = fromIntegral count
      , pos = fromIntegral pos
      }
  Syscall_pwrite64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count, arg3 = pos } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_pwrite64 $ SyscallEnterDetails_pwrite64
      { fd = fromIntegral fd
      , buf = bufPtr
      , bufBS
      , count = fromIntegral count
      , pos = fromIntegral pos
      }
  Syscall_readv -> do
    let SyscallArgs{ arg0 = fd, arg1 = vecAddr, arg2 = vlen } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_readv $ SyscallEnterDetails_readv
      { fd = fromIntegral fd
      , vec = vecPtr
      , vlen = fromIntegral vlen
      }
  Syscall_writev -> do
    let SyscallArgs{ arg0 = fd, arg1 = vecAddr, arg2 = vlen } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_writev $ SyscallEnterDetails_writev
      { fd = fromIntegral fd
      , vec = vecPtr
      , vlen = fromIntegral vlen
      }
  Syscall_preadv -> do
    let SyscallArgs{ arg0 = fd, arg1 = vecAddr, arg2 = vlen, arg3 = pos_l, arg4 = pos_h } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_preadv $ SyscallEnterDetails_preadv
      { fd = fromIntegral fd
      , vec = vecPtr
      , vlen = fromIntegral vlen
      , pos_l = fromIntegral pos_l
      , pos_h = fromIntegral pos_h
      }
  Syscall_preadv2 -> do
    let SyscallArgs{ arg0 = fd, arg1 = vecAddr, arg2 = vlen, arg3 = pos_l, arg4 = pos_h, arg5 = flags } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_preadv2 $ SyscallEnterDetails_preadv2
      { fd = fromIntegral fd
      , vec = vecPtr
      , vlen = fromIntegral vlen
      , pos_l = fromIntegral pos_l
      , pos_h = fromIntegral pos_h
      , flags = fromIntegral flags
      }
  Syscall_pwritev -> do
    let SyscallArgs{ arg0 = fd, arg1 = vecAddr, arg2 = vlen, arg3 = pos_l, arg4 = pos_h } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_pwritev $ SyscallEnterDetails_pwritev
      { fd = fromIntegral fd
      , vec = vecPtr
      , vlen = fromIntegral vlen
      , pos_l = fromIntegral pos_l
      , pos_h = fromIntegral pos_h
      }
  Syscall_pwritev2 -> do
    let SyscallArgs{ arg0 = fd, arg1 = vecAddr, arg2 = vlen, arg3 = pos_l, arg4 = pos_h, arg5 = flags } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_pwritev2 $ SyscallEnterDetails_pwritev2
      { fd = fromIntegral fd
      , vec = vecPtr
      , vlen = fromIntegral vlen
      , pos_l = fromIntegral pos_l
      , pos_h = fromIntegral pos_h
      , flags = fromIntegral flags
      }
  Syscall_sendfile -> do
    let SyscallArgs{ arg0 = out_fd, arg1 = in_fd, arg2 = offsetAddr, arg3 = count } = syscallArgs
    let offsetPtr = word64ToPtr offsetAddr
    pure $ DetailedSyscallEnter_sendfile $ SyscallEnterDetails_sendfile
      { out_fd = fromIntegral out_fd
      , in_fd = fromIntegral in_fd
      , offset = offsetPtr
      , count = fromIntegral count
      }
  Syscall_sendfile64 -> do
    let SyscallArgs{ arg0 = out_fd, arg1 = in_fd, arg2 = offsetAddr, arg3 = count } = syscallArgs
    let offsetPtr = word64ToPtr offsetAddr
    pure $ DetailedSyscallEnter_sendfile64 $ SyscallEnterDetails_sendfile64
      { out_fd = fromIntegral out_fd
      , in_fd = fromIntegral in_fd
      , offset = offsetPtr
      , count = fromIntegral count
      }
  Syscall_copy_file_range -> do
    let SyscallArgs{ arg0 = fd_in, arg1 = off_inAddr, arg2 = fd_out, arg3 = off_outAddr, arg4 = len, arg5 = flags } = syscallArgs
    let off_inPtr = word64ToPtr off_inAddr
    let off_outPtr = word64ToPtr off_outAddr
    pure $ DetailedSyscallEnter_copy_file_range $ SyscallEnterDetails_copy_file_range
      { fd_in = fromIntegral fd_in
      , off_in = off_inPtr
      , fd_out = fromIntegral fd_out
      , off_out = off_outPtr
      , len = fromIntegral len
      , flags = fromIntegral flags
      }
  Syscall_getdents -> do
    let SyscallArgs{ arg0 = fd, arg1 = direntAddr, arg2 = count } = syscallArgs
    let direntPtr = word64ToPtr direntAddr
    pure $ DetailedSyscallEnter_getdents $ SyscallEnterDetails_getdents
      { fd = fromIntegral fd
      , dirent = direntPtr
      , count = fromIntegral count
      }
  Syscall_getdents64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = direntAddr, arg2 = count } = syscallArgs
    let direntPtr = word64ToPtr direntAddr
    pure $ DetailedSyscallEnter_getdents64 $ SyscallEnterDetails_getdents64
      { fd = fromIntegral fd
      , dirent = direntPtr
      , count = fromIntegral count
      }
  Syscall_poll -> do
    let SyscallArgs{ arg0 = ufdsAddr, arg1 = nfds, arg2 = timeout_msecs } = syscallArgs
    let ufdsPtr = word64ToPtr ufdsAddr
    pure $ DetailedSyscallEnter_poll $ SyscallEnterDetails_poll
      { ufds = ufdsPtr
      , nfds = fromIntegral nfds
      , timeout_msecs = fromIntegral timeout_msecs
      }
  Syscall_ppoll -> do
    let SyscallArgs{ arg0 = ufdsAddr, arg1 = nfds, arg2 = tspAddr, arg3 = sigmaskAddr, arg4 = sigsetsize } = syscallArgs
    let ufdsPtr = word64ToPtr ufdsAddr
    let tspPtr = word64ToPtr tspAddr
    let sigmaskPtr = word64ToPtr sigmaskAddr
    pure $ DetailedSyscallEnter_ppoll $ SyscallEnterDetails_ppoll
      { ufds = ufdsPtr
      , nfds = fromIntegral nfds
      , tsp = tspPtr
      , sigmask = sigmaskPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_signalfd4 -> do
    let SyscallArgs{ arg0 = ufd, arg1 = user_maskAddr, arg2 = sizemask, arg3 = flags } = syscallArgs
    let user_maskPtr = word64ToPtr user_maskAddr
    pure $ DetailedSyscallEnter_signalfd4 $ SyscallEnterDetails_signalfd4
      { ufd = fromIntegral ufd
      , user_mask = user_maskPtr
      , sizemask = fromIntegral sizemask
      , flags = fromIntegral flags
      }
  Syscall_signalfd -> do
    let SyscallArgs{ arg0 = ufd, arg1 = user_maskAddr, arg2 = sizemask } = syscallArgs
    let user_maskPtr = word64ToPtr user_maskAddr
    pure $ DetailedSyscallEnter_signalfd $ SyscallEnterDetails_signalfd
      { ufd = fromIntegral ufd
      , user_mask = user_maskPtr
      , sizemask = fromIntegral sizemask
      }
  Syscall_vmsplice -> do
    let SyscallArgs{ arg0 = fd, arg1 = uiovAddr, arg2 = nr_segs, arg3 = flags } = syscallArgs
    let uiovPtr = word64ToPtr uiovAddr
    pure $ DetailedSyscallEnter_vmsplice $ SyscallEnterDetails_vmsplice
      { fd = fromIntegral fd
      , uiov = uiovPtr
      , nr_segs = fromIntegral nr_segs
      , flags = fromIntegral flags
      }
  Syscall_splice -> do
    let SyscallArgs{ arg0 = fd_in, arg1 = off_inAddr, arg2 = fd_out, arg3 = off_outAddr, arg4 = len, arg5 = flags } = syscallArgs
    let off_inPtr = word64ToPtr off_inAddr
    let off_outPtr = word64ToPtr off_outAddr
    pure $ DetailedSyscallEnter_splice $ SyscallEnterDetails_splice
      { fd_in = fromIntegral fd_in
      , off_in = off_inPtr
      , fd_out = fromIntegral fd_out
      , off_out = off_outPtr
      , len = fromIntegral len
      , flags = fromIntegral flags
      }
  Syscall_tee -> do
    let SyscallArgs{ arg0 = fdin, arg1 = fdout, arg2 = len, arg3 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_tee $ SyscallEnterDetails_tee
      { fdin = fromIntegral fdin
      , fdout = fromIntegral fdout
      , len = fromIntegral len
      , flags = fromIntegral flags
      }
  Syscall_readlinkat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = pathnameAddr, arg2 = bufAddr, arg3 = bufsiz } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let bufPtr = word64ToPtr bufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_readlinkat $ SyscallEnterDetails_readlinkat
      { dfd = fromIntegral dfd
      , pathname = pathnamePtr
      , pathnameBS
      , buf = bufPtr
      , bufBS
      , bufsiz = fromIntegral bufsiz
      }
  Syscall_readlink -> do
    let SyscallArgs{ arg0 = pathAddr, arg1 = bufAddr, arg2 = bufsiz } = syscallArgs
    let pathPtr = word64ToPtr pathAddr
    let bufPtr = word64ToPtr bufAddr
    pathBS <- peekNullTerminatedBytes proc pathPtr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_readlink $ SyscallEnterDetails_readlink
      { path = pathPtr
      , pathBS
      , buf = bufPtr
      , bufBS
      , bufsiz = fromIntegral bufsiz
      }
  Syscall_stat64 -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = statbufAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let statbufPtr = word64ToPtr statbufAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_stat64 $ SyscallEnterDetails_stat64
      { filename = filenamePtr
      , filenameBS
      , statbuf = statbufPtr
      }
  Syscall_lstat64 -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = statbufAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let statbufPtr = word64ToPtr statbufAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_lstat64 $ SyscallEnterDetails_lstat64
      { filename = filenamePtr
      , filenameBS
      , statbuf = statbufPtr
      }
  Syscall_fstat64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = statbufAddr } = syscallArgs
    let statbufPtr = word64ToPtr statbufAddr
    pure $ DetailedSyscallEnter_fstat64 $ SyscallEnterDetails_fstat64
      { fd = fromIntegral fd
      , statbuf = statbufPtr
      }
  Syscall_fstatat64 -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = statbufAddr, arg3 = flag } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let statbufPtr = word64ToPtr statbufAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_fstatat64 $ SyscallEnterDetails_fstatat64
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , statbuf = statbufPtr
      , flag = fromIntegral flag
      }
  Syscall_statx -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = flags, arg3 = mask, arg4 = bufferAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let bufferPtr = word64ToPtr bufferAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_statx $ SyscallEnterDetails_statx
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , flags = fromIntegral flags
      , mask = fromIntegral mask
      , buffer = bufferPtr
      }
  Syscall_statfs -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = bufAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let bufPtr = word64ToPtr bufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_statfs $ SyscallEnterDetails_statfs
      { pathname = pathnamePtr
      , pathnameBS
      , buf = bufPtr
      }
  Syscall_statfs64 -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = sz, arg2 = bufAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let bufPtr = word64ToPtr bufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_statfs64 $ SyscallEnterDetails_statfs64
      { pathname = pathnamePtr
      , pathnameBS
      , sz = fromIntegral sz
      , buf = bufPtr
      }
  Syscall_fstatfs -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_fstatfs $ SyscallEnterDetails_fstatfs
      { fd = fromIntegral fd
      , buf = bufPtr
      }
  Syscall_fstatfs64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = sz, arg2 = bufAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_fstatfs64 $ SyscallEnterDetails_fstatfs64
      { fd = fromIntegral fd
      , sz = fromIntegral sz
      , buf = bufPtr
      }
  Syscall_ustat -> do
    let SyscallArgs{ arg0 = dev, arg1 = ubufAddr } = syscallArgs
    let ubufPtr = word64ToPtr ubufAddr
    pure $ DetailedSyscallEnter_ustat $ SyscallEnterDetails_ustat
      { dev = fromIntegral dev
      , ubuf = ubufPtr
      }
  Syscall_sync -> do
    pure $ DetailedSyscallEnter_sync $ SyscallEnterDetails_sync
      { 
      }
  Syscall_syncfs -> do
    let SyscallArgs{ arg0 = fd } = syscallArgs
    pure $ DetailedSyscallEnter_syncfs $ SyscallEnterDetails_syncfs
      { fd = fromIntegral fd
      }
  Syscall_fsync -> do
    let SyscallArgs{ arg0 = fd } = syscallArgs
    pure $ DetailedSyscallEnter_fsync $ SyscallEnterDetails_fsync
      { fd = fromIntegral fd
      }
  Syscall_fdatasync -> do
    let SyscallArgs{ arg0 = fd } = syscallArgs
    pure $ DetailedSyscallEnter_fdatasync $ SyscallEnterDetails_fdatasync
      { fd = fromIntegral fd
      }
  Syscall_sync_file_range -> do
    let SyscallArgs{ arg0 = fd, arg1 = offset, arg2 = nbytes, arg3 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_sync_file_range $ SyscallEnterDetails_sync_file_range
      { fd = fromIntegral fd
      , offset = fromIntegral offset
      , nbytes = fromIntegral nbytes
      , flags = fromIntegral flags
      }
  Syscall_sync_file_range2 -> do
    let SyscallArgs{ arg0 = fd, arg1 = flags, arg2 = offset, arg3 = nbytes } = syscallArgs
    pure $ DetailedSyscallEnter_sync_file_range2 $ SyscallEnterDetails_sync_file_range2
      { fd = fromIntegral fd
      , flags = fromIntegral flags
      , offset = fromIntegral offset
      , nbytes = fromIntegral nbytes
      }
  Syscall_timerfd_create -> do
    let SyscallArgs{ arg0 = clockid, arg1 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_timerfd_create $ SyscallEnterDetails_timerfd_create
      { clockid = fromIntegral clockid
      , flags = fromIntegral flags
      }
  Syscall_timerfd_settime -> do
    let SyscallArgs{ arg0 = ufd, arg1 = flags, arg2 = utmrAddr, arg3 = otmrAddr } = syscallArgs
    let utmrPtr = word64ToPtr utmrAddr
    let otmrPtr = word64ToPtr otmrAddr
    pure $ DetailedSyscallEnter_timerfd_settime $ SyscallEnterDetails_timerfd_settime
      { ufd = fromIntegral ufd
      , flags = fromIntegral flags
      , utmr = utmrPtr
      , otmr = otmrPtr
      }
  Syscall_timerfd_gettime -> do
    let SyscallArgs{ arg0 = ufd, arg1 = otmrAddr } = syscallArgs
    let otmrPtr = word64ToPtr otmrAddr
    pure $ DetailedSyscallEnter_timerfd_gettime $ SyscallEnterDetails_timerfd_gettime
      { ufd = fromIntegral ufd
      , otmr = otmrPtr
      }
  Syscall_userfaultfd -> do
    let SyscallArgs{ arg0 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_userfaultfd $ SyscallEnterDetails_userfaultfd
      { flags = fromIntegral flags
      }
  Syscall_utimensat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = utimesAddr, arg3 = flags } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let utimesPtr = word64ToPtr utimesAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_utimensat $ SyscallEnterDetails_utimensat
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , utimes = utimesPtr
      , flags = fromIntegral flags
      }
  Syscall_futimesat -> do
    let SyscallArgs{ arg0 = dfd, arg1 = filenameAddr, arg2 = utimesAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let utimesPtr = word64ToPtr utimesAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_futimesat $ SyscallEnterDetails_futimesat
      { dfd = fromIntegral dfd
      , filename = filenamePtr
      , filenameBS
      , utimes = utimesPtr
      }
  Syscall_utimes -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = utimesAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let utimesPtr = word64ToPtr utimesAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_utimes $ SyscallEnterDetails_utimes
      { filename = filenamePtr
      , filenameBS
      , utimes = utimesPtr
      }
  Syscall_utime -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = timesAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let timesPtr = word64ToPtr timesAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    pure $ DetailedSyscallEnter_utime $ SyscallEnterDetails_utime
      { filename = filenamePtr
      , filenameBS
      , times = timesPtr
      }
  Syscall_setxattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = nameAddr, arg2 = valueAddr, arg3 = size, arg4 = flags } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let namePtr = word64ToPtr nameAddr
    let valuePtr = word64ToPtr valueAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_setxattr $ SyscallEnterDetails_setxattr
      { pathname = pathnamePtr
      , pathnameBS
      , name = namePtr
      , nameBS
      , value = valuePtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      }
  Syscall_lsetxattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = nameAddr, arg2 = valueAddr, arg3 = size, arg4 = flags } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let namePtr = word64ToPtr nameAddr
    let valuePtr = word64ToPtr valueAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_lsetxattr $ SyscallEnterDetails_lsetxattr
      { pathname = pathnamePtr
      , pathnameBS
      , name = namePtr
      , nameBS
      , value = valuePtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      }
  Syscall_fsetxattr -> do
    let SyscallArgs{ arg0 = fd, arg1 = nameAddr, arg2 = valueAddr, arg3 = size, arg4 = flags } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    let valuePtr = word64ToPtr valueAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_fsetxattr $ SyscallEnterDetails_fsetxattr
      { fd = fromIntegral fd
      , name = namePtr
      , nameBS
      , value = valuePtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      }
  Syscall_getxattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = nameAddr, arg2 = valueAddr, arg3 = size } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let namePtr = word64ToPtr nameAddr
    let valuePtr = word64ToPtr valueAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_getxattr $ SyscallEnterDetails_getxattr
      { pathname = pathnamePtr
      , pathnameBS
      , name = namePtr
      , nameBS
      , value = valuePtr
      , size = fromIntegral size
      }
  Syscall_lgetxattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = nameAddr, arg2 = valueAddr, arg3 = size } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let namePtr = word64ToPtr nameAddr
    let valuePtr = word64ToPtr valueAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_lgetxattr $ SyscallEnterDetails_lgetxattr
      { pathname = pathnamePtr
      , pathnameBS
      , name = namePtr
      , nameBS
      , value = valuePtr
      , size = fromIntegral size
      }
  Syscall_fgetxattr -> do
    let SyscallArgs{ arg0 = fd, arg1 = nameAddr, arg2 = valueAddr, arg3 = size } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    let valuePtr = word64ToPtr valueAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_fgetxattr $ SyscallEnterDetails_fgetxattr
      { fd = fromIntegral fd
      , name = namePtr
      , nameBS
      , value = valuePtr
      , size = fromIntegral size
      }
  Syscall_listxattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = listAddr, arg2 = size } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let listPtr = word64ToPtr listAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    listBS <- peekNullTerminatedBytes proc listPtr
    pure $ DetailedSyscallEnter_listxattr $ SyscallEnterDetails_listxattr
      { pathname = pathnamePtr
      , pathnameBS
      , list = listPtr
      , listBS
      , size = fromIntegral size
      }
  Syscall_llistxattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = listAddr, arg2 = size } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let listPtr = word64ToPtr listAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    listBS <- peekNullTerminatedBytes proc listPtr
    pure $ DetailedSyscallEnter_llistxattr $ SyscallEnterDetails_llistxattr
      { pathname = pathnamePtr
      , pathnameBS
      , list = listPtr
      , listBS
      , size = fromIntegral size
      }
  Syscall_flistxattr -> do
    let SyscallArgs{ arg0 = fd, arg1 = listAddr, arg2 = size } = syscallArgs
    let listPtr = word64ToPtr listAddr
    listBS <- peekNullTerminatedBytes proc listPtr
    pure $ DetailedSyscallEnter_flistxattr $ SyscallEnterDetails_flistxattr
      { fd = fromIntegral fd
      , list = listPtr
      , listBS
      , size = fromIntegral size
      }
  Syscall_removexattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = nameAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let namePtr = word64ToPtr nameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_removexattr $ SyscallEnterDetails_removexattr
      { pathname = pathnamePtr
      , pathnameBS
      , name = namePtr
      , nameBS
      }
  Syscall_lremovexattr -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = nameAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let namePtr = word64ToPtr nameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_lremovexattr $ SyscallEnterDetails_lremovexattr
      { pathname = pathnamePtr
      , pathnameBS
      , name = namePtr
      , nameBS
      }
  Syscall_fremovexattr -> do
    let SyscallArgs{ arg0 = fd, arg1 = nameAddr } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_fremovexattr $ SyscallEnterDetails_fremovexattr
      { fd = fromIntegral fd
      , name = namePtr
      , nameBS
      }
  Syscall_msgget -> do
    let SyscallArgs{ arg0 = key, arg1 = msgflg } = syscallArgs
    pure $ DetailedSyscallEnter_msgget $ SyscallEnterDetails_msgget
      { key = fromIntegral key
      , msgflg = fromIntegral msgflg
      }
  Syscall_msgctl -> do
    let SyscallArgs{ arg0 = msqid, arg1 = cmd, arg2 = bufAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_msgctl $ SyscallEnterDetails_msgctl
      { msqid = fromIntegral msqid
      , cmd = fromIntegral cmd
      , buf = bufPtr
      }
  Syscall_msgsnd -> do
    let SyscallArgs{ arg0 = msqid, arg1 = msgpAddr, arg2 = msgsz, arg3 = msgflg } = syscallArgs
    let msgpPtr = word64ToPtr msgpAddr
    pure $ DetailedSyscallEnter_msgsnd $ SyscallEnterDetails_msgsnd
      { msqid = fromIntegral msqid
      , msgp = msgpPtr
      , msgsz = fromIntegral msgsz
      , msgflg = fromIntegral msgflg
      }
  Syscall_msgrcv -> do
    let SyscallArgs{ arg0 = msqid, arg1 = msgpAddr, arg2 = msgsz, arg3 = msgtyp, arg4 = msgflg } = syscallArgs
    let msgpPtr = word64ToPtr msgpAddr
    pure $ DetailedSyscallEnter_msgrcv $ SyscallEnterDetails_msgrcv
      { msqid = fromIntegral msqid
      , msgp = msgpPtr
      , msgsz = fromIntegral msgsz
      , msgtyp = fromIntegral msgtyp
      , msgflg = fromIntegral msgflg
      }
  Syscall_semget -> do
    let SyscallArgs{ arg0 = key, arg1 = nsems, arg2 = semflg } = syscallArgs
    pure $ DetailedSyscallEnter_semget $ SyscallEnterDetails_semget
      { key = fromIntegral key
      , nsems = fromIntegral nsems
      , semflg = fromIntegral semflg
      }
  Syscall_semctl -> do
    let SyscallArgs{ arg0 = semid, arg1 = semnum, arg2 = cmd, arg3 = arg } = syscallArgs
    pure $ DetailedSyscallEnter_semctl $ SyscallEnterDetails_semctl
      { semid = fromIntegral semid
      , semnum = fromIntegral semnum
      , cmd = fromIntegral cmd
      , arg = fromIntegral arg
      }
  Syscall_semtimedop -> do
    let SyscallArgs{ arg0 = semid, arg1 = tsopsAddr, arg2 = nsops, arg3 = timeoutAddr } = syscallArgs
    let tsopsPtr = word64ToPtr tsopsAddr
    let timeoutPtr = word64ToPtr timeoutAddr
    pure $ DetailedSyscallEnter_semtimedop $ SyscallEnterDetails_semtimedop
      { semid = fromIntegral semid
      , tsops = tsopsPtr
      , nsops = fromIntegral nsops
      , timeout = timeoutPtr
      }
  Syscall_semop -> do
    let SyscallArgs{ arg0 = semid, arg1 = tsopsAddr, arg2 = nsops } = syscallArgs
    let tsopsPtr = word64ToPtr tsopsAddr
    pure $ DetailedSyscallEnter_semop $ SyscallEnterDetails_semop
      { semid = fromIntegral semid
      , tsops = tsopsPtr
      , nsops = fromIntegral nsops
      }
  Syscall_shmget -> do
    let SyscallArgs{ arg0 = key, arg1 = size, arg2 = shmflg } = syscallArgs
    pure $ DetailedSyscallEnter_shmget $ SyscallEnterDetails_shmget
      { key = fromIntegral key
      , size = fromIntegral size
      , shmflg = fromIntegral shmflg
      }
  Syscall_shmctl -> do
    let SyscallArgs{ arg0 = shmid, arg1 = cmd, arg2 = bufAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_shmctl $ SyscallEnterDetails_shmctl
      { shmid = fromIntegral shmid
      , cmd = fromIntegral cmd
      , buf = bufPtr
      }
  Syscall_shmat -> do
    let SyscallArgs{ arg0 = shmid, arg1 = shmaddrAddr, arg2 = shmflg } = syscallArgs
    let shmaddrPtr = word64ToPtr shmaddrAddr
    shmaddrBS <- peekNullTerminatedBytes proc shmaddrPtr
    pure $ DetailedSyscallEnter_shmat $ SyscallEnterDetails_shmat
      { shmid = fromIntegral shmid
      , shmaddr = shmaddrPtr
      , shmaddrBS
      , shmflg = fromIntegral shmflg
      }
  Syscall_shmdt -> do
    let SyscallArgs{ arg0 = shmaddrAddr } = syscallArgs
    let shmaddrPtr = word64ToPtr shmaddrAddr
    shmaddrBS <- peekNullTerminatedBytes proc shmaddrPtr
    pure $ DetailedSyscallEnter_shmdt $ SyscallEnterDetails_shmdt
      { shmaddr = shmaddrPtr
      , shmaddrBS
      }
  Syscall_ipc -> do
    let SyscallArgs{ arg0 = call, arg1 = first_, arg2 = second_, arg3 = third, arg4 = ptrAddr, arg5 = fifth } = syscallArgs
    let ptrPtr = word64ToPtr ptrAddr
    pure $ DetailedSyscallEnter_ipc $ SyscallEnterDetails_ipc
      { call = fromIntegral call
      , first_ = fromIntegral first_
      , second_ = fromIntegral second_
      , third = fromIntegral third
      , ptr = ptrPtr
      , fifth = fromIntegral fifth
      }
  Syscall_acct -> do
    let SyscallArgs{ arg0 = nameAddr } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_acct $ SyscallEnterDetails_acct
      { name = namePtr
      , nameBS
      }
  Syscall_perf_event_open -> do
    let SyscallArgs{ arg0 = attr_uptrAddr, arg1 = pid_, arg2 = cpu, arg3 = group_fd, arg4 = flags } = syscallArgs
    let attr_uptrPtr = word64ToPtr attr_uptrAddr
    pure $ DetailedSyscallEnter_perf_event_open $ SyscallEnterDetails_perf_event_open
      { attr_uptr = attr_uptrPtr
      , pid_ = fromIntegral pid_
      , cpu = fromIntegral cpu
      , group_fd = fromIntegral group_fd
      , flags = fromIntegral flags
      }
  Syscall_personality -> do
    let SyscallArgs{ arg0 = personality } = syscallArgs
    pure $ DetailedSyscallEnter_personality $ SyscallEnterDetails_personality
      { personality = fromIntegral personality
      }
  Syscall_waitid -> do
    let SyscallArgs{ arg0 = which, arg1 = upid, arg2 = infopAddr, arg3 = options, arg4 = ruAddr } = syscallArgs
    let infopPtr = word64ToPtr infopAddr
    let ruPtr = word64ToPtr ruAddr
    pure $ DetailedSyscallEnter_waitid $ SyscallEnterDetails_waitid
      { which = fromIntegral which
      , upid = fromIntegral upid
      , infop = infopPtr
      , options = fromIntegral options
      , ru = ruPtr
      }
  Syscall_wait4 -> do
    let SyscallArgs{ arg0 = upid, arg1 = stat_addrAddr, arg2 = options, arg3 = ruAddr } = syscallArgs
    let stat_addrPtr = word64ToPtr stat_addrAddr
    let ruPtr = word64ToPtr ruAddr
    pure $ DetailedSyscallEnter_wait4 $ SyscallEnterDetails_wait4
      { upid = fromIntegral upid
      , stat_addr = stat_addrPtr
      , options = fromIntegral options
      , ru = ruPtr
      }
  Syscall_waitpid -> do
    let SyscallArgs{ arg0 = pid_, arg1 = stat_addrAddr, arg2 = options } = syscallArgs
    let stat_addrPtr = word64ToPtr stat_addrAddr
    pure $ DetailedSyscallEnter_waitpid $ SyscallEnterDetails_waitpid
      { pid_ = fromIntegral pid_
      , stat_addr = stat_addrPtr
      , options = fromIntegral options
      }
  Syscall_set_tid_address -> do
    let SyscallArgs{ arg0 = tidptrAddr } = syscallArgs
    let tidptrPtr = word64ToPtr tidptrAddr
    pure $ DetailedSyscallEnter_set_tid_address $ SyscallEnterDetails_set_tid_address
      { tidptr = tidptrPtr
      }
  Syscall_fork -> do
    pure $ DetailedSyscallEnter_fork $ SyscallEnterDetails_fork
      { 
      }
  Syscall_vfork -> do
    pure $ DetailedSyscallEnter_vfork $ SyscallEnterDetails_vfork
      { 
      }
  Syscall_clone -> do
    let SyscallArgs{ arg0 = clone_flags, arg1 = newsp, arg2 = parent_tidptrAddr, arg3 = child_tidptrAddr, arg4 = tls } = syscallArgs
    let parent_tidptrPtr = word64ToPtr parent_tidptrAddr
    let child_tidptrPtr = word64ToPtr child_tidptrAddr
    pure $ DetailedSyscallEnter_clone $ SyscallEnterDetails_clone
      { clone_flags = fromIntegral clone_flags
      , newsp = fromIntegral newsp
      , parent_tidptr = parent_tidptrPtr
      , child_tidptr = child_tidptrPtr
      , tls = fromIntegral tls
      }
  Syscall_unshare -> do
    let SyscallArgs{ arg0 = unshare_flags } = syscallArgs
    pure $ DetailedSyscallEnter_unshare $ SyscallEnterDetails_unshare
      { unshare_flags = fromIntegral unshare_flags
      }
  Syscall_set_robust_list -> do
    let SyscallArgs{ arg0 = head_Addr, arg1 = len } = syscallArgs
    let headPtr = word64ToPtr head_Addr
    pure $ DetailedSyscallEnter_set_robust_list $ SyscallEnterDetails_set_robust_list
      { head_ = headPtr
      , len = fromIntegral len
      }
  Syscall_get_robust_list -> do
    let SyscallArgs{ arg0 = pid_, arg1 = head_ptrAddr, arg2 = len_ptrAddr } = syscallArgs
    let head_ptrPtr = word64ToPtr head_ptrAddr
    let len_ptrPtr = word64ToPtr len_ptrAddr
    pure $ DetailedSyscallEnter_get_robust_list $ SyscallEnterDetails_get_robust_list
      { pid_ = fromIntegral pid_
      , head_ptr = head_ptrPtr
      , len_ptr = len_ptrPtr
      }
  Syscall_futex -> do
    let SyscallArgs{ arg0 = uaddrAddr, arg1 = op, arg2 = val, arg3 = utimeAddr, arg4 = uaddr2Addr, arg5 = val3 } = syscallArgs
    let uaddrPtr = word64ToPtr uaddrAddr
    let utimePtr = word64ToPtr utimeAddr
    let uaddr2Ptr = word64ToPtr uaddr2Addr
    pure $ DetailedSyscallEnter_futex $ SyscallEnterDetails_futex
      { uaddr = uaddrPtr
      , op = fromIntegral op
      , val = fromIntegral val
      , utime = utimePtr
      , uaddr2 = uaddr2Ptr
      , val3 = fromIntegral val3
      }
  Syscall_getgroups -> do
    let SyscallArgs{ arg0 = gidsetsize, arg1 = grouplistAddr } = syscallArgs
    let grouplistPtr = word64ToPtr grouplistAddr
    pure $ DetailedSyscallEnter_getgroups $ SyscallEnterDetails_getgroups
      { gidsetsize = fromIntegral gidsetsize
      , grouplist = grouplistPtr
      }
  Syscall_setgroups -> do
    let SyscallArgs{ arg0 = gidsetsize, arg1 = grouplistAddr } = syscallArgs
    let grouplistPtr = word64ToPtr grouplistAddr
    pure $ DetailedSyscallEnter_setgroups $ SyscallEnterDetails_setgroups
      { gidsetsize = fromIntegral gidsetsize
      , grouplist = grouplistPtr
      }
  Syscall_kcmp -> do
    let SyscallArgs{ arg0 = pid1, arg1 = pid2, arg2 = type_, arg3 = idx1, arg4 = idx2 } = syscallArgs
    pure $ DetailedSyscallEnter_kcmp $ SyscallEnterDetails_kcmp
      { pid1 = fromIntegral pid1
      , pid2 = fromIntegral pid2
      , type_ = fromIntegral type_
      , idx1 = fromIntegral idx1
      , idx2 = fromIntegral idx2
      }
  Syscall_kexec_load -> do
    let SyscallArgs{ arg0 = entry, arg1 = nr_segments, arg2 = segmentsAddr, arg3 = flags } = syscallArgs
    let segmentsPtr = word64ToPtr segmentsAddr
    pure $ DetailedSyscallEnter_kexec_load $ SyscallEnterDetails_kexec_load
      { entry = fromIntegral entry
      , nr_segments = fromIntegral nr_segments
      , segments = segmentsPtr
      , flags = fromIntegral flags
      }
  Syscall_kexec_file_load -> do
    let SyscallArgs{ arg0 = kernel_fd, arg1 = initrd_fd, arg2 = cmdline_len, arg3 = cmdline_ptrAddr, arg4 = flags } = syscallArgs
    let cmdline_ptrPtr = word64ToPtr cmdline_ptrAddr
    cmdline_ptrBS <- peekNullTerminatedBytes proc cmdline_ptrPtr
    pure $ DetailedSyscallEnter_kexec_file_load $ SyscallEnterDetails_kexec_file_load
      { kernel_fd = fromIntegral kernel_fd
      , initrd_fd = fromIntegral initrd_fd
      , cmdline_len = fromIntegral cmdline_len
      , cmdline_ptr = cmdline_ptrPtr
      , cmdline_ptrBS
      , flags = fromIntegral flags
      }
  Syscall_delete_module -> do
    let SyscallArgs{ arg0 = name_userAddr, arg1 = flags } = syscallArgs
    let name_userPtr = word64ToPtr name_userAddr
    name_userBS <- peekNullTerminatedBytes proc name_userPtr
    pure $ DetailedSyscallEnter_delete_module $ SyscallEnterDetails_delete_module
      { name_user = name_userPtr
      , name_userBS
      , flags = fromIntegral flags
      }
  Syscall_init_module -> do
    let SyscallArgs{ arg0 = umodAddr, arg1 = len, arg2 = uargsAddr } = syscallArgs
    let umodPtr = word64ToPtr umodAddr
    let uargsPtr = word64ToPtr uargsAddr
    uargsBS <- peekNullTerminatedBytes proc uargsPtr
    pure $ DetailedSyscallEnter_init_module $ SyscallEnterDetails_init_module
      { umod = umodPtr
      , len = fromIntegral len
      , uargs = uargsPtr
      , uargsBS
      }
  Syscall_finit_module -> do
    let SyscallArgs{ arg0 = fd, arg1 = uargsAddr, arg2 = flags } = syscallArgs
    let uargsPtr = word64ToPtr uargsAddr
    uargsBS <- peekNullTerminatedBytes proc uargsPtr
    pure $ DetailedSyscallEnter_finit_module $ SyscallEnterDetails_finit_module
      { fd = fromIntegral fd
      , uargs = uargsPtr
      , uargsBS
      , flags = fromIntegral flags
      }
  Syscall_setns -> do
    let SyscallArgs{ arg0 = fd, arg1 = nstype } = syscallArgs
    pure $ DetailedSyscallEnter_setns $ SyscallEnterDetails_setns
      { fd = fromIntegral fd
      , nstype = fromIntegral nstype
      }
  Syscall_syslog -> do
    let SyscallArgs{ arg0 = type_, arg1 = bufAddr, arg2 = len } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufBS <- peekNullTerminatedBytes proc bufPtr
    pure $ DetailedSyscallEnter_syslog $ SyscallEnterDetails_syslog
      { type_ = fromIntegral type_
      , buf = bufPtr
      , bufBS
      , len = fromIntegral len
      }
  Syscall_ptrace -> do
    let SyscallArgs{ arg0 = request, arg1 = pid_, arg2 = addr, arg3 = data_ } = syscallArgs
    pure $ DetailedSyscallEnter_ptrace $ SyscallEnterDetails_ptrace
      { request = fromIntegral request
      , pid_ = fromIntegral pid_
      , addr = fromIntegral addr
      , data_ = fromIntegral data_
      }
  Syscall_reboot -> do
    let SyscallArgs{ arg0 = magic1, arg1 = magic2, arg2 = cmd, arg3 = argAddr } = syscallArgs
    let argPtr = word64ToPtr argAddr
    pure $ DetailedSyscallEnter_reboot $ SyscallEnterDetails_reboot
      { magic1 = fromIntegral magic1
      , magic2 = fromIntegral magic2
      , cmd = fromIntegral cmd
      , arg = argPtr
      }
  Syscall_rseq -> do
    let SyscallArgs{ arg0 = rseqAddr, arg1 = rseq_len, arg2 = flags, arg3 = sig } = syscallArgs
    let rseqPtr = word64ToPtr rseqAddr
    pure $ DetailedSyscallEnter_rseq $ SyscallEnterDetails_rseq
      { rseq = rseqPtr
      , rseq_len = fromIntegral rseq_len
      , flags = fromIntegral flags
      , sig = fromIntegral sig
      }
  Syscall_nice -> do
    let SyscallArgs{ arg0 = increment } = syscallArgs
    pure $ DetailedSyscallEnter_nice $ SyscallEnterDetails_nice
      { increment = fromIntegral increment
      }
  Syscall_sched_setscheduler -> do
    let SyscallArgs{ arg0 = pid_, arg1 = policy, arg2 = paramAddr } = syscallArgs
    let paramPtr = word64ToPtr paramAddr
    pure $ DetailedSyscallEnter_sched_setscheduler $ SyscallEnterDetails_sched_setscheduler
      { pid_ = fromIntegral pid_
      , policy = fromIntegral policy
      , param = paramPtr
      }
  Syscall_sched_setparam -> do
    let SyscallArgs{ arg0 = pid_, arg1 = paramAddr } = syscallArgs
    let paramPtr = word64ToPtr paramAddr
    pure $ DetailedSyscallEnter_sched_setparam $ SyscallEnterDetails_sched_setparam
      { pid_ = fromIntegral pid_
      , param = paramPtr
      }
  Syscall_sched_setattr -> do
    let SyscallArgs{ arg0 = pid_, arg1 = uattrAddr, arg2 = flags } = syscallArgs
    let uattrPtr = word64ToPtr uattrAddr
    pure $ DetailedSyscallEnter_sched_setattr $ SyscallEnterDetails_sched_setattr
      { pid_ = fromIntegral pid_
      , uattr = uattrPtr
      , flags = fromIntegral flags
      }
  Syscall_sched_getscheduler -> do
    let SyscallArgs{ arg0 = pid_ } = syscallArgs
    pure $ DetailedSyscallEnter_sched_getscheduler $ SyscallEnterDetails_sched_getscheduler
      { pid_ = fromIntegral pid_
      }
  Syscall_sched_getparam -> do
    let SyscallArgs{ arg0 = pid_, arg1 = paramAddr } = syscallArgs
    let paramPtr = word64ToPtr paramAddr
    pure $ DetailedSyscallEnter_sched_getparam $ SyscallEnterDetails_sched_getparam
      { pid_ = fromIntegral pid_
      , param = paramPtr
      }
  Syscall_sched_getattr -> do
    let SyscallArgs{ arg0 = pid_, arg1 = uattrAddr, arg2 = size, arg3 = flags } = syscallArgs
    let uattrPtr = word64ToPtr uattrAddr
    pure $ DetailedSyscallEnter_sched_getattr $ SyscallEnterDetails_sched_getattr
      { pid_ = fromIntegral pid_
      , uattr = uattrPtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      }
  Syscall_sched_setaffinity -> do
    let SyscallArgs{ arg0 = pid_, arg1 = len, arg2 = user_mask_ptrAddr } = syscallArgs
    let user_mask_ptrPtr = word64ToPtr user_mask_ptrAddr
    pure $ DetailedSyscallEnter_sched_setaffinity $ SyscallEnterDetails_sched_setaffinity
      { pid_ = fromIntegral pid_
      , len = fromIntegral len
      , user_mask_ptr = user_mask_ptrPtr
      }
  Syscall_sched_getaffinity -> do
    let SyscallArgs{ arg0 = pid_, arg1 = len, arg2 = user_mask_ptrAddr } = syscallArgs
    let user_mask_ptrPtr = word64ToPtr user_mask_ptrAddr
    pure $ DetailedSyscallEnter_sched_getaffinity $ SyscallEnterDetails_sched_getaffinity
      { pid_ = fromIntegral pid_
      , len = fromIntegral len
      , user_mask_ptr = user_mask_ptrPtr
      }
  Syscall_sched_yield -> do
    pure $ DetailedSyscallEnter_sched_yield $ SyscallEnterDetails_sched_yield
      { 
      }
  Syscall_sched_get_priority_max -> do
    let SyscallArgs{ arg0 = policy } = syscallArgs
    pure $ DetailedSyscallEnter_sched_get_priority_max $ SyscallEnterDetails_sched_get_priority_max
      { policy = fromIntegral policy
      }
  Syscall_sched_get_priority_min -> do
    let SyscallArgs{ arg0 = policy } = syscallArgs
    pure $ DetailedSyscallEnter_sched_get_priority_min $ SyscallEnterDetails_sched_get_priority_min
      { policy = fromIntegral policy
      }
  Syscall_sched_rr_get_interval -> do
    let SyscallArgs{ arg0 = pid_, arg1 = intervalAddr } = syscallArgs
    let intervalPtr = word64ToPtr intervalAddr
    pure $ DetailedSyscallEnter_sched_rr_get_interval $ SyscallEnterDetails_sched_rr_get_interval
      { pid_ = fromIntegral pid_
      , interval = intervalPtr
      }
  Syscall_membarrier -> do
    let SyscallArgs{ arg0 = cmd, arg1 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_membarrier $ SyscallEnterDetails_membarrier
      { cmd = fromIntegral cmd
      , flags = fromIntegral flags
      }
  Syscall_seccomp -> do
    let SyscallArgs{ arg0 = op, arg1 = flags, arg2 = uargsAddr } = syscallArgs
    let uargsPtr = word64ToPtr uargsAddr
    pure $ DetailedSyscallEnter_seccomp $ SyscallEnterDetails_seccomp
      { op = fromIntegral op
      , flags = fromIntegral flags
      , uargs = uargsPtr
      }
  Syscall_restart_syscall -> do
    pure $ DetailedSyscallEnter_restart_syscall $ SyscallEnterDetails_restart_syscall
      { 
      }
  Syscall_rt_sigprocmask -> do
    let SyscallArgs{ arg0 = how, arg1 = nsetAddr, arg2 = osetAddr, arg3 = sigsetsize } = syscallArgs
    let nsetPtr = word64ToPtr nsetAddr
    let osetPtr = word64ToPtr osetAddr
    pure $ DetailedSyscallEnter_rt_sigprocmask $ SyscallEnterDetails_rt_sigprocmask
      { how = fromIntegral how
      , nset = nsetPtr
      , oset = osetPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_rt_sigpending -> do
    let SyscallArgs{ arg0 = usetAddr, arg1 = sigsetsize } = syscallArgs
    let usetPtr = word64ToPtr usetAddr
    pure $ DetailedSyscallEnter_rt_sigpending $ SyscallEnterDetails_rt_sigpending
      { uset = usetPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_kill -> do
    let SyscallArgs{ arg0 = pid_, arg1 = sig } = syscallArgs
    pure $ DetailedSyscallEnter_kill $ SyscallEnterDetails_kill
      { pid_ = fromIntegral pid_
      , sig = fromIntegral sig
      }
  Syscall_tgkill -> do
    let SyscallArgs{ arg0 = tgid, arg1 = pid_, arg2 = sig } = syscallArgs
    pure $ DetailedSyscallEnter_tgkill $ SyscallEnterDetails_tgkill
      { tgid = fromIntegral tgid
      , pid_ = fromIntegral pid_
      , sig = fromIntegral sig
      }
  Syscall_tkill -> do
    let SyscallArgs{ arg0 = pid_, arg1 = sig } = syscallArgs
    pure $ DetailedSyscallEnter_tkill $ SyscallEnterDetails_tkill
      { pid_ = fromIntegral pid_
      , sig = fromIntegral sig
      }
  Syscall_sigpending -> do
    let SyscallArgs{ arg0 = usetAddr } = syscallArgs
    let usetPtr = word64ToPtr usetAddr
    pure $ DetailedSyscallEnter_sigpending $ SyscallEnterDetails_sigpending
      { uset = usetPtr
      }
  Syscall_sigprocmask -> do
    let SyscallArgs{ arg0 = how, arg1 = nsetAddr, arg2 = osetAddr } = syscallArgs
    let nsetPtr = word64ToPtr nsetAddr
    let osetPtr = word64ToPtr osetAddr
    pure $ DetailedSyscallEnter_sigprocmask $ SyscallEnterDetails_sigprocmask
      { how = fromIntegral how
      , nset = nsetPtr
      , oset = osetPtr
      }
  Syscall_rt_sigaction -> do
    let SyscallArgs{ arg0 = sig, arg1 = actAddr, arg2 = oactAddr, arg3 = sigsetsize } = syscallArgs
    let actPtr = word64ToPtr actAddr
    let oactPtr = word64ToPtr oactAddr
    pure $ DetailedSyscallEnter_rt_sigaction $ SyscallEnterDetails_rt_sigaction
      { sig = fromIntegral sig
      , act = actPtr
      , oact = oactPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_sigaction -> do
    let SyscallArgs{ arg0 = sig, arg1 = actAddr, arg2 = oactAddr } = syscallArgs
    let actPtr = word64ToPtr actAddr
    let oactPtr = word64ToPtr oactAddr
    pure $ DetailedSyscallEnter_sigaction $ SyscallEnterDetails_sigaction
      { sig = fromIntegral sig
      , act = actPtr
      , oact = oactPtr
      }
  Syscall_sgetmask -> do
    pure $ DetailedSyscallEnter_sgetmask $ SyscallEnterDetails_sgetmask
      { 
      }
  Syscall_ssetmask -> do
    let SyscallArgs{ arg0 = newmask } = syscallArgs
    pure $ DetailedSyscallEnter_ssetmask $ SyscallEnterDetails_ssetmask
      { newmask = fromIntegral newmask
      }
  Syscall_signal -> do
    let SyscallArgs{ arg0 = sig, arg1 = handlerAddr } = syscallArgs
    let handlerPtr = word64ToPtr handlerAddr
    pure $ DetailedSyscallEnter_signal $ SyscallEnterDetails_signal
      { sig = fromIntegral sig
      , handler = handlerPtr
      }
  Syscall_pause -> do
    pure $ DetailedSyscallEnter_pause $ SyscallEnterDetails_pause
      { 
      }
  Syscall_rt_sigsuspend -> do
    let SyscallArgs{ arg0 = unewsetAddr, arg1 = sigsetsize } = syscallArgs
    let unewsetPtr = word64ToPtr unewsetAddr
    pure $ DetailedSyscallEnter_rt_sigsuspend $ SyscallEnterDetails_rt_sigsuspend
      { unewset = unewsetPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_sigsuspend -> do
    let SyscallArgs{ arg0 = mask } = syscallArgs
    pure $ DetailedSyscallEnter_sigsuspend $ SyscallEnterDetails_sigsuspend
      { mask = fromIntegral mask
      }
  Syscall_setpriority -> do
    let SyscallArgs{ arg0 = which, arg1 = who, arg2 = niceval } = syscallArgs
    pure $ DetailedSyscallEnter_setpriority $ SyscallEnterDetails_setpriority
      { which = fromIntegral which
      , who = fromIntegral who
      , niceval = fromIntegral niceval
      }
  Syscall_getpriority -> do
    let SyscallArgs{ arg0 = which, arg1 = who } = syscallArgs
    pure $ DetailedSyscallEnter_getpriority $ SyscallEnterDetails_getpriority
      { which = fromIntegral which
      , who = fromIntegral who
      }
  Syscall_setregid -> do
    let SyscallArgs{ arg0 = rgid, arg1 = egid } = syscallArgs
    pure $ DetailedSyscallEnter_setregid $ SyscallEnterDetails_setregid
      { rgid = fromIntegral rgid
      , egid = fromIntegral egid
      }
  Syscall_setgid -> do
    let SyscallArgs{ arg0 = gid } = syscallArgs
    pure $ DetailedSyscallEnter_setgid $ SyscallEnterDetails_setgid
      { gid = fromIntegral gid
      }
  Syscall_setreuid -> do
    let SyscallArgs{ arg0 = ruid, arg1 = euid } = syscallArgs
    pure $ DetailedSyscallEnter_setreuid $ SyscallEnterDetails_setreuid
      { ruid = fromIntegral ruid
      , euid = fromIntegral euid
      }
  Syscall_setuid -> do
    let SyscallArgs{ arg0 = uid } = syscallArgs
    pure $ DetailedSyscallEnter_setuid $ SyscallEnterDetails_setuid
      { uid = fromIntegral uid
      }
  Syscall_setresuid -> do
    let SyscallArgs{ arg0 = ruid, arg1 = euid, arg2 = suid } = syscallArgs
    pure $ DetailedSyscallEnter_setresuid $ SyscallEnterDetails_setresuid
      { ruid = fromIntegral ruid
      , euid = fromIntegral euid
      , suid = fromIntegral suid
      }
  Syscall_getresuid -> do
    let SyscallArgs{ arg0 = ruidpAddr, arg1 = euidpAddr, arg2 = suidpAddr } = syscallArgs
    let ruidpPtr = word64ToPtr ruidpAddr
    let euidpPtr = word64ToPtr euidpAddr
    let suidpPtr = word64ToPtr suidpAddr
    pure $ DetailedSyscallEnter_getresuid $ SyscallEnterDetails_getresuid
      { ruidp = ruidpPtr
      , euidp = euidpPtr
      , suidp = suidpPtr
      }
  Syscall_setresgid -> do
    let SyscallArgs{ arg0 = rgid, arg1 = egid, arg2 = sgid } = syscallArgs
    pure $ DetailedSyscallEnter_setresgid $ SyscallEnterDetails_setresgid
      { rgid = fromIntegral rgid
      , egid = fromIntegral egid
      , sgid = fromIntegral sgid
      }
  Syscall_getresgid -> do
    let SyscallArgs{ arg0 = rgidpAddr, arg1 = egidpAddr, arg2 = sgidpAddr } = syscallArgs
    let rgidpPtr = word64ToPtr rgidpAddr
    let egidpPtr = word64ToPtr egidpAddr
    let sgidpPtr = word64ToPtr sgidpAddr
    pure $ DetailedSyscallEnter_getresgid $ SyscallEnterDetails_getresgid
      { rgidp = rgidpPtr
      , egidp = egidpPtr
      , sgidp = sgidpPtr
      }
  Syscall_setfsuid -> do
    let SyscallArgs{ arg0 = uid } = syscallArgs
    pure $ DetailedSyscallEnter_setfsuid $ SyscallEnterDetails_setfsuid
      { uid = fromIntegral uid
      }
  Syscall_setfsgid -> do
    let SyscallArgs{ arg0 = gid } = syscallArgs
    pure $ DetailedSyscallEnter_setfsgid $ SyscallEnterDetails_setfsgid
      { gid = fromIntegral gid
      }
  Syscall_getpid -> do
    pure $ DetailedSyscallEnter_getpid $ SyscallEnterDetails_getpid
      { 
      }
  Syscall_gettid -> do
    pure $ DetailedSyscallEnter_gettid $ SyscallEnterDetails_gettid
      { 
      }
  Syscall_getppid -> do
    pure $ DetailedSyscallEnter_getppid $ SyscallEnterDetails_getppid
      { 
      }
  Syscall_getuid -> do
    pure $ DetailedSyscallEnter_getuid $ SyscallEnterDetails_getuid
      { 
      }
  Syscall_geteuid -> do
    pure $ DetailedSyscallEnter_geteuid $ SyscallEnterDetails_geteuid
      { 
      }
  Syscall_getgid -> do
    pure $ DetailedSyscallEnter_getgid $ SyscallEnterDetails_getgid
      { 
      }
  Syscall_getegid -> do
    pure $ DetailedSyscallEnter_getegid $ SyscallEnterDetails_getegid
      { 
      }
  Syscall_times -> do
    let SyscallArgs{ arg0 = tbufAddr } = syscallArgs
    let tbufPtr = word64ToPtr tbufAddr
    pure $ DetailedSyscallEnter_times $ SyscallEnterDetails_times
      { tbuf = tbufPtr
      }
  Syscall_setpgid -> do
    let SyscallArgs{ arg0 = pid_, arg1 = pgid } = syscallArgs
    pure $ DetailedSyscallEnter_setpgid $ SyscallEnterDetails_setpgid
      { pid_ = fromIntegral pid_
      , pgid = fromIntegral pgid
      }
  Syscall_getpgid -> do
    let SyscallArgs{ arg0 = pid_ } = syscallArgs
    pure $ DetailedSyscallEnter_getpgid $ SyscallEnterDetails_getpgid
      { pid_ = fromIntegral pid_
      }
  Syscall_getpgrp -> do
    pure $ DetailedSyscallEnter_getpgrp $ SyscallEnterDetails_getpgrp
      { 
      }
  Syscall_getsid -> do
    let SyscallArgs{ arg0 = pid_ } = syscallArgs
    pure $ DetailedSyscallEnter_getsid $ SyscallEnterDetails_getsid
      { pid_ = fromIntegral pid_
      }
  Syscall_setsid -> do
    pure $ DetailedSyscallEnter_setsid $ SyscallEnterDetails_setsid
      { 
      }
  Syscall_uname -> do
    let SyscallArgs{ arg0 = nameAddr } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    pure $ DetailedSyscallEnter_uname $ SyscallEnterDetails_uname
      { name = namePtr
      }
  Syscall_olduname -> do
    let SyscallArgs{ arg0 = nameAddr } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    pure $ DetailedSyscallEnter_olduname $ SyscallEnterDetails_olduname
      { name = namePtr
      }
  Syscall_sethostname -> do
    let SyscallArgs{ arg0 = nameAddr, arg1 = len } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_sethostname $ SyscallEnterDetails_sethostname
      { name = namePtr
      , nameBS
      , len = fromIntegral len
      }
  Syscall_gethostname -> do
    let SyscallArgs{ arg0 = nameAddr, arg1 = len } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_gethostname $ SyscallEnterDetails_gethostname
      { name = namePtr
      , nameBS
      , len = fromIntegral len
      }
  Syscall_setdomainname -> do
    let SyscallArgs{ arg0 = nameAddr, arg1 = len } = syscallArgs
    let namePtr = word64ToPtr nameAddr
    nameBS <- peekNullTerminatedBytes proc namePtr
    pure $ DetailedSyscallEnter_setdomainname $ SyscallEnterDetails_setdomainname
      { name = namePtr
      , nameBS
      , len = fromIntegral len
      }
  Syscall_getrlimit -> do
    let SyscallArgs{ arg0 = resource, arg1 = rlimAddr } = syscallArgs
    let rlimPtr = word64ToPtr rlimAddr
    pure $ DetailedSyscallEnter_getrlimit $ SyscallEnterDetails_getrlimit
      { resource = fromIntegral resource
      , rlim = rlimPtr
      }
  Syscall_prlimit64 -> do
    let SyscallArgs{ arg0 = pid_, arg1 = resource, arg2 = new_rlimAddr, arg3 = old_rlimAddr } = syscallArgs
    let new_rlimPtr = word64ToPtr new_rlimAddr
    let old_rlimPtr = word64ToPtr old_rlimAddr
    pure $ DetailedSyscallEnter_prlimit64 $ SyscallEnterDetails_prlimit64
      { pid_ = fromIntegral pid_
      , resource = fromIntegral resource
      , new_rlim = new_rlimPtr
      , old_rlim = old_rlimPtr
      }
  Syscall_setrlimit -> do
    let SyscallArgs{ arg0 = resource, arg1 = rlimAddr } = syscallArgs
    let rlimPtr = word64ToPtr rlimAddr
    pure $ DetailedSyscallEnter_setrlimit $ SyscallEnterDetails_setrlimit
      { resource = fromIntegral resource
      , rlim = rlimPtr
      }
  Syscall_getrusage -> do
    let SyscallArgs{ arg0 = who, arg1 = ruAddr } = syscallArgs
    let ruPtr = word64ToPtr ruAddr
    pure $ DetailedSyscallEnter_getrusage $ SyscallEnterDetails_getrusage
      { who = fromIntegral who
      , ru = ruPtr
      }
  Syscall_umask -> do
    let SyscallArgs{ arg0 = mask } = syscallArgs
    pure $ DetailedSyscallEnter_umask $ SyscallEnterDetails_umask
      { mask = fromIntegral mask
      }
  Syscall_prctl -> do
    let SyscallArgs{ arg0 = option, arg1 = arg2, arg2 = arg3, arg3 = arg4, arg4 = arg5 } = syscallArgs
    pure $ DetailedSyscallEnter_prctl $ SyscallEnterDetails_prctl
      { option = fromIntegral option
      , arg2 = fromIntegral arg2
      , arg3 = fromIntegral arg3
      , arg4 = fromIntegral arg4
      , arg5 = fromIntegral arg5
      }
  Syscall_getcpu -> do
    let SyscallArgs{ arg0 = cpupAddr, arg1 = nodepAddr, arg2 = unusedAddr } = syscallArgs
    let cpupPtr = word64ToPtr cpupAddr
    let nodepPtr = word64ToPtr nodepAddr
    let unusedPtr = word64ToPtr unusedAddr
    pure $ DetailedSyscallEnter_getcpu $ SyscallEnterDetails_getcpu
      { cpup = cpupPtr
      , nodep = nodepPtr
      , unused = unusedPtr
      }
  Syscall_sysinfo -> do
    let SyscallArgs{ arg0 = infoAddr } = syscallArgs
    let infoPtr = word64ToPtr infoAddr
    pure $ DetailedSyscallEnter_sysinfo $ SyscallEnterDetails_sysinfo
      { info = infoPtr
      }
  Syscall_nanosleep -> do
    let SyscallArgs{ arg0 = rqtpAddr, arg1 = rmtpAddr } = syscallArgs
    let rqtpPtr = word64ToPtr rqtpAddr
    let rmtpPtr = word64ToPtr rmtpAddr
    pure $ DetailedSyscallEnter_nanosleep $ SyscallEnterDetails_nanosleep
      { rqtp = rqtpPtr
      , rmtp = rmtpPtr
      }
  Syscall_getitimer -> do
    let SyscallArgs{ arg0 = which, arg1 = valueAddr } = syscallArgs
    let valuePtr = word64ToPtr valueAddr
    pure $ DetailedSyscallEnter_getitimer $ SyscallEnterDetails_getitimer
      { which = fromIntegral which
      , value = valuePtr
      }
  Syscall_alarm -> do
    let SyscallArgs{ arg0 = seconds } = syscallArgs
    pure $ DetailedSyscallEnter_alarm $ SyscallEnterDetails_alarm
      { seconds = fromIntegral seconds
      }
  Syscall_setitimer -> do
    let SyscallArgs{ arg0 = which, arg1 = valueAddr, arg2 = ovalueAddr } = syscallArgs
    let valuePtr = word64ToPtr valueAddr
    let ovaluePtr = word64ToPtr ovalueAddr
    pure $ DetailedSyscallEnter_setitimer $ SyscallEnterDetails_setitimer
      { which = fromIntegral which
      , value = valuePtr
      , ovalue = ovaluePtr
      }
  Syscall_clock_settime -> do
    let SyscallArgs{ arg0 = which_clock, arg1 = tpAddr } = syscallArgs
    let tpPtr = word64ToPtr tpAddr
    pure $ DetailedSyscallEnter_clock_settime $ SyscallEnterDetails_clock_settime
      { which_clock = fromIntegral which_clock
      , tp = tpPtr
      }
  Syscall_clock_gettime -> do
    let SyscallArgs{ arg0 = which_clock, arg1 = tpAddr } = syscallArgs
    let tpPtr = word64ToPtr tpAddr
    pure $ DetailedSyscallEnter_clock_gettime $ SyscallEnterDetails_clock_gettime
      { which_clock = fromIntegral which_clock
      , tp = tpPtr
      }
  Syscall_clock_getres -> do
    let SyscallArgs{ arg0 = which_clock, arg1 = tpAddr } = syscallArgs
    let tpPtr = word64ToPtr tpAddr
    pure $ DetailedSyscallEnter_clock_getres $ SyscallEnterDetails_clock_getres
      { which_clock = fromIntegral which_clock
      , tp = tpPtr
      }
  Syscall_clock_nanosleep -> do
    let SyscallArgs{ arg0 = which_clock, arg1 = flags, arg2 = rqtpAddr, arg3 = rmtpAddr } = syscallArgs
    let rqtpPtr = word64ToPtr rqtpAddr
    let rmtpPtr = word64ToPtr rmtpAddr
    pure $ DetailedSyscallEnter_clock_nanosleep $ SyscallEnterDetails_clock_nanosleep
      { which_clock = fromIntegral which_clock
      , flags = fromIntegral flags
      , rqtp = rqtpPtr
      , rmtp = rmtpPtr
      }
  Syscall_timer_create -> do
    let SyscallArgs{ arg0 = which_clock, arg1 = timer_event_specAddr, arg2 = created_timer_idAddr } = syscallArgs
    let timer_event_specPtr = word64ToPtr timer_event_specAddr
    let created_timer_idPtr = word64ToPtr created_timer_idAddr
    pure $ DetailedSyscallEnter_timer_create $ SyscallEnterDetails_timer_create
      { which_clock = fromIntegral which_clock
      , timer_event_spec = timer_event_specPtr
      , created_timer_id = created_timer_idPtr
      }
  Syscall_timer_gettime -> do
    let SyscallArgs{ arg0 = timer_id, arg1 = settingAddr } = syscallArgs
    let settingPtr = word64ToPtr settingAddr
    pure $ DetailedSyscallEnter_timer_gettime $ SyscallEnterDetails_timer_gettime
      { timer_id = fromIntegral timer_id
      , setting = settingPtr
      }
  Syscall_timer_getoverrun -> do
    let SyscallArgs{ arg0 = timer_id } = syscallArgs
    pure $ DetailedSyscallEnter_timer_getoverrun $ SyscallEnterDetails_timer_getoverrun
      { timer_id = fromIntegral timer_id
      }
  Syscall_timer_settime -> do
    let SyscallArgs{ arg0 = timer_id, arg1 = flags, arg2 = new_settingAddr, arg3 = old_settingAddr } = syscallArgs
    let new_settingPtr = word64ToPtr new_settingAddr
    let old_settingPtr = word64ToPtr old_settingAddr
    pure $ DetailedSyscallEnter_timer_settime $ SyscallEnterDetails_timer_settime
      { timer_id = fromIntegral timer_id
      , flags = fromIntegral flags
      , new_setting = new_settingPtr
      , old_setting = old_settingPtr
      }
  Syscall_timer_delete -> do
    let SyscallArgs{ arg0 = timer_id } = syscallArgs
    pure $ DetailedSyscallEnter_timer_delete $ SyscallEnterDetails_timer_delete
      { timer_id = fromIntegral timer_id
      }
  Syscall_clock_adjtime -> do
    let SyscallArgs{ arg0 = which_clock, arg1 = utxAddr } = syscallArgs
    let utxPtr = word64ToPtr utxAddr
    pure $ DetailedSyscallEnter_clock_adjtime $ SyscallEnterDetails_clock_adjtime
      { which_clock = fromIntegral which_clock
      , utx = utxPtr
      }
  Syscall_time -> do
    let SyscallArgs{ arg0 = tlocAddr } = syscallArgs
    let tlocPtr = word64ToPtr tlocAddr
    pure $ DetailedSyscallEnter_time $ SyscallEnterDetails_time
      { tloc = tlocPtr
      }
  Syscall_stime -> do
    let SyscallArgs{ arg0 = tptrAddr } = syscallArgs
    let tptrPtr = word64ToPtr tptrAddr
    pure $ DetailedSyscallEnter_stime $ SyscallEnterDetails_stime
      { tptr = tptrPtr
      }
  Syscall_gettimeofday -> do
    let SyscallArgs{ arg0 = tvAddr, arg1 = tzAddr } = syscallArgs
    let tvPtr = word64ToPtr tvAddr
    let tzPtr = word64ToPtr tzAddr
    pure $ DetailedSyscallEnter_gettimeofday $ SyscallEnterDetails_gettimeofday
      { tv = tvPtr
      , tz = tzPtr
      }
  Syscall_settimeofday -> do
    let SyscallArgs{ arg0 = tvAddr, arg1 = tzAddr } = syscallArgs
    let tvPtr = word64ToPtr tvAddr
    let tzPtr = word64ToPtr tzAddr
    pure $ DetailedSyscallEnter_settimeofday $ SyscallEnterDetails_settimeofday
      { tv = tvPtr
      , tz = tzPtr
      }
  Syscall_adjtimex -> do
    let SyscallArgs{ arg0 = txc_pAddr } = syscallArgs
    let txc_pPtr = word64ToPtr txc_pAddr
    pure $ DetailedSyscallEnter_adjtimex $ SyscallEnterDetails_adjtimex
      { txc_p = txc_pPtr
      }
  Syscall_fadvise64_64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = offset, arg2 = len, arg3 = advice } = syscallArgs
    pure $ DetailedSyscallEnter_fadvise64_64 $ SyscallEnterDetails_fadvise64_64
      { fd = fromIntegral fd
      , offset = fromIntegral offset
      , len = fromIntegral len
      , advice = fromIntegral advice
      }
  Syscall_fadvise64 -> do
    let SyscallArgs{ arg0 = fd, arg1 = offset, arg2 = len, arg3 = advice } = syscallArgs
    pure $ DetailedSyscallEnter_fadvise64 $ SyscallEnterDetails_fadvise64
      { fd = fromIntegral fd
      , offset = fromIntegral offset
      , len = fromIntegral len
      , advice = fromIntegral advice
      }
  Syscall_madvise -> do
    let SyscallArgs{ arg0 = start, arg1 = len_in, arg2 = behavior } = syscallArgs
    pure $ DetailedSyscallEnter_madvise $ SyscallEnterDetails_madvise
      { start = fromIntegral start
      , len_in = fromIntegral len_in
      , behavior = fromIntegral behavior
      }
  Syscall_memfd_create -> do
    let SyscallArgs{ arg0 = unameAddr, arg1 = flags } = syscallArgs
    let unamePtr = word64ToPtr unameAddr
    unameBS <- peekNullTerminatedBytes proc unamePtr
    pure $ DetailedSyscallEnter_memfd_create $ SyscallEnterDetails_memfd_create
      { uname = unamePtr
      , unameBS
      , flags = fromIntegral flags
      }
  Syscall_mbind -> do
    let SyscallArgs{ arg0 = start, arg1 = len, arg2 = mode, arg3 = nmaskAddr, arg4 = maxnode, arg5 = flags } = syscallArgs
    let nmaskPtr = word64ToPtr nmaskAddr
    pure $ DetailedSyscallEnter_mbind $ SyscallEnterDetails_mbind
      { start = fromIntegral start
      , len = fromIntegral len
      , mode = fromIntegral mode
      , nmask = nmaskPtr
      , maxnode = fromIntegral maxnode
      , flags = fromIntegral flags
      }
  Syscall_set_mempolicy -> do
    let SyscallArgs{ arg0 = mode, arg1 = nmaskAddr, arg2 = maxnode } = syscallArgs
    let nmaskPtr = word64ToPtr nmaskAddr
    pure $ DetailedSyscallEnter_set_mempolicy $ SyscallEnterDetails_set_mempolicy
      { mode = fromIntegral mode
      , nmask = nmaskPtr
      , maxnode = fromIntegral maxnode
      }
  Syscall_migrate_pages -> do
    let SyscallArgs{ arg0 = pid_, arg1 = maxnode, arg2 = old_nodesAddr, arg3 = new_nodesAddr } = syscallArgs
    let old_nodesPtr = word64ToPtr old_nodesAddr
    let new_nodesPtr = word64ToPtr new_nodesAddr
    pure $ DetailedSyscallEnter_migrate_pages $ SyscallEnterDetails_migrate_pages
      { pid_ = fromIntegral pid_
      , maxnode = fromIntegral maxnode
      , old_nodes = old_nodesPtr
      , new_nodes = new_nodesPtr
      }
  Syscall_get_mempolicy -> do
    let SyscallArgs{ arg0 = policyAddr, arg1 = nmaskAddr, arg2 = maxnode, arg3 = addr, arg4 = flags } = syscallArgs
    let policyPtr = word64ToPtr policyAddr
    let nmaskPtr = word64ToPtr nmaskAddr
    pure $ DetailedSyscallEnter_get_mempolicy $ SyscallEnterDetails_get_mempolicy
      { policy = policyPtr
      , nmask = nmaskPtr
      , maxnode = fromIntegral maxnode
      , addr = fromIntegral addr
      , flags = fromIntegral flags
      }
  Syscall_move_pages -> do
    let SyscallArgs{ arg0 = pid_, arg1 = nr_pages, arg2 = pagesAddr, arg3 = nodesAddr, arg4 = statusAddr, arg5 = flags } = syscallArgs
    let pagesPtr = word64ToPtr pagesAddr
    let nodesPtr = word64ToPtr nodesAddr
    let statusPtr = word64ToPtr statusAddr
    pure $ DetailedSyscallEnter_move_pages $ SyscallEnterDetails_move_pages
      { pid_ = fromIntegral pid_
      , nr_pages = fromIntegral nr_pages
      , pages = pagesPtr
      , nodes = nodesPtr
      , status = statusPtr
      , flags = fromIntegral flags
      }
  Syscall_mincore -> do
    let SyscallArgs{ arg0 = start, arg1 = len, arg2 = vecAddr } = syscallArgs
    let vecPtr = word64ToPtr vecAddr
    pure $ DetailedSyscallEnter_mincore $ SyscallEnterDetails_mincore
      { start = fromIntegral start
      , len = fromIntegral len
      , vec = vecPtr
      }
  Syscall_mlock -> do
    let SyscallArgs{ arg0 = start, arg1 = len } = syscallArgs
    pure $ DetailedSyscallEnter_mlock $ SyscallEnterDetails_mlock
      { start = fromIntegral start
      , len = fromIntegral len
      }
  Syscall_mlock2 -> do
    let SyscallArgs{ arg0 = start, arg1 = len, arg2 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_mlock2 $ SyscallEnterDetails_mlock2
      { start = fromIntegral start
      , len = fromIntegral len
      , flags = fromIntegral flags
      }
  Syscall_munlock -> do
    let SyscallArgs{ arg0 = start, arg1 = len } = syscallArgs
    pure $ DetailedSyscallEnter_munlock $ SyscallEnterDetails_munlock
      { start = fromIntegral start
      , len = fromIntegral len
      }
  Syscall_mlockall -> do
    let SyscallArgs{ arg0 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_mlockall $ SyscallEnterDetails_mlockall
      { flags = fromIntegral flags
      }
  Syscall_munlockall -> do
    pure $ DetailedSyscallEnter_munlockall $ SyscallEnterDetails_munlockall
      { 
      }
  Syscall_brk -> do
    let SyscallArgs{ arg0 = brk } = syscallArgs
    pure $ DetailedSyscallEnter_brk $ SyscallEnterDetails_brk
      { brk = fromIntegral brk
      }
  Syscall_munmap -> do
    let SyscallArgs{ arg0 = addr, arg1 = len } = syscallArgs
    pure $ DetailedSyscallEnter_munmap $ SyscallEnterDetails_munmap
      { addr = fromIntegral addr
      , len = fromIntegral len
      }
  Syscall_remap_file_pages -> do
    let SyscallArgs{ arg0 = start, arg1 = size, arg2 = prot, arg3 = pgoff, arg4 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_remap_file_pages $ SyscallEnterDetails_remap_file_pages
      { start = fromIntegral start
      , size = fromIntegral size
      , prot = fromIntegral prot
      , pgoff = fromIntegral pgoff
      , flags = fromIntegral flags
      }
  Syscall_mprotect -> do
    let SyscallArgs{ arg0 = start, arg1 = len, arg2 = prot } = syscallArgs
    pure $ DetailedSyscallEnter_mprotect $ SyscallEnterDetails_mprotect
      { start = fromIntegral start
      , len = fromIntegral len
      , prot = fromIntegral prot
      }
  Syscall_pkey_mprotect -> do
    let SyscallArgs{ arg0 = start, arg1 = len, arg2 = prot, arg3 = pkey } = syscallArgs
    pure $ DetailedSyscallEnter_pkey_mprotect $ SyscallEnterDetails_pkey_mprotect
      { start = fromIntegral start
      , len = fromIntegral len
      , prot = fromIntegral prot
      , pkey = fromIntegral pkey
      }
  Syscall_pkey_alloc -> do
    let SyscallArgs{ arg0 = flags, arg1 = init_val } = syscallArgs
    pure $ DetailedSyscallEnter_pkey_alloc $ SyscallEnterDetails_pkey_alloc
      { flags = fromIntegral flags
      , init_val = fromIntegral init_val
      }
  Syscall_pkey_free -> do
    let SyscallArgs{ arg0 = pkey } = syscallArgs
    pure $ DetailedSyscallEnter_pkey_free $ SyscallEnterDetails_pkey_free
      { pkey = fromIntegral pkey
      }
  Syscall_mremap -> do
    let SyscallArgs{ arg0 = addr, arg1 = old_len, arg2 = new_len, arg3 = flags, arg4 = new_addr } = syscallArgs
    pure $ DetailedSyscallEnter_mremap $ SyscallEnterDetails_mremap
      { addr = fromIntegral addr
      , old_len = fromIntegral old_len
      , new_len = fromIntegral new_len
      , flags = fromIntegral flags
      , new_addr = fromIntegral new_addr
      }
  Syscall_msync -> do
    let SyscallArgs{ arg0 = start, arg1 = len, arg2 = flags } = syscallArgs
    pure $ DetailedSyscallEnter_msync $ SyscallEnterDetails_msync
      { start = fromIntegral start
      , len = fromIntegral len
      , flags = fromIntegral flags
      }
  Syscall_process_vm_readv -> do
    let SyscallArgs{ arg0 = pid_, arg1 = lvecAddr, arg2 = liovcnt, arg3 = rvecAddr, arg4 = riovcnt, arg5 = flags } = syscallArgs
    let lvecPtr = word64ToPtr lvecAddr
    let rvecPtr = word64ToPtr rvecAddr
    pure $ DetailedSyscallEnter_process_vm_readv $ SyscallEnterDetails_process_vm_readv
      { pid_ = fromIntegral pid_
      , lvec = lvecPtr
      , liovcnt = fromIntegral liovcnt
      , rvec = rvecPtr
      , riovcnt = fromIntegral riovcnt
      , flags = fromIntegral flags
      }
  Syscall_process_vm_writev -> do
    let SyscallArgs{ arg0 = pid_, arg1 = lvecAddr, arg2 = liovcnt, arg3 = rvecAddr, arg4 = riovcnt, arg5 = flags } = syscallArgs
    let lvecPtr = word64ToPtr lvecAddr
    let rvecPtr = word64ToPtr rvecAddr
    pure $ DetailedSyscallEnter_process_vm_writev $ SyscallEnterDetails_process_vm_writev
      { pid_ = fromIntegral pid_
      , lvec = lvecPtr
      , liovcnt = fromIntegral liovcnt
      , rvec = rvecPtr
      , riovcnt = fromIntegral riovcnt
      , flags = fromIntegral flags
      }
  Syscall_readahead -> do
    let SyscallArgs{ arg0 = fd, arg1 = offset, arg2 = count } = syscallArgs
    pure $ DetailedSyscallEnter_readahead $ SyscallEnterDetails_readahead
      { fd = fromIntegral fd
      , offset = fromIntegral offset
      , count = fromIntegral count
      }
  Syscall_swapoff -> do
    let SyscallArgs{ arg0 = specialfileAddr } = syscallArgs
    let specialfilePtr = word64ToPtr specialfileAddr
    specialfileBS <- peekNullTerminatedBytes proc specialfilePtr
    pure $ DetailedSyscallEnter_swapoff $ SyscallEnterDetails_swapoff
      { specialfile = specialfilePtr
      , specialfileBS
      }
  Syscall_swapon -> do
    let SyscallArgs{ arg0 = specialfileAddr, arg1 = swap_flags } = syscallArgs
    let specialfilePtr = word64ToPtr specialfileAddr
    specialfileBS <- peekNullTerminatedBytes proc specialfilePtr
    pure $ DetailedSyscallEnter_swapon $ SyscallEnterDetails_swapon
      { specialfile = specialfilePtr
      , specialfileBS
      , swap_flags = fromIntegral swap_flags
      }
  Syscall_socket -> do
    let SyscallArgs{ arg0 = family, arg1 = type_, arg2 = protocol } = syscallArgs
    pure $ DetailedSyscallEnter_socket $ SyscallEnterDetails_socket
      { family = fromIntegral family
      , type_ = fromIntegral type_
      , protocol = fromIntegral protocol
      }
  Syscall_socketpair -> do
    let SyscallArgs{ arg0 = family, arg1 = type_, arg2 = protocol, arg3 = usockvecAddr } = syscallArgs
    let usockvecPtr = word64ToPtr usockvecAddr
    pure $ DetailedSyscallEnter_socketpair $ SyscallEnterDetails_socketpair
      { family = fromIntegral family
      , type_ = fromIntegral type_
      , protocol = fromIntegral protocol
      , usockvec = usockvecPtr
      }
  Syscall_bind -> do
    let SyscallArgs{ arg0 = fd, arg1 = umyaddrAddr, arg2 = addrlen } = syscallArgs
    let umyaddrPtr = word64ToPtr umyaddrAddr
    pure $ DetailedSyscallEnter_bind $ SyscallEnterDetails_bind
      { fd = fromIntegral fd
      , umyaddr = umyaddrPtr
      , addrlen = fromIntegral addrlen
      }
  Syscall_listen -> do
    let SyscallArgs{ arg0 = fd, arg1 = backlog } = syscallArgs
    pure $ DetailedSyscallEnter_listen $ SyscallEnterDetails_listen
      { fd = fromIntegral fd
      , backlog = fromIntegral backlog
      }
  Syscall_accept4 -> do
    let SyscallArgs{ arg0 = fd, arg1 = upeer_sockaddrAddr, arg2 = upeer_addrlenAddr, arg3 = flags } = syscallArgs
    let upeer_sockaddrPtr = word64ToPtr upeer_sockaddrAddr
    let upeer_addrlenPtr = word64ToPtr upeer_addrlenAddr
    pure $ DetailedSyscallEnter_accept4 $ SyscallEnterDetails_accept4
      { fd = fromIntegral fd
      , upeer_sockaddr = upeer_sockaddrPtr
      , upeer_addrlen = upeer_addrlenPtr
      , flags = fromIntegral flags
      }
  Syscall_accept -> do
    let SyscallArgs{ arg0 = fd, arg1 = upeer_sockaddrAddr, arg2 = upeer_addrlenAddr } = syscallArgs
    let upeer_sockaddrPtr = word64ToPtr upeer_sockaddrAddr
    let upeer_addrlenPtr = word64ToPtr upeer_addrlenAddr
    pure $ DetailedSyscallEnter_accept $ SyscallEnterDetails_accept
      { fd = fromIntegral fd
      , upeer_sockaddr = upeer_sockaddrPtr
      , upeer_addrlen = upeer_addrlenPtr
      }
  Syscall_connect -> do
    let SyscallArgs{ arg0 = fd, arg1 = uservaddrAddr, arg2 = addrlen } = syscallArgs
    let uservaddrPtr = word64ToPtr uservaddrAddr
    pure $ DetailedSyscallEnter_connect $ SyscallEnterDetails_connect
      { fd = fromIntegral fd
      , uservaddr = uservaddrPtr
      , addrlen = fromIntegral addrlen
      }
  Syscall_getsockname -> do
    let SyscallArgs{ arg0 = fd, arg1 = usockaddrAddr, arg2 = usockaddr_lenAddr } = syscallArgs
    let usockaddrPtr = word64ToPtr usockaddrAddr
    let usockaddr_lenPtr = word64ToPtr usockaddr_lenAddr
    pure $ DetailedSyscallEnter_getsockname $ SyscallEnterDetails_getsockname
      { fd = fromIntegral fd
      , usockaddr = usockaddrPtr
      , usockaddr_len = usockaddr_lenPtr
      }
  Syscall_getpeername -> do
    let SyscallArgs{ arg0 = fd, arg1 = usockaddrAddr, arg2 = usockaddr_lenAddr } = syscallArgs
    let usockaddrPtr = word64ToPtr usockaddrAddr
    let usockaddr_lenPtr = word64ToPtr usockaddr_lenAddr
    pure $ DetailedSyscallEnter_getpeername $ SyscallEnterDetails_getpeername
      { fd = fromIntegral fd
      , usockaddr = usockaddrPtr
      , usockaddr_len = usockaddr_lenPtr
      }
  Syscall_sendto -> do
    let SyscallArgs{ arg0 = fd, arg1 = buffAddr, arg2 = len, arg3 = flags, arg4 = addrAddr, arg5 = addr_len } = syscallArgs
    let buffPtr = word64ToPtr buffAddr
    let addrPtr = word64ToPtr addrAddr
    pure $ DetailedSyscallEnter_sendto $ SyscallEnterDetails_sendto
      { fd = fromIntegral fd
      , buff = buffPtr
      , len = fromIntegral len
      , flags = fromIntegral flags
      , addr = addrPtr
      , addr_len = fromIntegral addr_len
      }
  Syscall_send -> do
    let SyscallArgs{ arg0 = fd, arg1 = buffAddr, arg2 = len, arg3 = flags } = syscallArgs
    let buffPtr = word64ToPtr buffAddr
    pure $ DetailedSyscallEnter_send $ SyscallEnterDetails_send
      { fd = fromIntegral fd
      , buff = buffPtr
      , len = fromIntegral len
      , flags = fromIntegral flags
      }
  Syscall_recvfrom -> do
    let SyscallArgs{ arg0 = fd, arg1 = ubufAddr, arg2 = size, arg3 = flags, arg4 = addrAddr, arg5 = addr_lenAddr } = syscallArgs
    let ubufPtr = word64ToPtr ubufAddr
    let addrPtr = word64ToPtr addrAddr
    let addr_lenPtr = word64ToPtr addr_lenAddr
    pure $ DetailedSyscallEnter_recvfrom $ SyscallEnterDetails_recvfrom
      { fd = fromIntegral fd
      , ubuf = ubufPtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      , addr = addrPtr
      , addr_len = addr_lenPtr
      }
  Syscall_recv -> do
    let SyscallArgs{ arg0 = fd, arg1 = ubufAddr, arg2 = size, arg3 = flags } = syscallArgs
    let ubufPtr = word64ToPtr ubufAddr
    pure $ DetailedSyscallEnter_recv $ SyscallEnterDetails_recv
      { fd = fromIntegral fd
      , ubuf = ubufPtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      }
  Syscall_setsockopt -> do
    let SyscallArgs{ arg0 = fd, arg1 = level, arg2 = optname, arg3 = optvalAddr, arg4 = optlen } = syscallArgs
    let optvalPtr = word64ToPtr optvalAddr
    optvalBS <- peekNullTerminatedBytes proc optvalPtr
    pure $ DetailedSyscallEnter_setsockopt $ SyscallEnterDetails_setsockopt
      { fd = fromIntegral fd
      , level = fromIntegral level
      , optname = fromIntegral optname
      , optval = optvalPtr
      , optvalBS
      , optlen = fromIntegral optlen
      }
  Syscall_getsockopt -> do
    let SyscallArgs{ arg0 = fd, arg1 = level, arg2 = optname, arg3 = optvalAddr, arg4 = optlenAddr } = syscallArgs
    let optvalPtr = word64ToPtr optvalAddr
    let optlenPtr = word64ToPtr optlenAddr
    optvalBS <- peekNullTerminatedBytes proc optvalPtr
    pure $ DetailedSyscallEnter_getsockopt $ SyscallEnterDetails_getsockopt
      { fd = fromIntegral fd
      , level = fromIntegral level
      , optname = fromIntegral optname
      , optval = optvalPtr
      , optvalBS
      , optlen = optlenPtr
      }
  Syscall_shutdown -> do
    let SyscallArgs{ arg0 = fd, arg1 = how } = syscallArgs
    pure $ DetailedSyscallEnter_shutdown $ SyscallEnterDetails_shutdown
      { fd = fromIntegral fd
      , how = fromIntegral how
      }
  Syscall_sendmsg -> do
    let SyscallArgs{ arg0 = fd, arg1 = msgAddr, arg2 = flags } = syscallArgs
    let msgPtr = word64ToPtr msgAddr
    pure $ DetailedSyscallEnter_sendmsg $ SyscallEnterDetails_sendmsg
      { fd = fromIntegral fd
      , msg = msgPtr
      , flags = fromIntegral flags
      }
  Syscall_sendmmsg -> do
    let SyscallArgs{ arg0 = fd, arg1 = mmsgAddr, arg2 = vlen, arg3 = flags } = syscallArgs
    let mmsgPtr = word64ToPtr mmsgAddr
    pure $ DetailedSyscallEnter_sendmmsg $ SyscallEnterDetails_sendmmsg
      { fd = fromIntegral fd
      , mmsg = mmsgPtr
      , vlen = fromIntegral vlen
      , flags = fromIntegral flags
      }
  Syscall_recvmsg -> do
    let SyscallArgs{ arg0 = fd, arg1 = msgAddr, arg2 = flags } = syscallArgs
    let msgPtr = word64ToPtr msgAddr
    pure $ DetailedSyscallEnter_recvmsg $ SyscallEnterDetails_recvmsg
      { fd = fromIntegral fd
      , msg = msgPtr
      , flags = fromIntegral flags
      }
  Syscall_recvmmsg -> do
    let SyscallArgs{ arg0 = fd, arg1 = mmsgAddr, arg2 = vlen, arg3 = flags, arg4 = timeoutAddr } = syscallArgs
    let mmsgPtr = word64ToPtr mmsgAddr
    let timeoutPtr = word64ToPtr timeoutAddr
    pure $ DetailedSyscallEnter_recvmmsg $ SyscallEnterDetails_recvmmsg
      { fd = fromIntegral fd
      , mmsg = mmsgPtr
      , vlen = fromIntegral vlen
      , flags = fromIntegral flags
      , timeout = timeoutPtr
      }
  Syscall_socketcall -> do
    let SyscallArgs{ arg0 = call, arg1 = argsAddr } = syscallArgs
    let argsPtr = word64ToPtr argsAddr
    pure $ DetailedSyscallEnter_socketcall $ SyscallEnterDetails_socketcall
      { call = fromIntegral call
      , args = argsPtr
      }
  Syscall_add_key -> do
    let SyscallArgs{ arg0 = _typeAddr, arg1 = _descriptionAddr, arg2 = _payloadAddr, arg3 = plen, arg4 = ringid } = syscallArgs
    let _typePtr = word64ToPtr _typeAddr
    let _descriptionPtr = word64ToPtr _descriptionAddr
    let _payloadPtr = word64ToPtr _payloadAddr
    _typeBS <- peekNullTerminatedBytes proc _typePtr
    _descriptionBS <- peekNullTerminatedBytes proc _descriptionPtr
    pure $ DetailedSyscallEnter_add_key $ SyscallEnterDetails_add_key
      { _type = _typePtr
      , _typeBS
      , _description = _descriptionPtr
      , _descriptionBS
      , _payload = _payloadPtr
      , plen = fromIntegral plen
      , ringid = fromIntegral ringid
      }
  Syscall_request_key -> do
    let SyscallArgs{ arg0 = _typeAddr, arg1 = _descriptionAddr, arg2 = _callout_infoAddr, arg3 = destringid } = syscallArgs
    let _typePtr = word64ToPtr _typeAddr
    let _descriptionPtr = word64ToPtr _descriptionAddr
    let _callout_infoPtr = word64ToPtr _callout_infoAddr
    _typeBS <- peekNullTerminatedBytes proc _typePtr
    _descriptionBS <- peekNullTerminatedBytes proc _descriptionPtr
    _callout_infoBS <- peekNullTerminatedBytes proc _callout_infoPtr
    pure $ DetailedSyscallEnter_request_key $ SyscallEnterDetails_request_key
      { _type = _typePtr
      , _typeBS
      , _description = _descriptionPtr
      , _descriptionBS
      , _callout_info = _callout_infoPtr
      , _callout_infoBS
      , destringid = fromIntegral destringid
      }
  Syscall_keyctl -> do
    let SyscallArgs{ arg0 = option, arg1 = arg2, arg2 = arg3, arg3 = arg4, arg4 = arg5 } = syscallArgs
    pure $ DetailedSyscallEnter_keyctl $ SyscallEnterDetails_keyctl
      { option = fromIntegral option
      , arg2 = fromIntegral arg2
      , arg3 = fromIntegral arg3
      , arg4 = fromIntegral arg4
      , arg5 = fromIntegral arg5
      }
  Syscall_select -> do
    let SyscallArgs{ arg0 = n, arg1 = inpAddr, arg2 = outpAddr, arg3 = exp_Addr, arg4 = tvpAddr } = syscallArgs
    let inpPtr = word64ToPtr inpAddr
    let outpPtr = word64ToPtr outpAddr
    let expPtr = word64ToPtr exp_Addr
    let tvpPtr = word64ToPtr tvpAddr
    pure $ DetailedSyscallEnter_select $ SyscallEnterDetails_select
      { n = fromIntegral n
      , inp = inpPtr
      , outp = outpPtr
      , exp_ = expPtr
      , tvp = tvpPtr
      }
  Syscall_pselect6 -> do
    let SyscallArgs{ arg0 = n, arg1 = inpAddr, arg2 = outpAddr, arg3 = exp_Addr, arg4 = tspAddr, arg5 = sigAddr } = syscallArgs
    let inpPtr = word64ToPtr inpAddr
    let outpPtr = word64ToPtr outpAddr
    let expPtr = word64ToPtr exp_Addr
    let tspPtr = word64ToPtr tspAddr
    let sigPtr = word64ToPtr sigAddr
    pure $ DetailedSyscallEnter_pselect6 $ SyscallEnterDetails_pselect6
      { n = fromIntegral n
      , inp = inpPtr
      , outp = outpPtr
      , exp_ = expPtr
      , tsp = tspPtr
      , sig = sigPtr
      }
  Syscall_mq_open -> do
    let SyscallArgs{ arg0 = u_nameAddr, arg1 = oflag, arg2 = mode, arg3 = u_attrAddr } = syscallArgs
    let u_namePtr = word64ToPtr u_nameAddr
    let u_attrPtr = word64ToPtr u_attrAddr
    u_nameBS <- peekNullTerminatedBytes proc u_namePtr
    pure $ DetailedSyscallEnter_mq_open $ SyscallEnterDetails_mq_open
      { u_name = u_namePtr
      , u_nameBS
      , oflag = fromIntegral oflag
      , mode = fromIntegral mode
      , u_attr = u_attrPtr
      }
  Syscall_mq_unlink -> do
    let SyscallArgs{ arg0 = u_nameAddr } = syscallArgs
    let u_namePtr = word64ToPtr u_nameAddr
    u_nameBS <- peekNullTerminatedBytes proc u_namePtr
    pure $ DetailedSyscallEnter_mq_unlink $ SyscallEnterDetails_mq_unlink
      { u_name = u_namePtr
      , u_nameBS
      }
  Syscall_bpf -> do
    let SyscallArgs{ arg0 = cmd, arg1 = uattrAddr, arg2 = size } = syscallArgs
    let uattrPtr = word64ToPtr uattrAddr
    pure $ DetailedSyscallEnter_bpf $ SyscallEnterDetails_bpf
      { cmd = fromIntegral cmd
      , uattr = uattrPtr
      , size = fromIntegral size
      }
  Syscall_capget -> do
    let SyscallArgs{ arg0 = headerAddr, arg1 = dataptrAddr } = syscallArgs
    let headerPtr = word64ToPtr headerAddr
    let dataptrPtr = word64ToPtr dataptrAddr
    pure $ DetailedSyscallEnter_capget $ SyscallEnterDetails_capget
      { header = headerPtr
      , dataptr = dataptrPtr
      }
  Syscall_capset -> do
    let SyscallArgs{ arg0 = headerAddr, arg1 = data_Addr } = syscallArgs
    let headerPtr = word64ToPtr headerAddr
    let data_Ptr = word64ToPtr data_Addr
    pure $ DetailedSyscallEnter_capset $ SyscallEnterDetails_capset
      { header = headerPtr
      , data_ = data_Ptr
      }
  Syscall_rt_sigtimedwait -> do
    let SyscallArgs{ arg0 = utheseAddr, arg1 = uinfoAddr, arg2 = utsAddr, arg3 = sigsetsize } = syscallArgs
    let uthesePtr = word64ToPtr utheseAddr
    let uinfoPtr = word64ToPtr uinfoAddr
    let utsPtr = word64ToPtr utsAddr
    pure $ DetailedSyscallEnter_rt_sigtimedwait $ SyscallEnterDetails_rt_sigtimedwait
      { uthese = uthesePtr
      , uinfo = uinfoPtr
      , uts = utsPtr
      , sigsetsize = fromIntegral sigsetsize
      }
  Syscall_rt_sigqueueinfo -> do
    let SyscallArgs{ arg0 = pid_, arg1 = sig, arg2 = uinfoAddr } = syscallArgs
    let uinfoPtr = word64ToPtr uinfoAddr
    pure $ DetailedSyscallEnter_rt_sigqueueinfo $ SyscallEnterDetails_rt_sigqueueinfo
      { pid_ = fromIntegral pid_
      , sig = fromIntegral sig
      , uinfo = uinfoPtr
      }
  Syscall_rt_tgsigqueueinfo -> do
    let SyscallArgs{ arg0 = tgid, arg1 = pid_, arg2 = sig, arg3 = uinfoAddr } = syscallArgs
    let uinfoPtr = word64ToPtr uinfoAddr
    pure $ DetailedSyscallEnter_rt_tgsigqueueinfo $ SyscallEnterDetails_rt_tgsigqueueinfo
      { tgid = fromIntegral tgid
      , pid_ = fromIntegral pid_
      , sig = fromIntegral sig
      , uinfo = uinfoPtr
      }
  Syscall_sigaltstack -> do
    let SyscallArgs{ arg0 = ussAddr, arg1 = uossAddr } = syscallArgs
    let ussPtr = word64ToPtr ussAddr
    let uossPtr = word64ToPtr uossAddr
    pure $ DetailedSyscallEnter_sigaltstack $ SyscallEnterDetails_sigaltstack
      { uss = ussPtr
      , uoss = uossPtr
      }
  Syscall_mq_timedsend -> do
    let SyscallArgs{ arg0 = mqdes, arg1 = u_msg_ptrAddr, arg2 = msg_len, arg3 = msg_prio, arg4 = u_abs_timeoutAddr } = syscallArgs
    let u_msg_ptrPtr = word64ToPtr u_msg_ptrAddr
    let u_abs_timeoutPtr = word64ToPtr u_abs_timeoutAddr
    u_msg_ptrBS <- peekNullTerminatedBytes proc u_msg_ptrPtr
    pure $ DetailedSyscallEnter_mq_timedsend $ SyscallEnterDetails_mq_timedsend
      { mqdes = fromIntegral mqdes
      , u_msg_ptr = u_msg_ptrPtr
      , u_msg_ptrBS
      , msg_len = fromIntegral msg_len
      , msg_prio = fromIntegral msg_prio
      , u_abs_timeout = u_abs_timeoutPtr
      }
  Syscall_mq_timedreceive -> do
    let SyscallArgs{ arg0 = mqdes, arg1 = u_msg_ptrAddr, arg2 = msg_len, arg3 = u_msg_prioAddr, arg4 = u_abs_timeoutAddr } = syscallArgs
    let u_msg_ptrPtr = word64ToPtr u_msg_ptrAddr
    let u_msg_prioPtr = word64ToPtr u_msg_prioAddr
    let u_abs_timeoutPtr = word64ToPtr u_abs_timeoutAddr
    u_msg_ptrBS <- peekNullTerminatedBytes proc u_msg_ptrPtr
    pure $ DetailedSyscallEnter_mq_timedreceive $ SyscallEnterDetails_mq_timedreceive
      { mqdes = fromIntegral mqdes
      , u_msg_ptr = u_msg_ptrPtr
      , u_msg_ptrBS
      , msg_len = fromIntegral msg_len
      , u_msg_prio = u_msg_prioPtr
      , u_abs_timeout = u_abs_timeoutPtr
      }
  Syscall_mq_notify -> do
    let SyscallArgs{ arg0 = mqdes, arg1 = u_notificationAddr } = syscallArgs
    let u_notificationPtr = word64ToPtr u_notificationAddr
    pure $ DetailedSyscallEnter_mq_notify $ SyscallEnterDetails_mq_notify
      { mqdes = fromIntegral mqdes
      , u_notification = u_notificationPtr
      }
  Syscall_mq_getsetattr -> do
    let SyscallArgs{ arg0 = mqdes, arg1 = u_mqstatAddr, arg2 = u_omqstatAddr } = syscallArgs
    let u_mqstatPtr = word64ToPtr u_mqstatAddr
    let u_omqstatPtr = word64ToPtr u_omqstatAddr
    pure $ DetailedSyscallEnter_mq_getsetattr $ SyscallEnterDetails_mq_getsetattr
      { mqdes = fromIntegral mqdes
      , u_mqstat = u_mqstatPtr
      , u_omqstat = u_omqstatPtr
      }
  _ -> pure $ DetailedSyscallEnter_unimplemented (KnownSyscall syscall) syscallArgs


getSyscallExitDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO (Either ERRNO DetailedSyscallExit)
getSyscallExitDetails knownSyscall syscallArgs pid = do

  (result, mbErrno) <- getExitedSyscallResult pid

  case mbErrno of
    Just errno -> return $ Left errno
    Nothing -> Right <$> do

      -- For some syscalls we must not try to get the enter details at their exit,
      -- because the registers involved are invalidated.
      -- TODO: Address this by not re-fetching the enter details at all, but by
      --       remembering them in a PID map.
      case knownSyscall of
        Syscall_execve | result == 0 -> do
          -- The execve() worked, we cannot get its enter details, as the
          -- registers involved are invalidated because the process image
          -- has been replaced.
          pure $ DetailedSyscallExit_execve
            SyscallExitDetails_execve{ optionalEnterDetail = Nothing, execveResult = fromIntegral result }
        _ -> do
          -- For all other syscalls, we can get the enter details.

          detailedSyscallEnter <- getSyscallEnterDetails knownSyscall syscallArgs pid

          case detailedSyscallEnter of

            DetailedSyscallEnter_open
              enterDetail@SyscallEnterDetails_open{} -> do
                pure $ DetailedSyscallExit_open $
                  SyscallExitDetails_open{ enterDetail, fd = fromIntegral result }

            DetailedSyscallEnter_openat
              enterDetail@SyscallEnterDetails_openat{} -> do
                pure $ DetailedSyscallExit_openat $
                  SyscallExitDetails_openat{ enterDetail, fd = fromIntegral result }

            DetailedSyscallEnter_creat
              enterDetail@SyscallEnterDetails_creat{} -> do
                pure $ DetailedSyscallExit_creat $
                  SyscallExitDetails_creat{ enterDetail, fd = fromIntegral result }

            DetailedSyscallEnter_pipe
              enterDetail@SyscallEnterDetails_pipe{ pipefd } -> do
                (readfd, writefd) <- readPipeFds pid pipefd
                pure $ DetailedSyscallExit_pipe $
                  SyscallExitDetails_pipe{ enterDetail, readfd, writefd }

            DetailedSyscallEnter_pipe2
              enterDetail@SyscallEnterDetails_pipe2{ pipefd } -> do
                (readfd, writefd) <- readPipeFds pid pipefd
                pure $ DetailedSyscallExit_pipe2 $
                  SyscallExitDetails_pipe2{ enterDetail, readfd, writefd }

            DetailedSyscallEnter_write
              enterDetail@SyscallEnterDetails_write{} -> do
                pure $ DetailedSyscallExit_write $
                  SyscallExitDetails_write{ enterDetail, writtenCount = fromIntegral result }

            DetailedSyscallEnter_access
              enterDetail@SyscallEnterDetails_access{} -> do
                pure $ DetailedSyscallExit_access $
                  SyscallExitDetails_access{ enterDetail }

            DetailedSyscallEnter_faccessat
              enterDetail@SyscallEnterDetails_faccessat{} -> do
                pure $ DetailedSyscallExit_faccessat $
                  SyscallExitDetails_faccessat{ enterDetail }

            DetailedSyscallEnter_read
              enterDetail@SyscallEnterDetails_read{ buf } -> do
                bufContents <- peekBytes (TracedProcess pid) buf (fromIntegral result)
                pure $ DetailedSyscallExit_read $
                  SyscallExitDetails_read{ enterDetail, readCount = fromIntegral result, bufContents }

            DetailedSyscallEnter_execve
              enterDetail@SyscallEnterDetails_execve{} -> do
                pure $ DetailedSyscallExit_execve $
                  SyscallExitDetails_execve{ optionalEnterDetail = Just enterDetail, execveResult = fromIntegral result }

            DetailedSyscallEnter_close
              enterDetail@SyscallEnterDetails_close{} -> do
                pure $ DetailedSyscallExit_close $
                  SyscallExitDetails_close{ enterDetail }

            DetailedSyscallEnter_rename
              enterDetail@SyscallEnterDetails_rename{} -> do
                pure $ DetailedSyscallExit_rename $
                  SyscallExitDetails_rename{ enterDetail }

            DetailedSyscallEnter_renameat
              enterDetail@SyscallEnterDetails_renameat{} -> do
                pure $ DetailedSyscallExit_renameat $
                  SyscallExitDetails_renameat{ enterDetail }

            DetailedSyscallEnter_renameat2
              enterDetail@SyscallEnterDetails_renameat2{} -> do
                pure $ DetailedSyscallExit_renameat2 $
                  SyscallExitDetails_renameat2{ enterDetail }

            DetailedSyscallEnter_stat
              enterDetail@SyscallEnterDetails_stat{statbuf} -> do
                stat <- Ptrace.peek (TracedProcess pid) statbuf
                pure $ DetailedSyscallExit_stat $
                  SyscallExitDetails_stat{ enterDetail, stat }

            DetailedSyscallEnter_fstat
              enterDetail@SyscallEnterDetails_fstat{statbuf} -> do
                stat <- Ptrace.peek (TracedProcess pid) statbuf
                pure $ DetailedSyscallExit_fstat $
                  SyscallExitDetails_fstat{ enterDetail, stat }

            DetailedSyscallEnter_lstat
              enterDetail@SyscallEnterDetails_lstat{statbuf} -> do
                stat <- Ptrace.peek (TracedProcess pid) statbuf
                pure $ DetailedSyscallExit_lstat $
                  SyscallExitDetails_lstat{ enterDetail, stat }

            DetailedSyscallEnter_newfstatat
              enterDetail@SyscallEnterDetails_newfstatat{statbuf} -> do
                stat <- Ptrace.peek (TracedProcess pid) statbuf
                pure $ DetailedSyscallExit_newfstatat $
                  SyscallExitDetails_newfstatat{ enterDetail, stat }

            DetailedSyscallEnter_exit
              enterDetail@SyscallEnterDetails_exit{} -> do
                pure $ DetailedSyscallExit_exit $ SyscallExitDetails_exit { enterDetail }

            DetailedSyscallEnter_exit_group
              enterDetail@SyscallEnterDetails_exit_group{} -> do
                pure $ DetailedSyscallExit_exit_group $ SyscallExitDetails_exit_group { enterDetail }


            DetailedSyscallEnter_ioperm
              enterDetail@SyscallEnterDetails_ioperm{} -> do
                pure $ DetailedSyscallExit_ioperm $
                  SyscallExitDetails_ioperm{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_iopl
              enterDetail@SyscallEnterDetails_iopl{} -> do
                pure $ DetailedSyscallExit_iopl $
                  SyscallExitDetails_iopl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_modify_ldt
              enterDetail@SyscallEnterDetails_modify_ldt{} -> do
                pure $ DetailedSyscallExit_modify_ldt $
                  SyscallExitDetails_modify_ldt{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_arch_prctl
              enterDetail@SyscallEnterDetails_arch_prctl{} -> do
                pure $ DetailedSyscallExit_arch_prctl $
                  SyscallExitDetails_arch_prctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sigreturn
              enterDetail@SyscallEnterDetails_sigreturn{} -> do
                pure $ DetailedSyscallExit_sigreturn $
                  SyscallExitDetails_sigreturn{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigreturn
              enterDetail@SyscallEnterDetails_rt_sigreturn{} -> do
                pure $ DetailedSyscallExit_rt_sigreturn $
                  SyscallExitDetails_rt_sigreturn{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mmap
              enterDetail@SyscallEnterDetails_mmap{} -> do
                pure $ DetailedSyscallExit_mmap $
                  SyscallExitDetails_mmap{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_set_thread_area
              enterDetail@SyscallEnterDetails_set_thread_area{} -> do
                pure $ DetailedSyscallExit_set_thread_area $
                  SyscallExitDetails_set_thread_area{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_get_thread_area
              enterDetail@SyscallEnterDetails_get_thread_area{} -> do
                pure $ DetailedSyscallExit_get_thread_area $
                  SyscallExitDetails_get_thread_area{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_vm86old
              enterDetail@SyscallEnterDetails_vm86old{} -> do
                pure $ DetailedSyscallExit_vm86old $
                  SyscallExitDetails_vm86old{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_vm86
              enterDetail@SyscallEnterDetails_vm86{} -> do
                pure $ DetailedSyscallExit_vm86 $
                  SyscallExitDetails_vm86{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ioprio_set
              enterDetail@SyscallEnterDetails_ioprio_set{} -> do
                pure $ DetailedSyscallExit_ioprio_set $
                  SyscallExitDetails_ioprio_set{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ioprio_get
              enterDetail@SyscallEnterDetails_ioprio_get{} -> do
                pure $ DetailedSyscallExit_ioprio_get $
                  SyscallExitDetails_ioprio_get{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getrandom
              enterDetail@SyscallEnterDetails_getrandom{} -> do
                pure $ DetailedSyscallExit_getrandom $
                  SyscallExitDetails_getrandom{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pciconfig_read
              enterDetail@SyscallEnterDetails_pciconfig_read{} -> do
                pure $ DetailedSyscallExit_pciconfig_read $
                  SyscallExitDetails_pciconfig_read{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pciconfig_write
              enterDetail@SyscallEnterDetails_pciconfig_write{} -> do
                pure $ DetailedSyscallExit_pciconfig_write $
                  SyscallExitDetails_pciconfig_write{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_io_setup
              enterDetail@SyscallEnterDetails_io_setup{} -> do
                pure $ DetailedSyscallExit_io_setup $
                  SyscallExitDetails_io_setup{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_io_destroy
              enterDetail@SyscallEnterDetails_io_destroy{} -> do
                pure $ DetailedSyscallExit_io_destroy $
                  SyscallExitDetails_io_destroy{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_io_submit
              enterDetail@SyscallEnterDetails_io_submit{} -> do
                pure $ DetailedSyscallExit_io_submit $
                  SyscallExitDetails_io_submit{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_io_cancel
              enterDetail@SyscallEnterDetails_io_cancel{} -> do
                pure $ DetailedSyscallExit_io_cancel $
                  SyscallExitDetails_io_cancel{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_io_getevents
              enterDetail@SyscallEnterDetails_io_getevents{} -> do
                pure $ DetailedSyscallExit_io_getevents $
                  SyscallExitDetails_io_getevents{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_io_pgetevents
              enterDetail@SyscallEnterDetails_io_pgetevents{} -> do
                pure $ DetailedSyscallExit_io_pgetevents $
                  SyscallExitDetails_io_pgetevents{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_bdflush
              enterDetail@SyscallEnterDetails_bdflush{} -> do
                pure $ DetailedSyscallExit_bdflush $
                  SyscallExitDetails_bdflush{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getcwd
              enterDetail@SyscallEnterDetails_getcwd{} -> do
                pure $ DetailedSyscallExit_getcwd $
                  SyscallExitDetails_getcwd{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lookup_dcookie
              enterDetail@SyscallEnterDetails_lookup_dcookie{} -> do
                pure $ DetailedSyscallExit_lookup_dcookie $
                  SyscallExitDetails_lookup_dcookie{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_eventfd2
              enterDetail@SyscallEnterDetails_eventfd2{} -> do
                pure $ DetailedSyscallExit_eventfd2 $
                  SyscallExitDetails_eventfd2{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_eventfd
              enterDetail@SyscallEnterDetails_eventfd{} -> do
                pure $ DetailedSyscallExit_eventfd $
                  SyscallExitDetails_eventfd{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_epoll_create1
              enterDetail@SyscallEnterDetails_epoll_create1{} -> do
                pure $ DetailedSyscallExit_epoll_create1 $
                  SyscallExitDetails_epoll_create1{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_epoll_create
              enterDetail@SyscallEnterDetails_epoll_create{} -> do
                pure $ DetailedSyscallExit_epoll_create $
                  SyscallExitDetails_epoll_create{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_epoll_ctl
              enterDetail@SyscallEnterDetails_epoll_ctl{} -> do
                pure $ DetailedSyscallExit_epoll_ctl $
                  SyscallExitDetails_epoll_ctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_epoll_wait
              enterDetail@SyscallEnterDetails_epoll_wait{} -> do
                pure $ DetailedSyscallExit_epoll_wait $
                  SyscallExitDetails_epoll_wait{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_epoll_pwait
              enterDetail@SyscallEnterDetails_epoll_pwait{} -> do
                pure $ DetailedSyscallExit_epoll_pwait $
                  SyscallExitDetails_epoll_pwait{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_uselib
              enterDetail@SyscallEnterDetails_uselib{} -> do
                pure $ DetailedSyscallExit_uselib $
                  SyscallExitDetails_uselib{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_execveat
              enterDetail@SyscallEnterDetails_execveat{} -> do
                pure $ DetailedSyscallExit_execveat $
                  SyscallExitDetails_execveat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fcntl
              enterDetail@SyscallEnterDetails_fcntl{} -> do
                pure $ DetailedSyscallExit_fcntl $
                  SyscallExitDetails_fcntl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fcntl64
              enterDetail@SyscallEnterDetails_fcntl64{} -> do
                pure $ DetailedSyscallExit_fcntl64 $
                  SyscallExitDetails_fcntl64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_name_to_handle_at
              enterDetail@SyscallEnterDetails_name_to_handle_at{} -> do
                pure $ DetailedSyscallExit_name_to_handle_at $
                  SyscallExitDetails_name_to_handle_at{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_open_by_handle_at
              enterDetail@SyscallEnterDetails_open_by_handle_at{} -> do
                pure $ DetailedSyscallExit_open_by_handle_at $
                  SyscallExitDetails_open_by_handle_at{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_dup3
              enterDetail@SyscallEnterDetails_dup3{} -> do
                pure $ DetailedSyscallExit_dup3 $
                  SyscallExitDetails_dup3{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_dup2
              enterDetail@SyscallEnterDetails_dup2{} -> do
                pure $ DetailedSyscallExit_dup2 $
                  SyscallExitDetails_dup2{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_dup
              enterDetail@SyscallEnterDetails_dup{} -> do
                pure $ DetailedSyscallExit_dup $
                  SyscallExitDetails_dup{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sysfs
              enterDetail@SyscallEnterDetails_sysfs{} -> do
                pure $ DetailedSyscallExit_sysfs $
                  SyscallExitDetails_sysfs{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ioctl
              enterDetail@SyscallEnterDetails_ioctl{} -> do
                pure $ DetailedSyscallExit_ioctl $
                  SyscallExitDetails_ioctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_flock
              enterDetail@SyscallEnterDetails_flock{} -> do
                pure $ DetailedSyscallExit_flock $
                  SyscallExitDetails_flock{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mknodat
              enterDetail@SyscallEnterDetails_mknodat{} -> do
                pure $ DetailedSyscallExit_mknodat $
                  SyscallExitDetails_mknodat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mknod
              enterDetail@SyscallEnterDetails_mknod{} -> do
                pure $ DetailedSyscallExit_mknod $
                  SyscallExitDetails_mknod{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mkdirat
              enterDetail@SyscallEnterDetails_mkdirat{} -> do
                pure $ DetailedSyscallExit_mkdirat $
                  SyscallExitDetails_mkdirat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mkdir
              enterDetail@SyscallEnterDetails_mkdir{} -> do
                pure $ DetailedSyscallExit_mkdir $
                  SyscallExitDetails_mkdir{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rmdir
              enterDetail@SyscallEnterDetails_rmdir{} -> do
                pure $ DetailedSyscallExit_rmdir $
                  SyscallExitDetails_rmdir{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_unlinkat
              enterDetail@SyscallEnterDetails_unlinkat{} -> do
                pure $ DetailedSyscallExit_unlinkat $
                  SyscallExitDetails_unlinkat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_unlink
              enterDetail@SyscallEnterDetails_unlink{} -> do
                pure $ DetailedSyscallExit_unlink $
                  SyscallExitDetails_unlink{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_symlinkat
              enterDetail@SyscallEnterDetails_symlinkat{} -> do
                pure $ DetailedSyscallExit_symlinkat $
                  SyscallExitDetails_symlinkat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_symlink
              enterDetail@SyscallEnterDetails_symlink{} -> do
                pure $ DetailedSyscallExit_symlink $
                  SyscallExitDetails_symlink{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_linkat
              enterDetail@SyscallEnterDetails_linkat{} -> do
                pure $ DetailedSyscallExit_linkat $
                  SyscallExitDetails_linkat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_link
              enterDetail@SyscallEnterDetails_link{} -> do
                pure $ DetailedSyscallExit_link $
                  SyscallExitDetails_link{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_umount
              enterDetail@SyscallEnterDetails_umount{} -> do
                pure $ DetailedSyscallExit_umount $
                  SyscallExitDetails_umount{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_oldumount
              enterDetail@SyscallEnterDetails_oldumount{} -> do
                pure $ DetailedSyscallExit_oldumount $
                  SyscallExitDetails_oldumount{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mount
              enterDetail@SyscallEnterDetails_mount{} -> do
                pure $ DetailedSyscallExit_mount $
                  SyscallExitDetails_mount{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pivot_root
              enterDetail@SyscallEnterDetails_pivot_root{} -> do
                pure $ DetailedSyscallExit_pivot_root $
                  SyscallExitDetails_pivot_root{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fanotify_init
              enterDetail@SyscallEnterDetails_fanotify_init{} -> do
                pure $ DetailedSyscallExit_fanotify_init $
                  SyscallExitDetails_fanotify_init{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fanotify_mark
              enterDetail@SyscallEnterDetails_fanotify_mark{} -> do
                pure $ DetailedSyscallExit_fanotify_mark $
                  SyscallExitDetails_fanotify_mark{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_inotify_init1
              enterDetail@SyscallEnterDetails_inotify_init1{} -> do
                pure $ DetailedSyscallExit_inotify_init1 $
                  SyscallExitDetails_inotify_init1{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_inotify_init
              enterDetail@SyscallEnterDetails_inotify_init{} -> do
                pure $ DetailedSyscallExit_inotify_init $
                  SyscallExitDetails_inotify_init{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_inotify_add_watch
              enterDetail@SyscallEnterDetails_inotify_add_watch{} -> do
                pure $ DetailedSyscallExit_inotify_add_watch $
                  SyscallExitDetails_inotify_add_watch{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_inotify_rm_watch
              enterDetail@SyscallEnterDetails_inotify_rm_watch{} -> do
                pure $ DetailedSyscallExit_inotify_rm_watch $
                  SyscallExitDetails_inotify_rm_watch{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_truncate
              enterDetail@SyscallEnterDetails_truncate{} -> do
                pure $ DetailedSyscallExit_truncate $
                  SyscallExitDetails_truncate{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ftruncate
              enterDetail@SyscallEnterDetails_ftruncate{} -> do
                pure $ DetailedSyscallExit_ftruncate $
                  SyscallExitDetails_ftruncate{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_truncate64
              enterDetail@SyscallEnterDetails_truncate64{} -> do
                pure $ DetailedSyscallExit_truncate64 $
                  SyscallExitDetails_truncate64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ftruncate64
              enterDetail@SyscallEnterDetails_ftruncate64{} -> do
                pure $ DetailedSyscallExit_ftruncate64 $
                  SyscallExitDetails_ftruncate64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fallocate
              enterDetail@SyscallEnterDetails_fallocate{} -> do
                pure $ DetailedSyscallExit_fallocate $
                  SyscallExitDetails_fallocate{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_chdir
              enterDetail@SyscallEnterDetails_chdir{} -> do
                pure $ DetailedSyscallExit_chdir $
                  SyscallExitDetails_chdir{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fchdir
              enterDetail@SyscallEnterDetails_fchdir{} -> do
                pure $ DetailedSyscallExit_fchdir $
                  SyscallExitDetails_fchdir{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_chroot
              enterDetail@SyscallEnterDetails_chroot{} -> do
                pure $ DetailedSyscallExit_chroot $
                  SyscallExitDetails_chroot{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fchmod
              enterDetail@SyscallEnterDetails_fchmod{} -> do
                pure $ DetailedSyscallExit_fchmod $
                  SyscallExitDetails_fchmod{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fchmodat
              enterDetail@SyscallEnterDetails_fchmodat{} -> do
                pure $ DetailedSyscallExit_fchmodat $
                  SyscallExitDetails_fchmodat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_chmod
              enterDetail@SyscallEnterDetails_chmod{} -> do
                pure $ DetailedSyscallExit_chmod $
                  SyscallExitDetails_chmod{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fchownat
              enterDetail@SyscallEnterDetails_fchownat{} -> do
                pure $ DetailedSyscallExit_fchownat $
                  SyscallExitDetails_fchownat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_chown
              enterDetail@SyscallEnterDetails_chown{} -> do
                pure $ DetailedSyscallExit_chown $
                  SyscallExitDetails_chown{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lchown
              enterDetail@SyscallEnterDetails_lchown{} -> do
                pure $ DetailedSyscallExit_lchown $
                  SyscallExitDetails_lchown{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fchown
              enterDetail@SyscallEnterDetails_fchown{} -> do
                pure $ DetailedSyscallExit_fchown $
                  SyscallExitDetails_fchown{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_vhangup
              enterDetail@SyscallEnterDetails_vhangup{} -> do
                pure $ DetailedSyscallExit_vhangup $
                  SyscallExitDetails_vhangup{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_quotactl
              enterDetail@SyscallEnterDetails_quotactl{} -> do
                pure $ DetailedSyscallExit_quotactl $
                  SyscallExitDetails_quotactl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lseek
              enterDetail@SyscallEnterDetails_lseek{} -> do
                pure $ DetailedSyscallExit_lseek $
                  SyscallExitDetails_lseek{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pread64
              enterDetail@SyscallEnterDetails_pread64{} -> do
                pure $ DetailedSyscallExit_pread64 $
                  SyscallExitDetails_pread64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pwrite64
              enterDetail@SyscallEnterDetails_pwrite64{} -> do
                pure $ DetailedSyscallExit_pwrite64 $
                  SyscallExitDetails_pwrite64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_readv
              enterDetail@SyscallEnterDetails_readv{} -> do
                pure $ DetailedSyscallExit_readv $
                  SyscallExitDetails_readv{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_writev
              enterDetail@SyscallEnterDetails_writev{} -> do
                pure $ DetailedSyscallExit_writev $
                  SyscallExitDetails_writev{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_preadv
              enterDetail@SyscallEnterDetails_preadv{} -> do
                pure $ DetailedSyscallExit_preadv $
                  SyscallExitDetails_preadv{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_preadv2
              enterDetail@SyscallEnterDetails_preadv2{} -> do
                pure $ DetailedSyscallExit_preadv2 $
                  SyscallExitDetails_preadv2{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pwritev
              enterDetail@SyscallEnterDetails_pwritev{} -> do
                pure $ DetailedSyscallExit_pwritev $
                  SyscallExitDetails_pwritev{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pwritev2
              enterDetail@SyscallEnterDetails_pwritev2{} -> do
                pure $ DetailedSyscallExit_pwritev2 $
                  SyscallExitDetails_pwritev2{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sendfile
              enterDetail@SyscallEnterDetails_sendfile{} -> do
                pure $ DetailedSyscallExit_sendfile $
                  SyscallExitDetails_sendfile{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sendfile64
              enterDetail@SyscallEnterDetails_sendfile64{} -> do
                pure $ DetailedSyscallExit_sendfile64 $
                  SyscallExitDetails_sendfile64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_copy_file_range
              enterDetail@SyscallEnterDetails_copy_file_range{} -> do
                pure $ DetailedSyscallExit_copy_file_range $
                  SyscallExitDetails_copy_file_range{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getdents
              enterDetail@SyscallEnterDetails_getdents{} -> do
                pure $ DetailedSyscallExit_getdents $
                  SyscallExitDetails_getdents{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getdents64
              enterDetail@SyscallEnterDetails_getdents64{} -> do
                pure $ DetailedSyscallExit_getdents64 $
                  SyscallExitDetails_getdents64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_poll
              enterDetail@SyscallEnterDetails_poll{} -> do
                pure $ DetailedSyscallExit_poll $
                  SyscallExitDetails_poll{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ppoll
              enterDetail@SyscallEnterDetails_ppoll{} -> do
                pure $ DetailedSyscallExit_ppoll $
                  SyscallExitDetails_ppoll{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_signalfd4
              enterDetail@SyscallEnterDetails_signalfd4{} -> do
                pure $ DetailedSyscallExit_signalfd4 $
                  SyscallExitDetails_signalfd4{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_signalfd
              enterDetail@SyscallEnterDetails_signalfd{} -> do
                pure $ DetailedSyscallExit_signalfd $
                  SyscallExitDetails_signalfd{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_vmsplice
              enterDetail@SyscallEnterDetails_vmsplice{} -> do
                pure $ DetailedSyscallExit_vmsplice $
                  SyscallExitDetails_vmsplice{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_splice
              enterDetail@SyscallEnterDetails_splice{} -> do
                pure $ DetailedSyscallExit_splice $
                  SyscallExitDetails_splice{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_tee
              enterDetail@SyscallEnterDetails_tee{} -> do
                pure $ DetailedSyscallExit_tee $
                  SyscallExitDetails_tee{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_readlinkat
              enterDetail@SyscallEnterDetails_readlinkat{} -> do
                pure $ DetailedSyscallExit_readlinkat $
                  SyscallExitDetails_readlinkat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_readlink
              enterDetail@SyscallEnterDetails_readlink{} -> do
                pure $ DetailedSyscallExit_readlink $
                  SyscallExitDetails_readlink{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_stat64
              enterDetail@SyscallEnterDetails_stat64{} -> do
                pure $ DetailedSyscallExit_stat64 $
                  SyscallExitDetails_stat64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lstat64
              enterDetail@SyscallEnterDetails_lstat64{} -> do
                pure $ DetailedSyscallExit_lstat64 $
                  SyscallExitDetails_lstat64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fstat64
              enterDetail@SyscallEnterDetails_fstat64{} -> do
                pure $ DetailedSyscallExit_fstat64 $
                  SyscallExitDetails_fstat64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fstatat64
              enterDetail@SyscallEnterDetails_fstatat64{} -> do
                pure $ DetailedSyscallExit_fstatat64 $
                  SyscallExitDetails_fstatat64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_statx
              enterDetail@SyscallEnterDetails_statx{} -> do
                pure $ DetailedSyscallExit_statx $
                  SyscallExitDetails_statx{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_statfs
              enterDetail@SyscallEnterDetails_statfs{} -> do
                pure $ DetailedSyscallExit_statfs $
                  SyscallExitDetails_statfs{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_statfs64
              enterDetail@SyscallEnterDetails_statfs64{} -> do
                pure $ DetailedSyscallExit_statfs64 $
                  SyscallExitDetails_statfs64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fstatfs
              enterDetail@SyscallEnterDetails_fstatfs{} -> do
                pure $ DetailedSyscallExit_fstatfs $
                  SyscallExitDetails_fstatfs{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fstatfs64
              enterDetail@SyscallEnterDetails_fstatfs64{} -> do
                pure $ DetailedSyscallExit_fstatfs64 $
                  SyscallExitDetails_fstatfs64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ustat
              enterDetail@SyscallEnterDetails_ustat{} -> do
                pure $ DetailedSyscallExit_ustat $
                  SyscallExitDetails_ustat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sync
              enterDetail@SyscallEnterDetails_sync{} -> do
                pure $ DetailedSyscallExit_sync $
                  SyscallExitDetails_sync{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_syncfs
              enterDetail@SyscallEnterDetails_syncfs{} -> do
                pure $ DetailedSyscallExit_syncfs $
                  SyscallExitDetails_syncfs{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fsync
              enterDetail@SyscallEnterDetails_fsync{} -> do
                pure $ DetailedSyscallExit_fsync $
                  SyscallExitDetails_fsync{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fdatasync
              enterDetail@SyscallEnterDetails_fdatasync{} -> do
                pure $ DetailedSyscallExit_fdatasync $
                  SyscallExitDetails_fdatasync{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sync_file_range
              enterDetail@SyscallEnterDetails_sync_file_range{} -> do
                pure $ DetailedSyscallExit_sync_file_range $
                  SyscallExitDetails_sync_file_range{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sync_file_range2
              enterDetail@SyscallEnterDetails_sync_file_range2{} -> do
                pure $ DetailedSyscallExit_sync_file_range2 $
                  SyscallExitDetails_sync_file_range2{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timerfd_create
              enterDetail@SyscallEnterDetails_timerfd_create{} -> do
                pure $ DetailedSyscallExit_timerfd_create $
                  SyscallExitDetails_timerfd_create{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timerfd_settime
              enterDetail@SyscallEnterDetails_timerfd_settime{} -> do
                pure $ DetailedSyscallExit_timerfd_settime $
                  SyscallExitDetails_timerfd_settime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timerfd_gettime
              enterDetail@SyscallEnterDetails_timerfd_gettime{} -> do
                pure $ DetailedSyscallExit_timerfd_gettime $
                  SyscallExitDetails_timerfd_gettime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_userfaultfd
              enterDetail@SyscallEnterDetails_userfaultfd{} -> do
                pure $ DetailedSyscallExit_userfaultfd $
                  SyscallExitDetails_userfaultfd{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_utimensat
              enterDetail@SyscallEnterDetails_utimensat{} -> do
                pure $ DetailedSyscallExit_utimensat $
                  SyscallExitDetails_utimensat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_futimesat
              enterDetail@SyscallEnterDetails_futimesat{} -> do
                pure $ DetailedSyscallExit_futimesat $
                  SyscallExitDetails_futimesat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_utimes
              enterDetail@SyscallEnterDetails_utimes{} -> do
                pure $ DetailedSyscallExit_utimes $
                  SyscallExitDetails_utimes{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_utime
              enterDetail@SyscallEnterDetails_utime{} -> do
                pure $ DetailedSyscallExit_utime $
                  SyscallExitDetails_utime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setxattr
              enterDetail@SyscallEnterDetails_setxattr{} -> do
                pure $ DetailedSyscallExit_setxattr $
                  SyscallExitDetails_setxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lsetxattr
              enterDetail@SyscallEnterDetails_lsetxattr{} -> do
                pure $ DetailedSyscallExit_lsetxattr $
                  SyscallExitDetails_lsetxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fsetxattr
              enterDetail@SyscallEnterDetails_fsetxattr{} -> do
                pure $ DetailedSyscallExit_fsetxattr $
                  SyscallExitDetails_fsetxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getxattr
              enterDetail@SyscallEnterDetails_getxattr{} -> do
                pure $ DetailedSyscallExit_getxattr $
                  SyscallExitDetails_getxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lgetxattr
              enterDetail@SyscallEnterDetails_lgetxattr{} -> do
                pure $ DetailedSyscallExit_lgetxattr $
                  SyscallExitDetails_lgetxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fgetxattr
              enterDetail@SyscallEnterDetails_fgetxattr{} -> do
                pure $ DetailedSyscallExit_fgetxattr $
                  SyscallExitDetails_fgetxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_listxattr
              enterDetail@SyscallEnterDetails_listxattr{} -> do
                pure $ DetailedSyscallExit_listxattr $
                  SyscallExitDetails_listxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_llistxattr
              enterDetail@SyscallEnterDetails_llistxattr{} -> do
                pure $ DetailedSyscallExit_llistxattr $
                  SyscallExitDetails_llistxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_flistxattr
              enterDetail@SyscallEnterDetails_flistxattr{} -> do
                pure $ DetailedSyscallExit_flistxattr $
                  SyscallExitDetails_flistxattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_removexattr
              enterDetail@SyscallEnterDetails_removexattr{} -> do
                pure $ DetailedSyscallExit_removexattr $
                  SyscallExitDetails_removexattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_lremovexattr
              enterDetail@SyscallEnterDetails_lremovexattr{} -> do
                pure $ DetailedSyscallExit_lremovexattr $
                  SyscallExitDetails_lremovexattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fremovexattr
              enterDetail@SyscallEnterDetails_fremovexattr{} -> do
                pure $ DetailedSyscallExit_fremovexattr $
                  SyscallExitDetails_fremovexattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_msgget
              enterDetail@SyscallEnterDetails_msgget{} -> do
                pure $ DetailedSyscallExit_msgget $
                  SyscallExitDetails_msgget{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_msgctl
              enterDetail@SyscallEnterDetails_msgctl{} -> do
                pure $ DetailedSyscallExit_msgctl $
                  SyscallExitDetails_msgctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_msgsnd
              enterDetail@SyscallEnterDetails_msgsnd{} -> do
                pure $ DetailedSyscallExit_msgsnd $
                  SyscallExitDetails_msgsnd{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_msgrcv
              enterDetail@SyscallEnterDetails_msgrcv{} -> do
                pure $ DetailedSyscallExit_msgrcv $
                  SyscallExitDetails_msgrcv{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_semget
              enterDetail@SyscallEnterDetails_semget{} -> do
                pure $ DetailedSyscallExit_semget $
                  SyscallExitDetails_semget{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_semctl
              enterDetail@SyscallEnterDetails_semctl{} -> do
                pure $ DetailedSyscallExit_semctl $
                  SyscallExitDetails_semctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_semtimedop
              enterDetail@SyscallEnterDetails_semtimedop{} -> do
                pure $ DetailedSyscallExit_semtimedop $
                  SyscallExitDetails_semtimedop{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_semop
              enterDetail@SyscallEnterDetails_semop{} -> do
                pure $ DetailedSyscallExit_semop $
                  SyscallExitDetails_semop{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_shmget
              enterDetail@SyscallEnterDetails_shmget{} -> do
                pure $ DetailedSyscallExit_shmget $
                  SyscallExitDetails_shmget{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_shmctl
              enterDetail@SyscallEnterDetails_shmctl{} -> do
                pure $ DetailedSyscallExit_shmctl $
                  SyscallExitDetails_shmctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_shmat
              enterDetail@SyscallEnterDetails_shmat{} -> do
                pure $ DetailedSyscallExit_shmat $
                  SyscallExitDetails_shmat{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_shmdt
              enterDetail@SyscallEnterDetails_shmdt{} -> do
                pure $ DetailedSyscallExit_shmdt $
                  SyscallExitDetails_shmdt{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ipc
              enterDetail@SyscallEnterDetails_ipc{} -> do
                pure $ DetailedSyscallExit_ipc $
                  SyscallExitDetails_ipc{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_acct
              enterDetail@SyscallEnterDetails_acct{} -> do
                pure $ DetailedSyscallExit_acct $
                  SyscallExitDetails_acct{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_perf_event_open
              enterDetail@SyscallEnterDetails_perf_event_open{} -> do
                pure $ DetailedSyscallExit_perf_event_open $
                  SyscallExitDetails_perf_event_open{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_personality
              enterDetail@SyscallEnterDetails_personality{} -> do
                pure $ DetailedSyscallExit_personality $
                  SyscallExitDetails_personality{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_waitid
              enterDetail@SyscallEnterDetails_waitid{} -> do
                pure $ DetailedSyscallExit_waitid $
                  SyscallExitDetails_waitid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_wait4
              enterDetail@SyscallEnterDetails_wait4{} -> do
                pure $ DetailedSyscallExit_wait4 $
                  SyscallExitDetails_wait4{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_waitpid
              enterDetail@SyscallEnterDetails_waitpid{} -> do
                pure $ DetailedSyscallExit_waitpid $
                  SyscallExitDetails_waitpid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_set_tid_address
              enterDetail@SyscallEnterDetails_set_tid_address{} -> do
                pure $ DetailedSyscallExit_set_tid_address $
                  SyscallExitDetails_set_tid_address{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fork
              enterDetail@SyscallEnterDetails_fork{} -> do
                pure $ DetailedSyscallExit_fork $
                  SyscallExitDetails_fork{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_vfork
              enterDetail@SyscallEnterDetails_vfork{} -> do
                pure $ DetailedSyscallExit_vfork $
                  SyscallExitDetails_vfork{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_clone
              enterDetail@SyscallEnterDetails_clone{} -> do
                pure $ DetailedSyscallExit_clone $
                  SyscallExitDetails_clone{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_unshare
              enterDetail@SyscallEnterDetails_unshare{} -> do
                pure $ DetailedSyscallExit_unshare $
                  SyscallExitDetails_unshare{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_set_robust_list
              enterDetail@SyscallEnterDetails_set_robust_list{} -> do
                pure $ DetailedSyscallExit_set_robust_list $
                  SyscallExitDetails_set_robust_list{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_get_robust_list
              enterDetail@SyscallEnterDetails_get_robust_list{} -> do
                pure $ DetailedSyscallExit_get_robust_list $
                  SyscallExitDetails_get_robust_list{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_futex
              enterDetail@SyscallEnterDetails_futex{} -> do
                pure $ DetailedSyscallExit_futex $
                  SyscallExitDetails_futex{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getgroups
              enterDetail@SyscallEnterDetails_getgroups{} -> do
                pure $ DetailedSyscallExit_getgroups $
                  SyscallExitDetails_getgroups{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setgroups
              enterDetail@SyscallEnterDetails_setgroups{} -> do
                pure $ DetailedSyscallExit_setgroups $
                  SyscallExitDetails_setgroups{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_kcmp
              enterDetail@SyscallEnterDetails_kcmp{} -> do
                pure $ DetailedSyscallExit_kcmp $
                  SyscallExitDetails_kcmp{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_kexec_load
              enterDetail@SyscallEnterDetails_kexec_load{} -> do
                pure $ DetailedSyscallExit_kexec_load $
                  SyscallExitDetails_kexec_load{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_kexec_file_load
              enterDetail@SyscallEnterDetails_kexec_file_load{} -> do
                pure $ DetailedSyscallExit_kexec_file_load $
                  SyscallExitDetails_kexec_file_load{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_delete_module
              enterDetail@SyscallEnterDetails_delete_module{} -> do
                pure $ DetailedSyscallExit_delete_module $
                  SyscallExitDetails_delete_module{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_init_module
              enterDetail@SyscallEnterDetails_init_module{} -> do
                pure $ DetailedSyscallExit_init_module $
                  SyscallExitDetails_init_module{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_finit_module
              enterDetail@SyscallEnterDetails_finit_module{} -> do
                pure $ DetailedSyscallExit_finit_module $
                  SyscallExitDetails_finit_module{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setns
              enterDetail@SyscallEnterDetails_setns{} -> do
                pure $ DetailedSyscallExit_setns $
                  SyscallExitDetails_setns{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_syslog
              enterDetail@SyscallEnterDetails_syslog{} -> do
                pure $ DetailedSyscallExit_syslog $
                  SyscallExitDetails_syslog{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ptrace
              enterDetail@SyscallEnterDetails_ptrace{} -> do
                pure $ DetailedSyscallExit_ptrace $
                  SyscallExitDetails_ptrace{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_reboot
              enterDetail@SyscallEnterDetails_reboot{} -> do
                pure $ DetailedSyscallExit_reboot $
                  SyscallExitDetails_reboot{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rseq
              enterDetail@SyscallEnterDetails_rseq{} -> do
                pure $ DetailedSyscallExit_rseq $
                  SyscallExitDetails_rseq{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_nice
              enterDetail@SyscallEnterDetails_nice{} -> do
                pure $ DetailedSyscallExit_nice $
                  SyscallExitDetails_nice{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_setscheduler
              enterDetail@SyscallEnterDetails_sched_setscheduler{} -> do
                pure $ DetailedSyscallExit_sched_setscheduler $
                  SyscallExitDetails_sched_setscheduler{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_setparam
              enterDetail@SyscallEnterDetails_sched_setparam{} -> do
                pure $ DetailedSyscallExit_sched_setparam $
                  SyscallExitDetails_sched_setparam{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_setattr
              enterDetail@SyscallEnterDetails_sched_setattr{} -> do
                pure $ DetailedSyscallExit_sched_setattr $
                  SyscallExitDetails_sched_setattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_getscheduler
              enterDetail@SyscallEnterDetails_sched_getscheduler{} -> do
                pure $ DetailedSyscallExit_sched_getscheduler $
                  SyscallExitDetails_sched_getscheduler{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_getparam
              enterDetail@SyscallEnterDetails_sched_getparam{} -> do
                pure $ DetailedSyscallExit_sched_getparam $
                  SyscallExitDetails_sched_getparam{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_getattr
              enterDetail@SyscallEnterDetails_sched_getattr{} -> do
                pure $ DetailedSyscallExit_sched_getattr $
                  SyscallExitDetails_sched_getattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_setaffinity
              enterDetail@SyscallEnterDetails_sched_setaffinity{} -> do
                pure $ DetailedSyscallExit_sched_setaffinity $
                  SyscallExitDetails_sched_setaffinity{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_getaffinity
              enterDetail@SyscallEnterDetails_sched_getaffinity{} -> do
                pure $ DetailedSyscallExit_sched_getaffinity $
                  SyscallExitDetails_sched_getaffinity{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_yield
              enterDetail@SyscallEnterDetails_sched_yield{} -> do
                pure $ DetailedSyscallExit_sched_yield $
                  SyscallExitDetails_sched_yield{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_get_priority_max
              enterDetail@SyscallEnterDetails_sched_get_priority_max{} -> do
                pure $ DetailedSyscallExit_sched_get_priority_max $
                  SyscallExitDetails_sched_get_priority_max{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_get_priority_min
              enterDetail@SyscallEnterDetails_sched_get_priority_min{} -> do
                pure $ DetailedSyscallExit_sched_get_priority_min $
                  SyscallExitDetails_sched_get_priority_min{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sched_rr_get_interval
              enterDetail@SyscallEnterDetails_sched_rr_get_interval{} -> do
                pure $ DetailedSyscallExit_sched_rr_get_interval $
                  SyscallExitDetails_sched_rr_get_interval{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_membarrier
              enterDetail@SyscallEnterDetails_membarrier{} -> do
                pure $ DetailedSyscallExit_membarrier $
                  SyscallExitDetails_membarrier{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_seccomp
              enterDetail@SyscallEnterDetails_seccomp{} -> do
                pure $ DetailedSyscallExit_seccomp $
                  SyscallExitDetails_seccomp{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_restart_syscall
              enterDetail@SyscallEnterDetails_restart_syscall{} -> do
                pure $ DetailedSyscallExit_restart_syscall $
                  SyscallExitDetails_restart_syscall{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigprocmask
              enterDetail@SyscallEnterDetails_rt_sigprocmask{} -> do
                pure $ DetailedSyscallExit_rt_sigprocmask $
                  SyscallExitDetails_rt_sigprocmask{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigpending
              enterDetail@SyscallEnterDetails_rt_sigpending{} -> do
                pure $ DetailedSyscallExit_rt_sigpending $
                  SyscallExitDetails_rt_sigpending{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_kill
              enterDetail@SyscallEnterDetails_kill{} -> do
                pure $ DetailedSyscallExit_kill $
                  SyscallExitDetails_kill{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_tgkill
              enterDetail@SyscallEnterDetails_tgkill{} -> do
                pure $ DetailedSyscallExit_tgkill $
                  SyscallExitDetails_tgkill{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_tkill
              enterDetail@SyscallEnterDetails_tkill{} -> do
                pure $ DetailedSyscallExit_tkill $
                  SyscallExitDetails_tkill{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sigpending
              enterDetail@SyscallEnterDetails_sigpending{} -> do
                pure $ DetailedSyscallExit_sigpending $
                  SyscallExitDetails_sigpending{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sigprocmask
              enterDetail@SyscallEnterDetails_sigprocmask{} -> do
                pure $ DetailedSyscallExit_sigprocmask $
                  SyscallExitDetails_sigprocmask{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigaction
              enterDetail@SyscallEnterDetails_rt_sigaction{} -> do
                pure $ DetailedSyscallExit_rt_sigaction $
                  SyscallExitDetails_rt_sigaction{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sigaction
              enterDetail@SyscallEnterDetails_sigaction{} -> do
                pure $ DetailedSyscallExit_sigaction $
                  SyscallExitDetails_sigaction{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sgetmask
              enterDetail@SyscallEnterDetails_sgetmask{} -> do
                pure $ DetailedSyscallExit_sgetmask $
                  SyscallExitDetails_sgetmask{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_ssetmask
              enterDetail@SyscallEnterDetails_ssetmask{} -> do
                pure $ DetailedSyscallExit_ssetmask $
                  SyscallExitDetails_ssetmask{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_signal
              enterDetail@SyscallEnterDetails_signal{} -> do
                pure $ DetailedSyscallExit_signal $
                  SyscallExitDetails_signal{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pause
              enterDetail@SyscallEnterDetails_pause{} -> do
                pure $ DetailedSyscallExit_pause $
                  SyscallExitDetails_pause{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigsuspend
              enterDetail@SyscallEnterDetails_rt_sigsuspend{} -> do
                pure $ DetailedSyscallExit_rt_sigsuspend $
                  SyscallExitDetails_rt_sigsuspend{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sigsuspend
              enterDetail@SyscallEnterDetails_sigsuspend{} -> do
                pure $ DetailedSyscallExit_sigsuspend $
                  SyscallExitDetails_sigsuspend{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setpriority
              enterDetail@SyscallEnterDetails_setpriority{} -> do
                pure $ DetailedSyscallExit_setpriority $
                  SyscallExitDetails_setpriority{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getpriority
              enterDetail@SyscallEnterDetails_getpriority{} -> do
                pure $ DetailedSyscallExit_getpriority $
                  SyscallExitDetails_getpriority{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setregid
              enterDetail@SyscallEnterDetails_setregid{} -> do
                pure $ DetailedSyscallExit_setregid $
                  SyscallExitDetails_setregid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setgid
              enterDetail@SyscallEnterDetails_setgid{} -> do
                pure $ DetailedSyscallExit_setgid $
                  SyscallExitDetails_setgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setreuid
              enterDetail@SyscallEnterDetails_setreuid{} -> do
                pure $ DetailedSyscallExit_setreuid $
                  SyscallExitDetails_setreuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setuid
              enterDetail@SyscallEnterDetails_setuid{} -> do
                pure $ DetailedSyscallExit_setuid $
                  SyscallExitDetails_setuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setresuid
              enterDetail@SyscallEnterDetails_setresuid{} -> do
                pure $ DetailedSyscallExit_setresuid $
                  SyscallExitDetails_setresuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getresuid
              enterDetail@SyscallEnterDetails_getresuid{} -> do
                pure $ DetailedSyscallExit_getresuid $
                  SyscallExitDetails_getresuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setresgid
              enterDetail@SyscallEnterDetails_setresgid{} -> do
                pure $ DetailedSyscallExit_setresgid $
                  SyscallExitDetails_setresgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getresgid
              enterDetail@SyscallEnterDetails_getresgid{} -> do
                pure $ DetailedSyscallExit_getresgid $
                  SyscallExitDetails_getresgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setfsuid
              enterDetail@SyscallEnterDetails_setfsuid{} -> do
                pure $ DetailedSyscallExit_setfsuid $
                  SyscallExitDetails_setfsuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setfsgid
              enterDetail@SyscallEnterDetails_setfsgid{} -> do
                pure $ DetailedSyscallExit_setfsgid $
                  SyscallExitDetails_setfsgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getpid
              enterDetail@SyscallEnterDetails_getpid{} -> do
                pure $ DetailedSyscallExit_getpid $
                  SyscallExitDetails_getpid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_gettid
              enterDetail@SyscallEnterDetails_gettid{} -> do
                pure $ DetailedSyscallExit_gettid $
                  SyscallExitDetails_gettid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getppid
              enterDetail@SyscallEnterDetails_getppid{} -> do
                pure $ DetailedSyscallExit_getppid $
                  SyscallExitDetails_getppid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getuid
              enterDetail@SyscallEnterDetails_getuid{} -> do
                pure $ DetailedSyscallExit_getuid $
                  SyscallExitDetails_getuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_geteuid
              enterDetail@SyscallEnterDetails_geteuid{} -> do
                pure $ DetailedSyscallExit_geteuid $
                  SyscallExitDetails_geteuid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getgid
              enterDetail@SyscallEnterDetails_getgid{} -> do
                pure $ DetailedSyscallExit_getgid $
                  SyscallExitDetails_getgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getegid
              enterDetail@SyscallEnterDetails_getegid{} -> do
                pure $ DetailedSyscallExit_getegid $
                  SyscallExitDetails_getegid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_times
              enterDetail@SyscallEnterDetails_times{} -> do
                pure $ DetailedSyscallExit_times $
                  SyscallExitDetails_times{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setpgid
              enterDetail@SyscallEnterDetails_setpgid{} -> do
                pure $ DetailedSyscallExit_setpgid $
                  SyscallExitDetails_setpgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getpgid
              enterDetail@SyscallEnterDetails_getpgid{} -> do
                pure $ DetailedSyscallExit_getpgid $
                  SyscallExitDetails_getpgid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getpgrp
              enterDetail@SyscallEnterDetails_getpgrp{} -> do
                pure $ DetailedSyscallExit_getpgrp $
                  SyscallExitDetails_getpgrp{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getsid
              enterDetail@SyscallEnterDetails_getsid{} -> do
                pure $ DetailedSyscallExit_getsid $
                  SyscallExitDetails_getsid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setsid
              enterDetail@SyscallEnterDetails_setsid{} -> do
                pure $ DetailedSyscallExit_setsid $
                  SyscallExitDetails_setsid{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_uname
              enterDetail@SyscallEnterDetails_uname{} -> do
                pure $ DetailedSyscallExit_uname $
                  SyscallExitDetails_uname{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_olduname
              enterDetail@SyscallEnterDetails_olduname{} -> do
                pure $ DetailedSyscallExit_olduname $
                  SyscallExitDetails_olduname{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sethostname
              enterDetail@SyscallEnterDetails_sethostname{} -> do
                pure $ DetailedSyscallExit_sethostname $
                  SyscallExitDetails_sethostname{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_gethostname
              enterDetail@SyscallEnterDetails_gethostname{} -> do
                pure $ DetailedSyscallExit_gethostname $
                  SyscallExitDetails_gethostname{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setdomainname
              enterDetail@SyscallEnterDetails_setdomainname{} -> do
                pure $ DetailedSyscallExit_setdomainname $
                  SyscallExitDetails_setdomainname{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getrlimit
              enterDetail@SyscallEnterDetails_getrlimit{} -> do
                pure $ DetailedSyscallExit_getrlimit $
                  SyscallExitDetails_getrlimit{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_prlimit64
              enterDetail@SyscallEnterDetails_prlimit64{} -> do
                pure $ DetailedSyscallExit_prlimit64 $
                  SyscallExitDetails_prlimit64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setrlimit
              enterDetail@SyscallEnterDetails_setrlimit{} -> do
                pure $ DetailedSyscallExit_setrlimit $
                  SyscallExitDetails_setrlimit{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getrusage
              enterDetail@SyscallEnterDetails_getrusage{} -> do
                pure $ DetailedSyscallExit_getrusage $
                  SyscallExitDetails_getrusage{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_umask
              enterDetail@SyscallEnterDetails_umask{} -> do
                pure $ DetailedSyscallExit_umask $
                  SyscallExitDetails_umask{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_prctl
              enterDetail@SyscallEnterDetails_prctl{} -> do
                pure $ DetailedSyscallExit_prctl $
                  SyscallExitDetails_prctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getcpu
              enterDetail@SyscallEnterDetails_getcpu{} -> do
                pure $ DetailedSyscallExit_getcpu $
                  SyscallExitDetails_getcpu{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sysinfo
              enterDetail@SyscallEnterDetails_sysinfo{} -> do
                pure $ DetailedSyscallExit_sysinfo $
                  SyscallExitDetails_sysinfo{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_nanosleep
              enterDetail@SyscallEnterDetails_nanosleep{} -> do
                pure $ DetailedSyscallExit_nanosleep $
                  SyscallExitDetails_nanosleep{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getitimer
              enterDetail@SyscallEnterDetails_getitimer{} -> do
                pure $ DetailedSyscallExit_getitimer $
                  SyscallExitDetails_getitimer{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_alarm
              enterDetail@SyscallEnterDetails_alarm{} -> do
                pure $ DetailedSyscallExit_alarm $
                  SyscallExitDetails_alarm{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setitimer
              enterDetail@SyscallEnterDetails_setitimer{} -> do
                pure $ DetailedSyscallExit_setitimer $
                  SyscallExitDetails_setitimer{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_clock_settime
              enterDetail@SyscallEnterDetails_clock_settime{} -> do
                pure $ DetailedSyscallExit_clock_settime $
                  SyscallExitDetails_clock_settime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_clock_gettime
              enterDetail@SyscallEnterDetails_clock_gettime{} -> do
                pure $ DetailedSyscallExit_clock_gettime $
                  SyscallExitDetails_clock_gettime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_clock_getres
              enterDetail@SyscallEnterDetails_clock_getres{} -> do
                pure $ DetailedSyscallExit_clock_getres $
                  SyscallExitDetails_clock_getres{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_clock_nanosleep
              enterDetail@SyscallEnterDetails_clock_nanosleep{} -> do
                pure $ DetailedSyscallExit_clock_nanosleep $
                  SyscallExitDetails_clock_nanosleep{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timer_create
              enterDetail@SyscallEnterDetails_timer_create{} -> do
                pure $ DetailedSyscallExit_timer_create $
                  SyscallExitDetails_timer_create{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timer_gettime
              enterDetail@SyscallEnterDetails_timer_gettime{} -> do
                pure $ DetailedSyscallExit_timer_gettime $
                  SyscallExitDetails_timer_gettime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timer_getoverrun
              enterDetail@SyscallEnterDetails_timer_getoverrun{} -> do
                pure $ DetailedSyscallExit_timer_getoverrun $
                  SyscallExitDetails_timer_getoverrun{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timer_settime
              enterDetail@SyscallEnterDetails_timer_settime{} -> do
                pure $ DetailedSyscallExit_timer_settime $
                  SyscallExitDetails_timer_settime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_timer_delete
              enterDetail@SyscallEnterDetails_timer_delete{} -> do
                pure $ DetailedSyscallExit_timer_delete $
                  SyscallExitDetails_timer_delete{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_clock_adjtime
              enterDetail@SyscallEnterDetails_clock_adjtime{} -> do
                pure $ DetailedSyscallExit_clock_adjtime $
                  SyscallExitDetails_clock_adjtime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_time
              enterDetail@SyscallEnterDetails_time{} -> do
                pure $ DetailedSyscallExit_time $
                  SyscallExitDetails_time{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_stime
              enterDetail@SyscallEnterDetails_stime{} -> do
                pure $ DetailedSyscallExit_stime $
                  SyscallExitDetails_stime{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_gettimeofday
              enterDetail@SyscallEnterDetails_gettimeofday{} -> do
                pure $ DetailedSyscallExit_gettimeofday $
                  SyscallExitDetails_gettimeofday{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_settimeofday
              enterDetail@SyscallEnterDetails_settimeofday{} -> do
                pure $ DetailedSyscallExit_settimeofday $
                  SyscallExitDetails_settimeofday{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_adjtimex
              enterDetail@SyscallEnterDetails_adjtimex{} -> do
                pure $ DetailedSyscallExit_adjtimex $
                  SyscallExitDetails_adjtimex{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fadvise64_64
              enterDetail@SyscallEnterDetails_fadvise64_64{} -> do
                pure $ DetailedSyscallExit_fadvise64_64 $
                  SyscallExitDetails_fadvise64_64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_fadvise64
              enterDetail@SyscallEnterDetails_fadvise64{} -> do
                pure $ DetailedSyscallExit_fadvise64 $
                  SyscallExitDetails_fadvise64{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_madvise
              enterDetail@SyscallEnterDetails_madvise{} -> do
                pure $ DetailedSyscallExit_madvise $
                  SyscallExitDetails_madvise{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_memfd_create
              enterDetail@SyscallEnterDetails_memfd_create{} -> do
                pure $ DetailedSyscallExit_memfd_create $
                  SyscallExitDetails_memfd_create{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mbind
              enterDetail@SyscallEnterDetails_mbind{} -> do
                pure $ DetailedSyscallExit_mbind $
                  SyscallExitDetails_mbind{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_set_mempolicy
              enterDetail@SyscallEnterDetails_set_mempolicy{} -> do
                pure $ DetailedSyscallExit_set_mempolicy $
                  SyscallExitDetails_set_mempolicy{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_migrate_pages
              enterDetail@SyscallEnterDetails_migrate_pages{} -> do
                pure $ DetailedSyscallExit_migrate_pages $
                  SyscallExitDetails_migrate_pages{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_get_mempolicy
              enterDetail@SyscallEnterDetails_get_mempolicy{} -> do
                pure $ DetailedSyscallExit_get_mempolicy $
                  SyscallExitDetails_get_mempolicy{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_move_pages
              enterDetail@SyscallEnterDetails_move_pages{} -> do
                pure $ DetailedSyscallExit_move_pages $
                  SyscallExitDetails_move_pages{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mincore
              enterDetail@SyscallEnterDetails_mincore{} -> do
                pure $ DetailedSyscallExit_mincore $
                  SyscallExitDetails_mincore{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mlock
              enterDetail@SyscallEnterDetails_mlock{} -> do
                pure $ DetailedSyscallExit_mlock $
                  SyscallExitDetails_mlock{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mlock2
              enterDetail@SyscallEnterDetails_mlock2{} -> do
                pure $ DetailedSyscallExit_mlock2 $
                  SyscallExitDetails_mlock2{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_munlock
              enterDetail@SyscallEnterDetails_munlock{} -> do
                pure $ DetailedSyscallExit_munlock $
                  SyscallExitDetails_munlock{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mlockall
              enterDetail@SyscallEnterDetails_mlockall{} -> do
                pure $ DetailedSyscallExit_mlockall $
                  SyscallExitDetails_mlockall{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_munlockall
              enterDetail@SyscallEnterDetails_munlockall{} -> do
                pure $ DetailedSyscallExit_munlockall $
                  SyscallExitDetails_munlockall{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_brk
              enterDetail@SyscallEnterDetails_brk{} -> do
                pure $ DetailedSyscallExit_brk $
                  SyscallExitDetails_brk{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_munmap
              enterDetail@SyscallEnterDetails_munmap{} -> do
                pure $ DetailedSyscallExit_munmap $
                  SyscallExitDetails_munmap{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_remap_file_pages
              enterDetail@SyscallEnterDetails_remap_file_pages{} -> do
                pure $ DetailedSyscallExit_remap_file_pages $
                  SyscallExitDetails_remap_file_pages{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mprotect
              enterDetail@SyscallEnterDetails_mprotect{} -> do
                pure $ DetailedSyscallExit_mprotect $
                  SyscallExitDetails_mprotect{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pkey_mprotect
              enterDetail@SyscallEnterDetails_pkey_mprotect{} -> do
                pure $ DetailedSyscallExit_pkey_mprotect $
                  SyscallExitDetails_pkey_mprotect{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pkey_alloc
              enterDetail@SyscallEnterDetails_pkey_alloc{} -> do
                pure $ DetailedSyscallExit_pkey_alloc $
                  SyscallExitDetails_pkey_alloc{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pkey_free
              enterDetail@SyscallEnterDetails_pkey_free{} -> do
                pure $ DetailedSyscallExit_pkey_free $
                  SyscallExitDetails_pkey_free{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mremap
              enterDetail@SyscallEnterDetails_mremap{} -> do
                pure $ DetailedSyscallExit_mremap $
                  SyscallExitDetails_mremap{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_msync
              enterDetail@SyscallEnterDetails_msync{} -> do
                pure $ DetailedSyscallExit_msync $
                  SyscallExitDetails_msync{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_process_vm_readv
              enterDetail@SyscallEnterDetails_process_vm_readv{} -> do
                pure $ DetailedSyscallExit_process_vm_readv $
                  SyscallExitDetails_process_vm_readv{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_process_vm_writev
              enterDetail@SyscallEnterDetails_process_vm_writev{} -> do
                pure $ DetailedSyscallExit_process_vm_writev $
                  SyscallExitDetails_process_vm_writev{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_readahead
              enterDetail@SyscallEnterDetails_readahead{} -> do
                pure $ DetailedSyscallExit_readahead $
                  SyscallExitDetails_readahead{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_swapoff
              enterDetail@SyscallEnterDetails_swapoff{} -> do
                pure $ DetailedSyscallExit_swapoff $
                  SyscallExitDetails_swapoff{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_swapon
              enterDetail@SyscallEnterDetails_swapon{} -> do
                pure $ DetailedSyscallExit_swapon $
                  SyscallExitDetails_swapon{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_socket
              enterDetail@SyscallEnterDetails_socket{} -> do
                pure $ DetailedSyscallExit_socket $
                  SyscallExitDetails_socket{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_socketpair
              enterDetail@SyscallEnterDetails_socketpair{} -> do
                pure $ DetailedSyscallExit_socketpair $
                  SyscallExitDetails_socketpair{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_bind
              enterDetail@SyscallEnterDetails_bind{} -> do
                pure $ DetailedSyscallExit_bind $
                  SyscallExitDetails_bind{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_listen
              enterDetail@SyscallEnterDetails_listen{} -> do
                pure $ DetailedSyscallExit_listen $
                  SyscallExitDetails_listen{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_accept4
              enterDetail@SyscallEnterDetails_accept4{} -> do
                pure $ DetailedSyscallExit_accept4 $
                  SyscallExitDetails_accept4{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_accept
              enterDetail@SyscallEnterDetails_accept{} -> do
                pure $ DetailedSyscallExit_accept $
                  SyscallExitDetails_accept{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_connect
              enterDetail@SyscallEnterDetails_connect{} -> do
                pure $ DetailedSyscallExit_connect $
                  SyscallExitDetails_connect{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getsockname
              enterDetail@SyscallEnterDetails_getsockname{} -> do
                pure $ DetailedSyscallExit_getsockname $
                  SyscallExitDetails_getsockname{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getpeername
              enterDetail@SyscallEnterDetails_getpeername{} -> do
                pure $ DetailedSyscallExit_getpeername $
                  SyscallExitDetails_getpeername{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sendto
              enterDetail@SyscallEnterDetails_sendto{} -> do
                pure $ DetailedSyscallExit_sendto $
                  SyscallExitDetails_sendto{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_send
              enterDetail@SyscallEnterDetails_send{} -> do
                pure $ DetailedSyscallExit_send $
                  SyscallExitDetails_send{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_recvfrom
              enterDetail@SyscallEnterDetails_recvfrom{} -> do
                pure $ DetailedSyscallExit_recvfrom $
                  SyscallExitDetails_recvfrom{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_recv
              enterDetail@SyscallEnterDetails_recv{} -> do
                pure $ DetailedSyscallExit_recv $
                  SyscallExitDetails_recv{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_setsockopt
              enterDetail@SyscallEnterDetails_setsockopt{} -> do
                pure $ DetailedSyscallExit_setsockopt $
                  SyscallExitDetails_setsockopt{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_getsockopt
              enterDetail@SyscallEnterDetails_getsockopt{} -> do
                pure $ DetailedSyscallExit_getsockopt $
                  SyscallExitDetails_getsockopt{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_shutdown
              enterDetail@SyscallEnterDetails_shutdown{} -> do
                pure $ DetailedSyscallExit_shutdown $
                  SyscallExitDetails_shutdown{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sendmsg
              enterDetail@SyscallEnterDetails_sendmsg{} -> do
                pure $ DetailedSyscallExit_sendmsg $
                  SyscallExitDetails_sendmsg{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sendmmsg
              enterDetail@SyscallEnterDetails_sendmmsg{} -> do
                pure $ DetailedSyscallExit_sendmmsg $
                  SyscallExitDetails_sendmmsg{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_recvmsg
              enterDetail@SyscallEnterDetails_recvmsg{} -> do
                pure $ DetailedSyscallExit_recvmsg $
                  SyscallExitDetails_recvmsg{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_recvmmsg
              enterDetail@SyscallEnterDetails_recvmmsg{} -> do
                pure $ DetailedSyscallExit_recvmmsg $
                  SyscallExitDetails_recvmmsg{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_socketcall
              enterDetail@SyscallEnterDetails_socketcall{} -> do
                pure $ DetailedSyscallExit_socketcall $
                  SyscallExitDetails_socketcall{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_add_key
              enterDetail@SyscallEnterDetails_add_key{} -> do
                pure $ DetailedSyscallExit_add_key $
                  SyscallExitDetails_add_key{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_request_key
              enterDetail@SyscallEnterDetails_request_key{} -> do
                pure $ DetailedSyscallExit_request_key $
                  SyscallExitDetails_request_key{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_keyctl
              enterDetail@SyscallEnterDetails_keyctl{} -> do
                pure $ DetailedSyscallExit_keyctl $
                  SyscallExitDetails_keyctl{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_select
              enterDetail@SyscallEnterDetails_select{} -> do
                pure $ DetailedSyscallExit_select $
                  SyscallExitDetails_select{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_pselect6
              enterDetail@SyscallEnterDetails_pselect6{} -> do
                pure $ DetailedSyscallExit_pselect6 $
                  SyscallExitDetails_pselect6{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mq_open
              enterDetail@SyscallEnterDetails_mq_open{} -> do
                pure $ DetailedSyscallExit_mq_open $
                  SyscallExitDetails_mq_open{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mq_unlink
              enterDetail@SyscallEnterDetails_mq_unlink{} -> do
                pure $ DetailedSyscallExit_mq_unlink $
                  SyscallExitDetails_mq_unlink{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_bpf
              enterDetail@SyscallEnterDetails_bpf{} -> do
                pure $ DetailedSyscallExit_bpf $
                  SyscallExitDetails_bpf{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_capget
              enterDetail@SyscallEnterDetails_capget{} -> do
                pure $ DetailedSyscallExit_capget $
                  SyscallExitDetails_capget{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_capset
              enterDetail@SyscallEnterDetails_capset{} -> do
                pure $ DetailedSyscallExit_capset $
                  SyscallExitDetails_capset{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigtimedwait
              enterDetail@SyscallEnterDetails_rt_sigtimedwait{} -> do
                pure $ DetailedSyscallExit_rt_sigtimedwait $
                  SyscallExitDetails_rt_sigtimedwait{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_sigqueueinfo
              enterDetail@SyscallEnterDetails_rt_sigqueueinfo{} -> do
                pure $ DetailedSyscallExit_rt_sigqueueinfo $
                  SyscallExitDetails_rt_sigqueueinfo{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_rt_tgsigqueueinfo
              enterDetail@SyscallEnterDetails_rt_tgsigqueueinfo{} -> do
                pure $ DetailedSyscallExit_rt_tgsigqueueinfo $
                  SyscallExitDetails_rt_tgsigqueueinfo{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_sigaltstack
              enterDetail@SyscallEnterDetails_sigaltstack{} -> do
                pure $ DetailedSyscallExit_sigaltstack $
                  SyscallExitDetails_sigaltstack{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mq_timedsend
              enterDetail@SyscallEnterDetails_mq_timedsend{} -> do
                pure $ DetailedSyscallExit_mq_timedsend $
                  SyscallExitDetails_mq_timedsend{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mq_timedreceive
              enterDetail@SyscallEnterDetails_mq_timedreceive{} -> do
                pure $ DetailedSyscallExit_mq_timedreceive $
                  SyscallExitDetails_mq_timedreceive{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mq_notify
              enterDetail@SyscallEnterDetails_mq_notify{} -> do
                pure $ DetailedSyscallExit_mq_notify $
                  SyscallExitDetails_mq_notify{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_mq_getsetattr
              enterDetail@SyscallEnterDetails_mq_getsetattr{} -> do
                pure $ DetailedSyscallExit_mq_getsetattr $
                  SyscallExitDetails_mq_getsetattr{ enterDetail, retval = fromIntegral result }

            DetailedSyscallEnter_unimplemented syscall _syscallArgs ->
              pure $ DetailedSyscallExit_unimplemented syscall syscallArgs result

readPipeFds :: CPid -> Ptr CInt -> IO (CInt, CInt)
readPipeFds pid pipefd = do
  let fdSize = sizeOf (undefined :: CInt)
      sz = 2 * fdSize
  bytes <- peekBytes (TracedProcess pid) pipefd sz
  let (ptr, off, _size) = BSI.toForeignPtr bytes
  withForeignPtr ptr $ \p -> do
    (,) <$> peekByteOff p off <*> peekByteOff p (off + fdSize)

syscallEnterDetailsOnlyConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, DetailedSyscallEnter) m ()
syscallEnterDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop (SyscallEnter (KnownSyscall syscall, syscallArgs)) -> do
    detailedSyscallEnter <- liftIO $ getSyscallEnterDetails syscall syscallArgs pid
    yield (pid, detailedSyscallEnter)
  _ -> return () -- skip


syscallExitDetailsOnlyConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, (Either (Syscall, ERRNO) DetailedSyscallExit)) m ()
syscallExitDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop (SyscallExit (syscall@(KnownSyscall knownSyscall), syscallArgs)) -> do
    eDetailed <- liftIO $ getSyscallExitDetails knownSyscall syscallArgs pid
    yield (pid, mapLeft (syscall, ) eDetailed)
  _ -> return () -- skip


formatDetailedSyscallEnter :: DetailedSyscallEnter -> String
formatDetailedSyscallEnter = \case

  DetailedSyscallEnter_open
    SyscallEnterDetails_open{ pathnameBS, flags, mode } ->
      "open(" ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_openat
    SyscallEnterDetails_openat{ dirfd, pathnameBS, flags, mode } ->
      "openat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_creat
    SyscallEnterDetails_creat{ pathnameBS, mode } ->
      "creat(" ++ show pathnameBS ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_pipe
    SyscallEnterDetails_pipe{ } ->
      "pipe([])"

  DetailedSyscallEnter_pipe2
    SyscallEnterDetails_pipe2{ flags } ->
      "pipe([], " ++ show flags ++ ")"

  DetailedSyscallEnter_access
    SyscallEnterDetails_access{ pathnameBS, accessMode } ->
      "access(" ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ")"

  DetailedSyscallEnter_faccessat
    SyscallEnterDetails_faccessat{ dirfd, pathnameBS, accessMode, flags } ->
      "faccessat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ", " ++ show flags ++")"

  DetailedSyscallEnter_write
    SyscallEnterDetails_write{ fd, bufContents, count } ->
      "write(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_read
    SyscallEnterDetails_read{ fd, count } ->
      "read(" ++ show fd ++ ", void *buf, " ++ show count ++ ")"

  DetailedSyscallEnter_close
    SyscallEnterDetails_close{ fd } ->
      "close(" ++ show fd ++ ")"

  DetailedSyscallEnter_rename
    SyscallEnterDetails_rename{ oldpathBS, newpathBS } ->
      "rename(" ++ show oldpathBS ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallEnter_renameat
    SyscallEnterDetails_renameat{ olddirfd, oldpathBS, newdirfd, newpathBS } ->
      "renameat(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallEnter_renameat2
    SyscallEnterDetails_renameat2{ olddirfd, oldpathBS, newdirfd, newpathBS, flags } ->
      "renameat2(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                 ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_stat
    SyscallEnterDetails_stat{ pathnameBS } ->
      "stat(" ++ show pathnameBS ++ ", struct stat *statbuf)"

  DetailedSyscallEnter_fstat
    SyscallEnterDetails_fstat{ fd } ->
      "fstat(" ++ show fd ++ ", struct stat *statbuf)"

  DetailedSyscallEnter_lstat
    SyscallEnterDetails_lstat{ pathnameBS } ->
      "lstat(" ++ show pathnameBS ++ ", struct stat *statbuf)"

  DetailedSyscallEnter_newfstatat
    SyscallEnterDetails_newfstatat{ dirfd, pathnameBS, flags } ->
      "newfstatat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", struct stat *statbuf, " ++ show flags ++ ")"

  DetailedSyscallEnter_execve
    SyscallEnterDetails_execve{ filenameBS, argvList, envpList } ->
      "execve(" ++ show filenameBS ++ ", " ++ show argvList ++ ", " ++ show envpList ++ ")"

  DetailedSyscallEnter_exit
    SyscallEnterDetails_exit{ status } ->
      "exit(" ++ show status ++ ")"

  DetailedSyscallEnter_exit_group
    SyscallEnterDetails_exit_group{ status } ->
      "exit_group(" ++ show status ++ ")"

  DetailedSyscallEnter_ioperm
    SyscallEnterDetails_ioperm{ from, num, turn_on } ->
      "ioperm(" ++ show from ++ ", " ++ show num ++ ", " ++ show turn_on ++ ")"

  DetailedSyscallEnter_iopl
    SyscallEnterDetails_iopl{ level } ->
      "iopl(" ++ show level ++ ")"

  DetailedSyscallEnter_modify_ldt
    SyscallEnterDetails_modify_ldt{ func, ptr, bytecount } ->
      "modify_ldt(" ++ show func ++ ", " ++ show ptr ++ ", " ++ show bytecount ++ ")"

  DetailedSyscallEnter_arch_prctl
    SyscallEnterDetails_arch_prctl{ option, arg2 } ->
      "arch_prctl(" ++ show option ++ ", " ++ show arg2 ++ ")"

  DetailedSyscallEnter_sigreturn
    SyscallEnterDetails_sigreturn{  } ->
      "sigreturn()"

  DetailedSyscallEnter_rt_sigreturn
    SyscallEnterDetails_rt_sigreturn{  } ->
      "rt_sigreturn()"

  DetailedSyscallEnter_mmap
    SyscallEnterDetails_mmap{ addr, len, prot, flags, fd, off } ->
      "mmap(" ++ show addr ++ ", " ++ show len ++ ", " ++ show prot ++ ", " ++ show flags ++ ", " ++ show fd ++ ", " ++ show off ++ ")"

  DetailedSyscallEnter_set_thread_area
    SyscallEnterDetails_set_thread_area{ u_info } ->
      "set_thread_area(" ++ show u_info ++ ")"

  DetailedSyscallEnter_get_thread_area
    SyscallEnterDetails_get_thread_area{ u_info } ->
      "get_thread_area(" ++ show u_info ++ ")"

  DetailedSyscallEnter_vm86old
    SyscallEnterDetails_vm86old{ user_vm86 } ->
      "vm86old(" ++ show user_vm86 ++ ")"

  DetailedSyscallEnter_vm86
    SyscallEnterDetails_vm86{ cmd, arg } ->
      "vm86(" ++ show cmd ++ ", " ++ show arg ++ ")"

  DetailedSyscallEnter_ioprio_set
    SyscallEnterDetails_ioprio_set{ which, who, ioprio } ->
      "ioprio_set(" ++ show which ++ ", " ++ show who ++ ", " ++ show ioprio ++ ")"

  DetailedSyscallEnter_ioprio_get
    SyscallEnterDetails_ioprio_get{ which, who } ->
      "ioprio_get(" ++ show which ++ ", " ++ show who ++ ")"

  DetailedSyscallEnter_getrandom
    SyscallEnterDetails_getrandom{ bufBS, count, flags } ->
      "getrandom(" ++ show bufBS ++ ", " ++ show count ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_pciconfig_read
    SyscallEnterDetails_pciconfig_read{ bus, dfn, off, len, buf } ->
      "pciconfig_read(" ++ show bus ++ ", " ++ show dfn ++ ", " ++ show off ++ ", " ++ show len ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_pciconfig_write
    SyscallEnterDetails_pciconfig_write{ bus, dfn, off, len, buf } ->
      "pciconfig_write(" ++ show bus ++ ", " ++ show dfn ++ ", " ++ show off ++ ", " ++ show len ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_io_setup
    SyscallEnterDetails_io_setup{ nr_events, ctxp } ->
      "io_setup(" ++ show nr_events ++ ", " ++ show ctxp ++ ")"

  DetailedSyscallEnter_io_destroy
    SyscallEnterDetails_io_destroy{ ctx } ->
      "io_destroy(" ++ show ctx ++ ")"

  DetailedSyscallEnter_io_submit
    SyscallEnterDetails_io_submit{ ctx_id, nr, iocbpp } ->
      "io_submit(" ++ show ctx_id ++ ", " ++ show nr ++ ", " ++ show iocbpp ++ ")"

  DetailedSyscallEnter_io_cancel
    SyscallEnterDetails_io_cancel{ ctx_id, iocb, result } ->
      "io_cancel(" ++ show ctx_id ++ ", " ++ show iocb ++ ", " ++ show result ++ ")"

  DetailedSyscallEnter_io_getevents
    SyscallEnterDetails_io_getevents{ ctx_id, min_nr, nr, events, timeout } ->
      "io_getevents(" ++ show ctx_id ++ ", " ++ show min_nr ++ ", " ++ show nr ++ ", " ++ show events ++ ", " ++ show timeout ++ ")"

  DetailedSyscallEnter_io_pgetevents
    SyscallEnterDetails_io_pgetevents{ ctx_id, min_nr, nr, events, timeout, usig } ->
      "io_pgetevents(" ++ show ctx_id ++ ", " ++ show min_nr ++ ", " ++ show nr ++ ", " ++ show events ++ ", " ++ show timeout ++ ", " ++ show usig ++ ")"

  DetailedSyscallEnter_bdflush
    SyscallEnterDetails_bdflush{ func, data_ } ->
      "bdflush(" ++ show func ++ ", " ++ show data_ ++ ")"

  DetailedSyscallEnter_getcwd
    SyscallEnterDetails_getcwd{ bufBS, size } ->
      "getcwd(" ++ show bufBS ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_lookup_dcookie
    SyscallEnterDetails_lookup_dcookie{ cookie64, bufBS, len } ->
      "lookup_dcookie(" ++ show cookie64 ++ ", " ++ show bufBS ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_eventfd2
    SyscallEnterDetails_eventfd2{ count, flags } ->
      "eventfd2(" ++ show count ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_eventfd
    SyscallEnterDetails_eventfd{ count } ->
      "eventfd(" ++ show count ++ ")"

  DetailedSyscallEnter_epoll_create1
    SyscallEnterDetails_epoll_create1{ flags } ->
      "epoll_create1(" ++ show flags ++ ")"

  DetailedSyscallEnter_epoll_create
    SyscallEnterDetails_epoll_create{ size } ->
      "epoll_create(" ++ show size ++ ")"

  DetailedSyscallEnter_epoll_ctl
    SyscallEnterDetails_epoll_ctl{ epfd, op, fd, event } ->
      "epoll_ctl(" ++ show epfd ++ ", " ++ show op ++ ", " ++ show fd ++ ", " ++ show event ++ ")"

  DetailedSyscallEnter_epoll_wait
    SyscallEnterDetails_epoll_wait{ epfd, events, maxevents, timeout } ->
      "epoll_wait(" ++ show epfd ++ ", " ++ show events ++ ", " ++ show maxevents ++ ", " ++ show timeout ++ ")"

  DetailedSyscallEnter_epoll_pwait
    SyscallEnterDetails_epoll_pwait{ epfd, events, maxevents, timeout, sigmask, sigsetsize } ->
      "epoll_pwait(" ++ show epfd ++ ", " ++ show events ++ ", " ++ show maxevents ++ ", " ++ show timeout ++ ", " ++ show sigmask ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_uselib
    SyscallEnterDetails_uselib{ libraryBS } ->
      "uselib(" ++ show libraryBS ++ ")"

  DetailedSyscallEnter_execveat
    SyscallEnterDetails_execveat{ fd, filenameBS, argv, envp, flags } ->
      "execveat(" ++ show fd ++ ", " ++ show filenameBS ++ ", " ++ show argv ++ ", " ++ show envp ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_fcntl
    SyscallEnterDetails_fcntl{ fd, cmd, arg } ->
      "fcntl(" ++ show fd ++ ", " ++ show cmd ++ ", " ++ show arg ++ ")"

  DetailedSyscallEnter_fcntl64
    SyscallEnterDetails_fcntl64{ fd, cmd, arg } ->
      "fcntl64(" ++ show fd ++ ", " ++ show cmd ++ ", " ++ show arg ++ ")"

  DetailedSyscallEnter_name_to_handle_at
    SyscallEnterDetails_name_to_handle_at{ dfd, nameBS, handle, mnt_id, flag } ->
      "name_to_handle_at(" ++ show dfd ++ ", " ++ show nameBS ++ ", " ++ show handle ++ ", " ++ show mnt_id ++ ", " ++ show flag ++ ")"

  DetailedSyscallEnter_open_by_handle_at
    SyscallEnterDetails_open_by_handle_at{ mountdirfd, handle, flags } ->
      "open_by_handle_at(" ++ show mountdirfd ++ ", " ++ show handle ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_dup3
    SyscallEnterDetails_dup3{ oldfd, newfd, flags } ->
      "dup3(" ++ show oldfd ++ ", " ++ show newfd ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_dup2
    SyscallEnterDetails_dup2{ oldfd, newfd } ->
      "dup2(" ++ show oldfd ++ ", " ++ show newfd ++ ")"

  DetailedSyscallEnter_dup
    SyscallEnterDetails_dup{ fildes } ->
      "dup(" ++ show fildes ++ ")"

  DetailedSyscallEnter_sysfs
    SyscallEnterDetails_sysfs{ option, arg1, arg2 } ->
      "sysfs(" ++ show option ++ ", " ++ show arg1 ++ ", " ++ show arg2 ++ ")"

  DetailedSyscallEnter_ioctl
    SyscallEnterDetails_ioctl{ fd, cmd, arg } ->
      "ioctl(" ++ show fd ++ ", " ++ show cmd ++ ", " ++ show arg ++ ")"

  DetailedSyscallEnter_flock
    SyscallEnterDetails_flock{ fd, cmd } ->
      "flock(" ++ show fd ++ ", " ++ show cmd ++ ")"

  DetailedSyscallEnter_mknodat
    SyscallEnterDetails_mknodat{ dfd, filenameBS, mode, dev } ->
      "mknodat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show mode ++ ", " ++ show dev ++ ")"

  DetailedSyscallEnter_mknod
    SyscallEnterDetails_mknod{ filenameBS, mode, dev } ->
      "mknod(" ++ show filenameBS ++ ", " ++ show mode ++ ", " ++ show dev ++ ")"

  DetailedSyscallEnter_mkdirat
    SyscallEnterDetails_mkdirat{ dfd, pathnameBS, mode } ->
      "mkdirat(" ++ show dfd ++ ", " ++ show pathnameBS ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_mkdir
    SyscallEnterDetails_mkdir{ pathnameBS, mode } ->
      "mkdir(" ++ show pathnameBS ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_rmdir
    SyscallEnterDetails_rmdir{ pathnameBS } ->
      "rmdir(" ++ show pathnameBS ++ ")"

  DetailedSyscallEnter_unlinkat
    SyscallEnterDetails_unlinkat{ dfd, pathnameBS, flag } ->
      "unlinkat(" ++ show dfd ++ ", " ++ show pathnameBS ++ ", " ++ show flag ++ ")"

  DetailedSyscallEnter_unlink
    SyscallEnterDetails_unlink{ pathnameBS } ->
      "unlink(" ++ show pathnameBS ++ ")"

  DetailedSyscallEnter_symlinkat
    SyscallEnterDetails_symlinkat{ oldnameBS, newdfd, newnameBS } ->
      "symlinkat(" ++ show oldnameBS ++ ", " ++ show newdfd ++ ", " ++ show newnameBS ++ ")"

  DetailedSyscallEnter_symlink
    SyscallEnterDetails_symlink{ oldnameBS, newnameBS } ->
      "symlink(" ++ show oldnameBS ++ ", " ++ show newnameBS ++ ")"

  DetailedSyscallEnter_linkat
    SyscallEnterDetails_linkat{ olddfd, oldnameBS, newdfd, newnameBS, flags } ->
      "linkat(" ++ show olddfd ++ ", " ++ show oldnameBS ++ ", " ++ show newdfd ++ ", " ++ show newnameBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_link
    SyscallEnterDetails_link{ oldnameBS, newnameBS } ->
      "link(" ++ show oldnameBS ++ ", " ++ show newnameBS ++ ")"

  DetailedSyscallEnter_umount
    SyscallEnterDetails_umount{ nameBS, flags } ->
      "umount(" ++ show nameBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_oldumount
    SyscallEnterDetails_oldumount{ nameBS } ->
      "oldumount(" ++ show nameBS ++ ")"

  DetailedSyscallEnter_mount
    SyscallEnterDetails_mount{ dev_nameBS, dir_nameBS, type_BS, flags, data_ } ->
      "mount(" ++ show dev_nameBS ++ ", " ++ show dir_nameBS ++ ", " ++ show type_BS ++ ", " ++ show flags ++ ", " ++ show data_ ++ ")"

  DetailedSyscallEnter_pivot_root
    SyscallEnterDetails_pivot_root{ new_rootBS, put_oldBS } ->
      "pivot_root(" ++ show new_rootBS ++ ", " ++ show put_oldBS ++ ")"

  DetailedSyscallEnter_fanotify_init
    SyscallEnterDetails_fanotify_init{ flags, event_f_flags } ->
      "fanotify_init(" ++ show flags ++ ", " ++ show event_f_flags ++ ")"

  DetailedSyscallEnter_fanotify_mark
    SyscallEnterDetails_fanotify_mark{ fanotify_fd, flags, mask, dfd, pathnameBS } ->
      "fanotify_mark(" ++ show fanotify_fd ++ ", " ++ show flags ++ ", " ++ show mask ++ ", " ++ show dfd ++ ", " ++ show pathnameBS ++ ")"

  DetailedSyscallEnter_inotify_init1
    SyscallEnterDetails_inotify_init1{ flags } ->
      "inotify_init1(" ++ show flags ++ ")"

  DetailedSyscallEnter_inotify_init
    SyscallEnterDetails_inotify_init{  } ->
      "inotify_init()"

  DetailedSyscallEnter_inotify_add_watch
    SyscallEnterDetails_inotify_add_watch{ fd, pathnameBS, mask } ->
      "inotify_add_watch(" ++ show fd ++ ", " ++ show pathnameBS ++ ", " ++ show mask ++ ")"

  DetailedSyscallEnter_inotify_rm_watch
    SyscallEnterDetails_inotify_rm_watch{ fd, wd } ->
      "inotify_rm_watch(" ++ show fd ++ ", " ++ show wd ++ ")"

  DetailedSyscallEnter_truncate
    SyscallEnterDetails_truncate{ pathBS, length_ } ->
      "truncate(" ++ show pathBS ++ ", " ++ show length_ ++ ")"

  DetailedSyscallEnter_ftruncate
    SyscallEnterDetails_ftruncate{ fd, length_ } ->
      "ftruncate(" ++ show fd ++ ", " ++ show length_ ++ ")"

  DetailedSyscallEnter_truncate64
    SyscallEnterDetails_truncate64{ pathBS, length_ } ->
      "truncate64(" ++ show pathBS ++ ", " ++ show length_ ++ ")"

  DetailedSyscallEnter_ftruncate64
    SyscallEnterDetails_ftruncate64{ fd, length_ } ->
      "ftruncate64(" ++ show fd ++ ", " ++ show length_ ++ ")"

  DetailedSyscallEnter_fallocate
    SyscallEnterDetails_fallocate{ fd, mode, offset, len } ->
      "fallocate(" ++ show fd ++ ", " ++ show mode ++ ", " ++ show offset ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_chdir
    SyscallEnterDetails_chdir{ filenameBS } ->
      "chdir(" ++ show filenameBS ++ ")"

  DetailedSyscallEnter_fchdir
    SyscallEnterDetails_fchdir{ fd } ->
      "fchdir(" ++ show fd ++ ")"

  DetailedSyscallEnter_chroot
    SyscallEnterDetails_chroot{ filenameBS } ->
      "chroot(" ++ show filenameBS ++ ")"

  DetailedSyscallEnter_fchmod
    SyscallEnterDetails_fchmod{ fd, mode } ->
      "fchmod(" ++ show fd ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_fchmodat
    SyscallEnterDetails_fchmodat{ dfd, filenameBS, mode } ->
      "fchmodat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_chmod
    SyscallEnterDetails_chmod{ filenameBS, mode } ->
      "chmod(" ++ show filenameBS ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_fchownat
    SyscallEnterDetails_fchownat{ dfd, filenameBS, user, group, flag } ->
      "fchownat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show user ++ ", " ++ show group ++ ", " ++ show flag ++ ")"

  DetailedSyscallEnter_chown
    SyscallEnterDetails_chown{ filenameBS, user, group } ->
      "chown(" ++ show filenameBS ++ ", " ++ show user ++ ", " ++ show group ++ ")"

  DetailedSyscallEnter_lchown
    SyscallEnterDetails_lchown{ filenameBS, user, group } ->
      "lchown(" ++ show filenameBS ++ ", " ++ show user ++ ", " ++ show group ++ ")"

  DetailedSyscallEnter_fchown
    SyscallEnterDetails_fchown{ fd, user, group } ->
      "fchown(" ++ show fd ++ ", " ++ show user ++ ", " ++ show group ++ ")"

  DetailedSyscallEnter_vhangup
    SyscallEnterDetails_vhangup{  } ->
      "vhangup()"

  DetailedSyscallEnter_quotactl
    SyscallEnterDetails_quotactl{ cmd, specialBS, id_, addr } ->
      "quotactl(" ++ show cmd ++ ", " ++ show specialBS ++ ", " ++ show id_ ++ ", " ++ show addr ++ ")"

  DetailedSyscallEnter_lseek
    SyscallEnterDetails_lseek{ fd, offset, whence } ->
      "lseek(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show whence ++ ")"

  DetailedSyscallEnter_pread64
    SyscallEnterDetails_pread64{ fd, bufBS, count, pos } ->
      "pread64(" ++ show fd ++ ", " ++ show bufBS ++ ", " ++ show count ++ ", " ++ show pos ++ ")"

  DetailedSyscallEnter_pwrite64
    SyscallEnterDetails_pwrite64{ fd, bufBS, count, pos } ->
      "pwrite64(" ++ show fd ++ ", " ++ show bufBS ++ ", " ++ show count ++ ", " ++ show pos ++ ")"

  DetailedSyscallEnter_readv
    SyscallEnterDetails_readv{ fd, vec, vlen } ->
      "readv(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ")"

  DetailedSyscallEnter_writev
    SyscallEnterDetails_writev{ fd, vec, vlen } ->
      "writev(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ")"

  DetailedSyscallEnter_preadv
    SyscallEnterDetails_preadv{ fd, vec, vlen, pos_l, pos_h } ->
      "preadv(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ")"

  DetailedSyscallEnter_preadv2
    SyscallEnterDetails_preadv2{ fd, vec, vlen, pos_l, pos_h, flags } ->
      "preadv2(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_pwritev
    SyscallEnterDetails_pwritev{ fd, vec, vlen, pos_l, pos_h } ->
      "pwritev(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ")"

  DetailedSyscallEnter_pwritev2
    SyscallEnterDetails_pwritev2{ fd, vec, vlen, pos_l, pos_h, flags } ->
      "pwritev2(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_sendfile
    SyscallEnterDetails_sendfile{ out_fd, in_fd, offset, count } ->
      "sendfile(" ++ show out_fd ++ ", " ++ show in_fd ++ ", " ++ show offset ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_sendfile64
    SyscallEnterDetails_sendfile64{ out_fd, in_fd, offset, count } ->
      "sendfile64(" ++ show out_fd ++ ", " ++ show in_fd ++ ", " ++ show offset ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_copy_file_range
    SyscallEnterDetails_copy_file_range{ fd_in, off_in, fd_out, off_out, len, flags } ->
      "copy_file_range(" ++ show fd_in ++ ", " ++ show off_in ++ ", " ++ show fd_out ++ ", " ++ show off_out ++ ", " ++ show len ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_getdents
    SyscallEnterDetails_getdents{ fd, dirent, count } ->
      "getdents(" ++ show fd ++ ", " ++ show dirent ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_getdents64
    SyscallEnterDetails_getdents64{ fd, dirent, count } ->
      "getdents64(" ++ show fd ++ ", " ++ show dirent ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_poll
    SyscallEnterDetails_poll{ ufds, nfds, timeout_msecs } ->
      "poll(" ++ show ufds ++ ", " ++ show nfds ++ ", " ++ show timeout_msecs ++ ")"

  DetailedSyscallEnter_ppoll
    SyscallEnterDetails_ppoll{ ufds, nfds, tsp, sigmask, sigsetsize } ->
      "ppoll(" ++ show ufds ++ ", " ++ show nfds ++ ", " ++ show tsp ++ ", " ++ show sigmask ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_signalfd4
    SyscallEnterDetails_signalfd4{ ufd, user_mask, sizemask, flags } ->
      "signalfd4(" ++ show ufd ++ ", " ++ show user_mask ++ ", " ++ show sizemask ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_signalfd
    SyscallEnterDetails_signalfd{ ufd, user_mask, sizemask } ->
      "signalfd(" ++ show ufd ++ ", " ++ show user_mask ++ ", " ++ show sizemask ++ ")"

  DetailedSyscallEnter_vmsplice
    SyscallEnterDetails_vmsplice{ fd, uiov, nr_segs, flags } ->
      "vmsplice(" ++ show fd ++ ", " ++ show uiov ++ ", " ++ show nr_segs ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_splice
    SyscallEnterDetails_splice{ fd_in, off_in, fd_out, off_out, len, flags } ->
      "splice(" ++ show fd_in ++ ", " ++ show off_in ++ ", " ++ show fd_out ++ ", " ++ show off_out ++ ", " ++ show len ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_tee
    SyscallEnterDetails_tee{ fdin, fdout, len, flags } ->
      "tee(" ++ show fdin ++ ", " ++ show fdout ++ ", " ++ show len ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_readlinkat
    SyscallEnterDetails_readlinkat{ dfd, pathnameBS, bufBS, bufsiz } ->
      "readlinkat(" ++ show dfd ++ ", " ++ show pathnameBS ++ ", " ++ show bufBS ++ ", " ++ show bufsiz ++ ")"

  DetailedSyscallEnter_readlink
    SyscallEnterDetails_readlink{ pathBS, bufBS, bufsiz } ->
      "readlink(" ++ show pathBS ++ ", " ++ show bufBS ++ ", " ++ show bufsiz ++ ")"

  DetailedSyscallEnter_stat64
    SyscallEnterDetails_stat64{ filenameBS, statbuf } ->
      "stat64(" ++ show filenameBS ++ ", " ++ show statbuf ++ ")"

  DetailedSyscallEnter_lstat64
    SyscallEnterDetails_lstat64{ filenameBS, statbuf } ->
      "lstat64(" ++ show filenameBS ++ ", " ++ show statbuf ++ ")"

  DetailedSyscallEnter_fstat64
    SyscallEnterDetails_fstat64{ fd, statbuf } ->
      "fstat64(" ++ show fd ++ ", " ++ show statbuf ++ ")"

  DetailedSyscallEnter_fstatat64
    SyscallEnterDetails_fstatat64{ dfd, filenameBS, statbuf, flag } ->
      "fstatat64(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show statbuf ++ ", " ++ show flag ++ ")"

  DetailedSyscallEnter_statx
    SyscallEnterDetails_statx{ dfd, filenameBS, flags, mask, buffer } ->
      "statx(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show flags ++ ", " ++ show mask ++ ", " ++ show buffer ++ ")"

  DetailedSyscallEnter_statfs
    SyscallEnterDetails_statfs{ pathnameBS, buf } ->
      "statfs(" ++ show pathnameBS ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_statfs64
    SyscallEnterDetails_statfs64{ pathnameBS, sz, buf } ->
      "statfs64(" ++ show pathnameBS ++ ", " ++ show sz ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_fstatfs
    SyscallEnterDetails_fstatfs{ fd, buf } ->
      "fstatfs(" ++ show fd ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_fstatfs64
    SyscallEnterDetails_fstatfs64{ fd, sz, buf } ->
      "fstatfs64(" ++ show fd ++ ", " ++ show sz ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_ustat
    SyscallEnterDetails_ustat{ dev, ubuf } ->
      "ustat(" ++ show dev ++ ", " ++ show ubuf ++ ")"

  DetailedSyscallEnter_sync
    SyscallEnterDetails_sync{  } ->
      "sync()"

  DetailedSyscallEnter_syncfs
    SyscallEnterDetails_syncfs{ fd } ->
      "syncfs(" ++ show fd ++ ")"

  DetailedSyscallEnter_fsync
    SyscallEnterDetails_fsync{ fd } ->
      "fsync(" ++ show fd ++ ")"

  DetailedSyscallEnter_fdatasync
    SyscallEnterDetails_fdatasync{ fd } ->
      "fdatasync(" ++ show fd ++ ")"

  DetailedSyscallEnter_sync_file_range
    SyscallEnterDetails_sync_file_range{ fd, offset, nbytes, flags } ->
      "sync_file_range(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show nbytes ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_sync_file_range2
    SyscallEnterDetails_sync_file_range2{ fd, flags, offset, nbytes } ->
      "sync_file_range2(" ++ show fd ++ ", " ++ show flags ++ ", " ++ show offset ++ ", " ++ show nbytes ++ ")"

  DetailedSyscallEnter_timerfd_create
    SyscallEnterDetails_timerfd_create{ clockid, flags } ->
      "timerfd_create(" ++ show clockid ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_timerfd_settime
    SyscallEnterDetails_timerfd_settime{ ufd, flags, utmr, otmr } ->
      "timerfd_settime(" ++ show ufd ++ ", " ++ show flags ++ ", " ++ show utmr ++ ", " ++ show otmr ++ ")"

  DetailedSyscallEnter_timerfd_gettime
    SyscallEnterDetails_timerfd_gettime{ ufd, otmr } ->
      "timerfd_gettime(" ++ show ufd ++ ", " ++ show otmr ++ ")"

  DetailedSyscallEnter_userfaultfd
    SyscallEnterDetails_userfaultfd{ flags } ->
      "userfaultfd(" ++ show flags ++ ")"

  DetailedSyscallEnter_utimensat
    SyscallEnterDetails_utimensat{ dfd, filenameBS, utimes, flags } ->
      "utimensat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show utimes ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_futimesat
    SyscallEnterDetails_futimesat{ dfd, filenameBS, utimes } ->
      "futimesat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show utimes ++ ")"

  DetailedSyscallEnter_utimes
    SyscallEnterDetails_utimes{ filenameBS, utimes } ->
      "utimes(" ++ show filenameBS ++ ", " ++ show utimes ++ ")"

  DetailedSyscallEnter_utime
    SyscallEnterDetails_utime{ filenameBS, times } ->
      "utime(" ++ show filenameBS ++ ", " ++ show times ++ ")"

  DetailedSyscallEnter_setxattr
    SyscallEnterDetails_setxattr{ pathnameBS, nameBS, value, size, flags } ->
      "setxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_lsetxattr
    SyscallEnterDetails_lsetxattr{ pathnameBS, nameBS, value, size, flags } ->
      "lsetxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_fsetxattr
    SyscallEnterDetails_fsetxattr{ fd, nameBS, value, size, flags } ->
      "fsetxattr(" ++ show fd ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_getxattr
    SyscallEnterDetails_getxattr{ pathnameBS, nameBS, value, size } ->
      "getxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_lgetxattr
    SyscallEnterDetails_lgetxattr{ pathnameBS, nameBS, value, size } ->
      "lgetxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_fgetxattr
    SyscallEnterDetails_fgetxattr{ fd, nameBS, value, size } ->
      "fgetxattr(" ++ show fd ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_listxattr
    SyscallEnterDetails_listxattr{ pathnameBS, listBS, size } ->
      "listxattr(" ++ show pathnameBS ++ ", " ++ show listBS ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_llistxattr
    SyscallEnterDetails_llistxattr{ pathnameBS, listBS, size } ->
      "llistxattr(" ++ show pathnameBS ++ ", " ++ show listBS ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_flistxattr
    SyscallEnterDetails_flistxattr{ fd, listBS, size } ->
      "flistxattr(" ++ show fd ++ ", " ++ show listBS ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_removexattr
    SyscallEnterDetails_removexattr{ pathnameBS, nameBS } ->
      "removexattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ")"

  DetailedSyscallEnter_lremovexattr
    SyscallEnterDetails_lremovexattr{ pathnameBS, nameBS } ->
      "lremovexattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ")"

  DetailedSyscallEnter_fremovexattr
    SyscallEnterDetails_fremovexattr{ fd, nameBS } ->
      "fremovexattr(" ++ show fd ++ ", " ++ show nameBS ++ ")"

  DetailedSyscallEnter_msgget
    SyscallEnterDetails_msgget{ key, msgflg } ->
      "msgget(" ++ show key ++ ", " ++ show msgflg ++ ")"

  DetailedSyscallEnter_msgctl
    SyscallEnterDetails_msgctl{ msqid, cmd, buf } ->
      "msgctl(" ++ show msqid ++ ", " ++ show cmd ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_msgsnd
    SyscallEnterDetails_msgsnd{ msqid, msgp, msgsz, msgflg } ->
      "msgsnd(" ++ show msqid ++ ", " ++ show msgp ++ ", " ++ show msgsz ++ ", " ++ show msgflg ++ ")"

  DetailedSyscallEnter_msgrcv
    SyscallEnterDetails_msgrcv{ msqid, msgp, msgsz, msgtyp, msgflg } ->
      "msgrcv(" ++ show msqid ++ ", " ++ show msgp ++ ", " ++ show msgsz ++ ", " ++ show msgtyp ++ ", " ++ show msgflg ++ ")"

  DetailedSyscallEnter_semget
    SyscallEnterDetails_semget{ key, nsems, semflg } ->
      "semget(" ++ show key ++ ", " ++ show nsems ++ ", " ++ show semflg ++ ")"

  DetailedSyscallEnter_semctl
    SyscallEnterDetails_semctl{ semid, semnum, cmd, arg } ->
      "semctl(" ++ show semid ++ ", " ++ show semnum ++ ", " ++ show cmd ++ ", " ++ show arg ++ ")"

  DetailedSyscallEnter_semtimedop
    SyscallEnterDetails_semtimedop{ semid, tsops, nsops, timeout } ->
      "semtimedop(" ++ show semid ++ ", " ++ show tsops ++ ", " ++ show nsops ++ ", " ++ show timeout ++ ")"

  DetailedSyscallEnter_semop
    SyscallEnterDetails_semop{ semid, tsops, nsops } ->
      "semop(" ++ show semid ++ ", " ++ show tsops ++ ", " ++ show nsops ++ ")"

  DetailedSyscallEnter_shmget
    SyscallEnterDetails_shmget{ key, size, shmflg } ->
      "shmget(" ++ show key ++ ", " ++ show size ++ ", " ++ show shmflg ++ ")"

  DetailedSyscallEnter_shmctl
    SyscallEnterDetails_shmctl{ shmid, cmd, buf } ->
      "shmctl(" ++ show shmid ++ ", " ++ show cmd ++ ", " ++ show buf ++ ")"

  DetailedSyscallEnter_shmat
    SyscallEnterDetails_shmat{ shmid, shmaddrBS, shmflg } ->
      "shmat(" ++ show shmid ++ ", " ++ show shmaddrBS ++ ", " ++ show shmflg ++ ")"

  DetailedSyscallEnter_shmdt
    SyscallEnterDetails_shmdt{ shmaddrBS } ->
      "shmdt(" ++ show shmaddrBS ++ ")"

  DetailedSyscallEnter_ipc
    SyscallEnterDetails_ipc{ call, first_, second_, third, ptr, fifth } ->
      "ipc(" ++ show call ++ ", " ++ show first_ ++ ", " ++ show second_ ++ ", " ++ show third ++ ", " ++ show ptr ++ ", " ++ show fifth ++ ")"

  DetailedSyscallEnter_acct
    SyscallEnterDetails_acct{ nameBS } ->
      "acct(" ++ show nameBS ++ ")"

  DetailedSyscallEnter_perf_event_open
    SyscallEnterDetails_perf_event_open{ attr_uptr, pid_, cpu, group_fd, flags } ->
      "perf_event_open(" ++ show attr_uptr ++ ", " ++ show pid_ ++ ", " ++ show cpu ++ ", " ++ show group_fd ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_personality
    SyscallEnterDetails_personality{ personality } ->
      "personality(" ++ show personality ++ ")"

  DetailedSyscallEnter_waitid
    SyscallEnterDetails_waitid{ which, upid, infop, options, ru } ->
      "waitid(" ++ show which ++ ", " ++ show upid ++ ", " ++ show infop ++ ", " ++ show options ++ ", " ++ show ru ++ ")"

  DetailedSyscallEnter_wait4
    SyscallEnterDetails_wait4{ upid, stat_addr, options, ru } ->
      "wait4(" ++ show upid ++ ", " ++ show stat_addr ++ ", " ++ show options ++ ", " ++ show ru ++ ")"

  DetailedSyscallEnter_waitpid
    SyscallEnterDetails_waitpid{ pid_, stat_addr, options } ->
      "waitpid(" ++ show pid_ ++ ", " ++ show stat_addr ++ ", " ++ show options ++ ")"

  DetailedSyscallEnter_set_tid_address
    SyscallEnterDetails_set_tid_address{ tidptr } ->
      "set_tid_address(" ++ show tidptr ++ ")"

  DetailedSyscallEnter_fork
    SyscallEnterDetails_fork{  } ->
      "fork()"

  DetailedSyscallEnter_vfork
    SyscallEnterDetails_vfork{  } ->
      "vfork()"

  DetailedSyscallEnter_clone
    SyscallEnterDetails_clone{ clone_flags, newsp, parent_tidptr, child_tidptr, tls } ->
      "clone(" ++ show clone_flags ++ ", " ++ show newsp ++ ", " ++ show parent_tidptr ++ ", " ++ show child_tidptr ++ ", " ++ show tls ++ ")"

  DetailedSyscallEnter_unshare
    SyscallEnterDetails_unshare{ unshare_flags } ->
      "unshare(" ++ show unshare_flags ++ ")"

  DetailedSyscallEnter_set_robust_list
    SyscallEnterDetails_set_robust_list{ head_, len } ->
      "set_robust_list(" ++ show head_ ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_get_robust_list
    SyscallEnterDetails_get_robust_list{ pid_, head_ptr, len_ptr } ->
      "get_robust_list(" ++ show pid_ ++ ", " ++ show head_ptr ++ ", " ++ show len_ptr ++ ")"

  DetailedSyscallEnter_futex
    SyscallEnterDetails_futex{ uaddr, op, val, utime, uaddr2, val3 } ->
      "futex(" ++ show uaddr ++ ", " ++ show op ++ ", " ++ show val ++ ", " ++ show utime ++ ", " ++ show uaddr2 ++ ", " ++ show val3 ++ ")"

  DetailedSyscallEnter_getgroups
    SyscallEnterDetails_getgroups{ gidsetsize, grouplist } ->
      "getgroups(" ++ show gidsetsize ++ ", " ++ show grouplist ++ ")"

  DetailedSyscallEnter_setgroups
    SyscallEnterDetails_setgroups{ gidsetsize, grouplist } ->
      "setgroups(" ++ show gidsetsize ++ ", " ++ show grouplist ++ ")"

  DetailedSyscallEnter_kcmp
    SyscallEnterDetails_kcmp{ pid1, pid2, type_, idx1, idx2 } ->
      "kcmp(" ++ show pid1 ++ ", " ++ show pid2 ++ ", " ++ show type_ ++ ", " ++ show idx1 ++ ", " ++ show idx2 ++ ")"

  DetailedSyscallEnter_kexec_load
    SyscallEnterDetails_kexec_load{ entry, nr_segments, segments, flags } ->
      "kexec_load(" ++ show entry ++ ", " ++ show nr_segments ++ ", " ++ show segments ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_kexec_file_load
    SyscallEnterDetails_kexec_file_load{ kernel_fd, initrd_fd, cmdline_len, cmdline_ptrBS, flags } ->
      "kexec_file_load(" ++ show kernel_fd ++ ", " ++ show initrd_fd ++ ", " ++ show cmdline_len ++ ", " ++ show cmdline_ptrBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_delete_module
    SyscallEnterDetails_delete_module{ name_userBS, flags } ->
      "delete_module(" ++ show name_userBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_init_module
    SyscallEnterDetails_init_module{ umod, len, uargsBS } ->
      "init_module(" ++ show umod ++ ", " ++ show len ++ ", " ++ show uargsBS ++ ")"

  DetailedSyscallEnter_finit_module
    SyscallEnterDetails_finit_module{ fd, uargsBS, flags } ->
      "finit_module(" ++ show fd ++ ", " ++ show uargsBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_setns
    SyscallEnterDetails_setns{ fd, nstype } ->
      "setns(" ++ show fd ++ ", " ++ show nstype ++ ")"

  DetailedSyscallEnter_syslog
    SyscallEnterDetails_syslog{ type_, bufBS, len } ->
      "syslog(" ++ show type_ ++ ", " ++ show bufBS ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_ptrace
    SyscallEnterDetails_ptrace{ request, pid_, addr, data_ } ->
      "ptrace(" ++ show request ++ ", " ++ show pid_ ++ ", " ++ show addr ++ ", " ++ show data_ ++ ")"

  DetailedSyscallEnter_reboot
    SyscallEnterDetails_reboot{ magic1, magic2, cmd, arg } ->
      "reboot(" ++ show magic1 ++ ", " ++ show magic2 ++ ", " ++ show cmd ++ ", " ++ show arg ++ ")"

  DetailedSyscallEnter_rseq
    SyscallEnterDetails_rseq{ rseq, rseq_len, flags, sig } ->
      "rseq(" ++ show rseq ++ ", " ++ show rseq_len ++ ", " ++ show flags ++ ", " ++ show sig ++ ")"

  DetailedSyscallEnter_nice
    SyscallEnterDetails_nice{ increment } ->
      "nice(" ++ show increment ++ ")"

  DetailedSyscallEnter_sched_setscheduler
    SyscallEnterDetails_sched_setscheduler{ pid_, policy, param } ->
      "sched_setscheduler(" ++ show pid_ ++ ", " ++ show policy ++ ", " ++ show param ++ ")"

  DetailedSyscallEnter_sched_setparam
    SyscallEnterDetails_sched_setparam{ pid_, param } ->
      "sched_setparam(" ++ show pid_ ++ ", " ++ show param ++ ")"

  DetailedSyscallEnter_sched_setattr
    SyscallEnterDetails_sched_setattr{ pid_, uattr, flags } ->
      "sched_setattr(" ++ show pid_ ++ ", " ++ show uattr ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_sched_getscheduler
    SyscallEnterDetails_sched_getscheduler{ pid_ } ->
      "sched_getscheduler(" ++ show pid_ ++ ")"

  DetailedSyscallEnter_sched_getparam
    SyscallEnterDetails_sched_getparam{ pid_, param } ->
      "sched_getparam(" ++ show pid_ ++ ", " ++ show param ++ ")"

  DetailedSyscallEnter_sched_getattr
    SyscallEnterDetails_sched_getattr{ pid_, uattr, size, flags } ->
      "sched_getattr(" ++ show pid_ ++ ", " ++ show uattr ++ ", " ++ show size ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_sched_setaffinity
    SyscallEnterDetails_sched_setaffinity{ pid_, len, user_mask_ptr } ->
      "sched_setaffinity(" ++ show pid_ ++ ", " ++ show len ++ ", " ++ show user_mask_ptr ++ ")"

  DetailedSyscallEnter_sched_getaffinity
    SyscallEnterDetails_sched_getaffinity{ pid_, len, user_mask_ptr } ->
      "sched_getaffinity(" ++ show pid_ ++ ", " ++ show len ++ ", " ++ show user_mask_ptr ++ ")"

  DetailedSyscallEnter_sched_yield
    SyscallEnterDetails_sched_yield{  } ->
      "sched_yield()"

  DetailedSyscallEnter_sched_get_priority_max
    SyscallEnterDetails_sched_get_priority_max{ policy } ->
      "sched_get_priority_max(" ++ show policy ++ ")"

  DetailedSyscallEnter_sched_get_priority_min
    SyscallEnterDetails_sched_get_priority_min{ policy } ->
      "sched_get_priority_min(" ++ show policy ++ ")"

  DetailedSyscallEnter_sched_rr_get_interval
    SyscallEnterDetails_sched_rr_get_interval{ pid_, interval } ->
      "sched_rr_get_interval(" ++ show pid_ ++ ", " ++ show interval ++ ")"

  DetailedSyscallEnter_membarrier
    SyscallEnterDetails_membarrier{ cmd, flags } ->
      "membarrier(" ++ show cmd ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_seccomp
    SyscallEnterDetails_seccomp{ op, flags, uargs } ->
      "seccomp(" ++ show op ++ ", " ++ show flags ++ ", " ++ show uargs ++ ")"

  DetailedSyscallEnter_restart_syscall
    SyscallEnterDetails_restart_syscall{  } ->
      "restart_syscall()"

  DetailedSyscallEnter_rt_sigprocmask
    SyscallEnterDetails_rt_sigprocmask{ how, nset, oset, sigsetsize } ->
      "rt_sigprocmask(" ++ show how ++ ", " ++ show nset ++ ", " ++ show oset ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_rt_sigpending
    SyscallEnterDetails_rt_sigpending{ uset, sigsetsize } ->
      "rt_sigpending(" ++ show uset ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_kill
    SyscallEnterDetails_kill{ pid_, sig } ->
      "kill(" ++ show pid_ ++ ", " ++ show sig ++ ")"

  DetailedSyscallEnter_tgkill
    SyscallEnterDetails_tgkill{ tgid, pid_, sig } ->
      "tgkill(" ++ show tgid ++ ", " ++ show pid_ ++ ", " ++ show sig ++ ")"

  DetailedSyscallEnter_tkill
    SyscallEnterDetails_tkill{ pid_, sig } ->
      "tkill(" ++ show pid_ ++ ", " ++ show sig ++ ")"

  DetailedSyscallEnter_sigpending
    SyscallEnterDetails_sigpending{ uset } ->
      "sigpending(" ++ show uset ++ ")"

  DetailedSyscallEnter_sigprocmask
    SyscallEnterDetails_sigprocmask{ how, nset, oset } ->
      "sigprocmask(" ++ show how ++ ", " ++ show nset ++ ", " ++ show oset ++ ")"

  DetailedSyscallEnter_rt_sigaction
    SyscallEnterDetails_rt_sigaction{ sig, act, oact, sigsetsize } ->
      "rt_sigaction(" ++ show sig ++ ", " ++ show act ++ ", " ++ show oact ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_sigaction
    SyscallEnterDetails_sigaction{ sig, act, oact } ->
      "sigaction(" ++ show sig ++ ", " ++ show act ++ ", " ++ show oact ++ ")"

  DetailedSyscallEnter_sgetmask
    SyscallEnterDetails_sgetmask{  } ->
      "sgetmask()"

  DetailedSyscallEnter_ssetmask
    SyscallEnterDetails_ssetmask{ newmask } ->
      "ssetmask(" ++ show newmask ++ ")"

  DetailedSyscallEnter_signal
    SyscallEnterDetails_signal{ sig, handler } ->
      "signal(" ++ show sig ++ ", " ++ show handler ++ ")"

  DetailedSyscallEnter_pause
    SyscallEnterDetails_pause{  } ->
      "pause()"

  DetailedSyscallEnter_rt_sigsuspend
    SyscallEnterDetails_rt_sigsuspend{ unewset, sigsetsize } ->
      "rt_sigsuspend(" ++ show unewset ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_sigsuspend
    SyscallEnterDetails_sigsuspend{ mask } ->
      "sigsuspend(" ++ show mask ++ ")"

  DetailedSyscallEnter_setpriority
    SyscallEnterDetails_setpriority{ which, who, niceval } ->
      "setpriority(" ++ show which ++ ", " ++ show who ++ ", " ++ show niceval ++ ")"

  DetailedSyscallEnter_getpriority
    SyscallEnterDetails_getpriority{ which, who } ->
      "getpriority(" ++ show which ++ ", " ++ show who ++ ")"

  DetailedSyscallEnter_setregid
    SyscallEnterDetails_setregid{ rgid, egid } ->
      "setregid(" ++ show rgid ++ ", " ++ show egid ++ ")"

  DetailedSyscallEnter_setgid
    SyscallEnterDetails_setgid{ gid } ->
      "setgid(" ++ show gid ++ ")"

  DetailedSyscallEnter_setreuid
    SyscallEnterDetails_setreuid{ ruid, euid } ->
      "setreuid(" ++ show ruid ++ ", " ++ show euid ++ ")"

  DetailedSyscallEnter_setuid
    SyscallEnterDetails_setuid{ uid } ->
      "setuid(" ++ show uid ++ ")"

  DetailedSyscallEnter_setresuid
    SyscallEnterDetails_setresuid{ ruid, euid, suid } ->
      "setresuid(" ++ show ruid ++ ", " ++ show euid ++ ", " ++ show suid ++ ")"

  DetailedSyscallEnter_getresuid
    SyscallEnterDetails_getresuid{ ruidp, euidp, suidp } ->
      "getresuid(" ++ show ruidp ++ ", " ++ show euidp ++ ", " ++ show suidp ++ ")"

  DetailedSyscallEnter_setresgid
    SyscallEnterDetails_setresgid{ rgid, egid, sgid } ->
      "setresgid(" ++ show rgid ++ ", " ++ show egid ++ ", " ++ show sgid ++ ")"

  DetailedSyscallEnter_getresgid
    SyscallEnterDetails_getresgid{ rgidp, egidp, sgidp } ->
      "getresgid(" ++ show rgidp ++ ", " ++ show egidp ++ ", " ++ show sgidp ++ ")"

  DetailedSyscallEnter_setfsuid
    SyscallEnterDetails_setfsuid{ uid } ->
      "setfsuid(" ++ show uid ++ ")"

  DetailedSyscallEnter_setfsgid
    SyscallEnterDetails_setfsgid{ gid } ->
      "setfsgid(" ++ show gid ++ ")"

  DetailedSyscallEnter_getpid
    SyscallEnterDetails_getpid{  } ->
      "getpid()"

  DetailedSyscallEnter_gettid
    SyscallEnterDetails_gettid{  } ->
      "gettid()"

  DetailedSyscallEnter_getppid
    SyscallEnterDetails_getppid{  } ->
      "getppid()"

  DetailedSyscallEnter_getuid
    SyscallEnterDetails_getuid{  } ->
      "getuid()"

  DetailedSyscallEnter_geteuid
    SyscallEnterDetails_geteuid{  } ->
      "geteuid()"

  DetailedSyscallEnter_getgid
    SyscallEnterDetails_getgid{  } ->
      "getgid()"

  DetailedSyscallEnter_getegid
    SyscallEnterDetails_getegid{  } ->
      "getegid()"

  DetailedSyscallEnter_times
    SyscallEnterDetails_times{ tbuf } ->
      "times(" ++ show tbuf ++ ")"

  DetailedSyscallEnter_setpgid
    SyscallEnterDetails_setpgid{ pid_, pgid } ->
      "setpgid(" ++ show pid_ ++ ", " ++ show pgid ++ ")"

  DetailedSyscallEnter_getpgid
    SyscallEnterDetails_getpgid{ pid_ } ->
      "getpgid(" ++ show pid_ ++ ")"

  DetailedSyscallEnter_getpgrp
    SyscallEnterDetails_getpgrp{  } ->
      "getpgrp()"

  DetailedSyscallEnter_getsid
    SyscallEnterDetails_getsid{ pid_ } ->
      "getsid(" ++ show pid_ ++ ")"

  DetailedSyscallEnter_setsid
    SyscallEnterDetails_setsid{  } ->
      "setsid()"

  DetailedSyscallEnter_uname
    SyscallEnterDetails_uname{ name } ->
      "uname(" ++ show name ++ ")"

  DetailedSyscallEnter_olduname
    SyscallEnterDetails_olduname{ name } ->
      "olduname(" ++ show name ++ ")"

  DetailedSyscallEnter_sethostname
    SyscallEnterDetails_sethostname{ nameBS, len } ->
      "sethostname(" ++ show nameBS ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_gethostname
    SyscallEnterDetails_gethostname{ nameBS, len } ->
      "gethostname(" ++ show nameBS ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_setdomainname
    SyscallEnterDetails_setdomainname{ nameBS, len } ->
      "setdomainname(" ++ show nameBS ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_getrlimit
    SyscallEnterDetails_getrlimit{ resource, rlim } ->
      "getrlimit(" ++ show resource ++ ", " ++ show rlim ++ ")"

  DetailedSyscallEnter_prlimit64
    SyscallEnterDetails_prlimit64{ pid_, resource, new_rlim, old_rlim } ->
      "prlimit64(" ++ show pid_ ++ ", " ++ show resource ++ ", " ++ show new_rlim ++ ", " ++ show old_rlim ++ ")"

  DetailedSyscallEnter_setrlimit
    SyscallEnterDetails_setrlimit{ resource, rlim } ->
      "setrlimit(" ++ show resource ++ ", " ++ show rlim ++ ")"

  DetailedSyscallEnter_getrusage
    SyscallEnterDetails_getrusage{ who, ru } ->
      "getrusage(" ++ show who ++ ", " ++ show ru ++ ")"

  DetailedSyscallEnter_umask
    SyscallEnterDetails_umask{ mask } ->
      "umask(" ++ show mask ++ ")"

  DetailedSyscallEnter_prctl
    SyscallEnterDetails_prctl{ option, arg2, arg3, arg4, arg5 } ->
      "prctl(" ++ show option ++ ", " ++ show arg2 ++ ", " ++ show arg3 ++ ", " ++ show arg4 ++ ", " ++ show arg5 ++ ")"

  DetailedSyscallEnter_getcpu
    SyscallEnterDetails_getcpu{ cpup, nodep, unused } ->
      "getcpu(" ++ show cpup ++ ", " ++ show nodep ++ ", " ++ show unused ++ ")"

  DetailedSyscallEnter_sysinfo
    SyscallEnterDetails_sysinfo{ info } ->
      "sysinfo(" ++ show info ++ ")"

  DetailedSyscallEnter_nanosleep
    SyscallEnterDetails_nanosleep{ rqtp, rmtp } ->
      "nanosleep(" ++ show rqtp ++ ", " ++ show rmtp ++ ")"

  DetailedSyscallEnter_getitimer
    SyscallEnterDetails_getitimer{ which, value } ->
      "getitimer(" ++ show which ++ ", " ++ show value ++ ")"

  DetailedSyscallEnter_alarm
    SyscallEnterDetails_alarm{ seconds } ->
      "alarm(" ++ show seconds ++ ")"

  DetailedSyscallEnter_setitimer
    SyscallEnterDetails_setitimer{ which, value, ovalue } ->
      "setitimer(" ++ show which ++ ", " ++ show value ++ ", " ++ show ovalue ++ ")"

  DetailedSyscallEnter_clock_settime
    SyscallEnterDetails_clock_settime{ which_clock, tp } ->
      "clock_settime(" ++ show which_clock ++ ", " ++ show tp ++ ")"

  DetailedSyscallEnter_clock_gettime
    SyscallEnterDetails_clock_gettime{ which_clock, tp } ->
      "clock_gettime(" ++ show which_clock ++ ", " ++ show tp ++ ")"

  DetailedSyscallEnter_clock_getres
    SyscallEnterDetails_clock_getres{ which_clock, tp } ->
      "clock_getres(" ++ show which_clock ++ ", " ++ show tp ++ ")"

  DetailedSyscallEnter_clock_nanosleep
    SyscallEnterDetails_clock_nanosleep{ which_clock, flags, rqtp, rmtp } ->
      "clock_nanosleep(" ++ show which_clock ++ ", " ++ show flags ++ ", " ++ show rqtp ++ ", " ++ show rmtp ++ ")"

  DetailedSyscallEnter_timer_create
    SyscallEnterDetails_timer_create{ which_clock, timer_event_spec, created_timer_id } ->
      "timer_create(" ++ show which_clock ++ ", " ++ show timer_event_spec ++ ", " ++ show created_timer_id ++ ")"

  DetailedSyscallEnter_timer_gettime
    SyscallEnterDetails_timer_gettime{ timer_id, setting } ->
      "timer_gettime(" ++ show timer_id ++ ", " ++ show setting ++ ")"

  DetailedSyscallEnter_timer_getoverrun
    SyscallEnterDetails_timer_getoverrun{ timer_id } ->
      "timer_getoverrun(" ++ show timer_id ++ ")"

  DetailedSyscallEnter_timer_settime
    SyscallEnterDetails_timer_settime{ timer_id, flags, new_setting, old_setting } ->
      "timer_settime(" ++ show timer_id ++ ", " ++ show flags ++ ", " ++ show new_setting ++ ", " ++ show old_setting ++ ")"

  DetailedSyscallEnter_timer_delete
    SyscallEnterDetails_timer_delete{ timer_id } ->
      "timer_delete(" ++ show timer_id ++ ")"

  DetailedSyscallEnter_clock_adjtime
    SyscallEnterDetails_clock_adjtime{ which_clock, utx } ->
      "clock_adjtime(" ++ show which_clock ++ ", " ++ show utx ++ ")"

  DetailedSyscallEnter_time
    SyscallEnterDetails_time{ tloc } ->
      "time(" ++ show tloc ++ ")"

  DetailedSyscallEnter_stime
    SyscallEnterDetails_stime{ tptr } ->
      "stime(" ++ show tptr ++ ")"

  DetailedSyscallEnter_gettimeofday
    SyscallEnterDetails_gettimeofday{ tv, tz } ->
      "gettimeofday(" ++ show tv ++ ", " ++ show tz ++ ")"

  DetailedSyscallEnter_settimeofday
    SyscallEnterDetails_settimeofday{ tv, tz } ->
      "settimeofday(" ++ show tv ++ ", " ++ show tz ++ ")"

  DetailedSyscallEnter_adjtimex
    SyscallEnterDetails_adjtimex{ txc_p } ->
      "adjtimex(" ++ show txc_p ++ ")"

  DetailedSyscallEnter_fadvise64_64
    SyscallEnterDetails_fadvise64_64{ fd, offset, len, advice } ->
      "fadvise64_64(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show len ++ ", " ++ show advice ++ ")"

  DetailedSyscallEnter_fadvise64
    SyscallEnterDetails_fadvise64{ fd, offset, len, advice } ->
      "fadvise64(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show len ++ ", " ++ show advice ++ ")"

  DetailedSyscallEnter_madvise
    SyscallEnterDetails_madvise{ start, len_in, behavior } ->
      "madvise(" ++ show start ++ ", " ++ show len_in ++ ", " ++ show behavior ++ ")"

  DetailedSyscallEnter_memfd_create
    SyscallEnterDetails_memfd_create{ unameBS, flags } ->
      "memfd_create(" ++ show unameBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_mbind
    SyscallEnterDetails_mbind{ start, len, mode, nmask, maxnode, flags } ->
      "mbind(" ++ show start ++ ", " ++ show len ++ ", " ++ show mode ++ ", " ++ show nmask ++ ", " ++ show maxnode ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_set_mempolicy
    SyscallEnterDetails_set_mempolicy{ mode, nmask, maxnode } ->
      "set_mempolicy(" ++ show mode ++ ", " ++ show nmask ++ ", " ++ show maxnode ++ ")"

  DetailedSyscallEnter_migrate_pages
    SyscallEnterDetails_migrate_pages{ pid_, maxnode, old_nodes, new_nodes } ->
      "migrate_pages(" ++ show pid_ ++ ", " ++ show maxnode ++ ", " ++ show old_nodes ++ ", " ++ show new_nodes ++ ")"

  DetailedSyscallEnter_get_mempolicy
    SyscallEnterDetails_get_mempolicy{ policy, nmask, maxnode, addr, flags } ->
      "get_mempolicy(" ++ show policy ++ ", " ++ show nmask ++ ", " ++ show maxnode ++ ", " ++ show addr ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_move_pages
    SyscallEnterDetails_move_pages{ pid_, nr_pages, pages, nodes, status, flags } ->
      "move_pages(" ++ show pid_ ++ ", " ++ show nr_pages ++ ", " ++ show pages ++ ", " ++ show nodes ++ ", " ++ show status ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_mincore
    SyscallEnterDetails_mincore{ start, len, vec } ->
      "mincore(" ++ show start ++ ", " ++ show len ++ ", " ++ show vec ++ ")"

  DetailedSyscallEnter_mlock
    SyscallEnterDetails_mlock{ start, len } ->
      "mlock(" ++ show start ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_mlock2
    SyscallEnterDetails_mlock2{ start, len, flags } ->
      "mlock2(" ++ show start ++ ", " ++ show len ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_munlock
    SyscallEnterDetails_munlock{ start, len } ->
      "munlock(" ++ show start ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_mlockall
    SyscallEnterDetails_mlockall{ flags } ->
      "mlockall(" ++ show flags ++ ")"

  DetailedSyscallEnter_munlockall
    SyscallEnterDetails_munlockall{  } ->
      "munlockall()"

  DetailedSyscallEnter_brk
    SyscallEnterDetails_brk{ brk } ->
      "brk(" ++ show brk ++ ")"

  DetailedSyscallEnter_munmap
    SyscallEnterDetails_munmap{ addr, len } ->
      "munmap(" ++ show addr ++ ", " ++ show len ++ ")"

  DetailedSyscallEnter_remap_file_pages
    SyscallEnterDetails_remap_file_pages{ start, size, prot, pgoff, flags } ->
      "remap_file_pages(" ++ show start ++ ", " ++ show size ++ ", " ++ show prot ++ ", " ++ show pgoff ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_mprotect
    SyscallEnterDetails_mprotect{ start, len, prot } ->
      "mprotect(" ++ show start ++ ", " ++ show len ++ ", " ++ show prot ++ ")"

  DetailedSyscallEnter_pkey_mprotect
    SyscallEnterDetails_pkey_mprotect{ start, len, prot, pkey } ->
      "pkey_mprotect(" ++ show start ++ ", " ++ show len ++ ", " ++ show prot ++ ", " ++ show pkey ++ ")"

  DetailedSyscallEnter_pkey_alloc
    SyscallEnterDetails_pkey_alloc{ flags, init_val } ->
      "pkey_alloc(" ++ show flags ++ ", " ++ show init_val ++ ")"

  DetailedSyscallEnter_pkey_free
    SyscallEnterDetails_pkey_free{ pkey } ->
      "pkey_free(" ++ show pkey ++ ")"

  DetailedSyscallEnter_mremap
    SyscallEnterDetails_mremap{ addr, old_len, new_len, flags, new_addr } ->
      "mremap(" ++ show addr ++ ", " ++ show old_len ++ ", " ++ show new_len ++ ", " ++ show flags ++ ", " ++ show new_addr ++ ")"

  DetailedSyscallEnter_msync
    SyscallEnterDetails_msync{ start, len, flags } ->
      "msync(" ++ show start ++ ", " ++ show len ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_process_vm_readv
    SyscallEnterDetails_process_vm_readv{ pid_, lvec, liovcnt, rvec, riovcnt, flags } ->
      "process_vm_readv(" ++ show pid_ ++ ", " ++ show lvec ++ ", " ++ show liovcnt ++ ", " ++ show rvec ++ ", " ++ show riovcnt ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_process_vm_writev
    SyscallEnterDetails_process_vm_writev{ pid_, lvec, liovcnt, rvec, riovcnt, flags } ->
      "process_vm_writev(" ++ show pid_ ++ ", " ++ show lvec ++ ", " ++ show liovcnt ++ ", " ++ show rvec ++ ", " ++ show riovcnt ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_readahead
    SyscallEnterDetails_readahead{ fd, offset, count } ->
      "readahead(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_swapoff
    SyscallEnterDetails_swapoff{ specialfileBS } ->
      "swapoff(" ++ show specialfileBS ++ ")"

  DetailedSyscallEnter_swapon
    SyscallEnterDetails_swapon{ specialfileBS, swap_flags } ->
      "swapon(" ++ show specialfileBS ++ ", " ++ show swap_flags ++ ")"

  DetailedSyscallEnter_socket
    SyscallEnterDetails_socket{ family, type_, protocol } ->
      "socket(" ++ show family ++ ", " ++ show type_ ++ ", " ++ show protocol ++ ")"

  DetailedSyscallEnter_socketpair
    SyscallEnterDetails_socketpair{ family, type_, protocol, usockvec } ->
      "socketpair(" ++ show family ++ ", " ++ show type_ ++ ", " ++ show protocol ++ ", " ++ show usockvec ++ ")"

  DetailedSyscallEnter_bind
    SyscallEnterDetails_bind{ fd, umyaddr, addrlen } ->
      "bind(" ++ show fd ++ ", " ++ show umyaddr ++ ", " ++ show addrlen ++ ")"

  DetailedSyscallEnter_listen
    SyscallEnterDetails_listen{ fd, backlog } ->
      "listen(" ++ show fd ++ ", " ++ show backlog ++ ")"

  DetailedSyscallEnter_accept4
    SyscallEnterDetails_accept4{ fd, upeer_sockaddr, upeer_addrlen, flags } ->
      "accept4(" ++ show fd ++ ", " ++ show upeer_sockaddr ++ ", " ++ show upeer_addrlen ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_accept
    SyscallEnterDetails_accept{ fd, upeer_sockaddr, upeer_addrlen } ->
      "accept(" ++ show fd ++ ", " ++ show upeer_sockaddr ++ ", " ++ show upeer_addrlen ++ ")"

  DetailedSyscallEnter_connect
    SyscallEnterDetails_connect{ fd, uservaddr, addrlen } ->
      "connect(" ++ show fd ++ ", " ++ show uservaddr ++ ", " ++ show addrlen ++ ")"

  DetailedSyscallEnter_getsockname
    SyscallEnterDetails_getsockname{ fd, usockaddr, usockaddr_len } ->
      "getsockname(" ++ show fd ++ ", " ++ show usockaddr ++ ", " ++ show usockaddr_len ++ ")"

  DetailedSyscallEnter_getpeername
    SyscallEnterDetails_getpeername{ fd, usockaddr, usockaddr_len } ->
      "getpeername(" ++ show fd ++ ", " ++ show usockaddr ++ ", " ++ show usockaddr_len ++ ")"

  DetailedSyscallEnter_sendto
    SyscallEnterDetails_sendto{ fd, buff, len, flags, addr, addr_len } ->
      "sendto(" ++ show fd ++ ", " ++ show buff ++ ", " ++ show len ++ ", " ++ show flags ++ ", " ++ show addr ++ ", " ++ show addr_len ++ ")"

  DetailedSyscallEnter_send
    SyscallEnterDetails_send{ fd, buff, len, flags } ->
      "send(" ++ show fd ++ ", " ++ show buff ++ ", " ++ show len ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_recvfrom
    SyscallEnterDetails_recvfrom{ fd, ubuf, size, flags, addr, addr_len } ->
      "recvfrom(" ++ show fd ++ ", " ++ show ubuf ++ ", " ++ show size ++ ", " ++ show flags ++ ", " ++ show addr ++ ", " ++ show addr_len ++ ")"

  DetailedSyscallEnter_recv
    SyscallEnterDetails_recv{ fd, ubuf, size, flags } ->
      "recv(" ++ show fd ++ ", " ++ show ubuf ++ ", " ++ show size ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_setsockopt
    SyscallEnterDetails_setsockopt{ fd, level, optname, optvalBS, optlen } ->
      "setsockopt(" ++ show fd ++ ", " ++ show level ++ ", " ++ show optname ++ ", " ++ show optvalBS ++ ", " ++ show optlen ++ ")"

  DetailedSyscallEnter_getsockopt
    SyscallEnterDetails_getsockopt{ fd, level, optname, optvalBS, optlen } ->
      "getsockopt(" ++ show fd ++ ", " ++ show level ++ ", " ++ show optname ++ ", " ++ show optvalBS ++ ", " ++ show optlen ++ ")"

  DetailedSyscallEnter_shutdown
    SyscallEnterDetails_shutdown{ fd, how } ->
      "shutdown(" ++ show fd ++ ", " ++ show how ++ ")"

  DetailedSyscallEnter_sendmsg
    SyscallEnterDetails_sendmsg{ fd, msg, flags } ->
      "sendmsg(" ++ show fd ++ ", " ++ show msg ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_sendmmsg
    SyscallEnterDetails_sendmmsg{ fd, mmsg, vlen, flags } ->
      "sendmmsg(" ++ show fd ++ ", " ++ show mmsg ++ ", " ++ show vlen ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_recvmsg
    SyscallEnterDetails_recvmsg{ fd, msg, flags } ->
      "recvmsg(" ++ show fd ++ ", " ++ show msg ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_recvmmsg
    SyscallEnterDetails_recvmmsg{ fd, mmsg, vlen, flags, timeout } ->
      "recvmmsg(" ++ show fd ++ ", " ++ show mmsg ++ ", " ++ show vlen ++ ", " ++ show flags ++ ", " ++ show timeout ++ ")"

  DetailedSyscallEnter_socketcall
    SyscallEnterDetails_socketcall{ call, args } ->
      "socketcall(" ++ show call ++ ", " ++ show args ++ ")"

  DetailedSyscallEnter_add_key
    SyscallEnterDetails_add_key{ _typeBS, _descriptionBS, _payload, plen, ringid } ->
      "add_key(" ++ show _typeBS ++ ", " ++ show _descriptionBS ++ ", " ++ show _payload ++ ", " ++ show plen ++ ", " ++ show ringid ++ ")"

  DetailedSyscallEnter_request_key
    SyscallEnterDetails_request_key{ _typeBS, _descriptionBS, _callout_infoBS, destringid } ->
      "request_key(" ++ show _typeBS ++ ", " ++ show _descriptionBS ++ ", " ++ show _callout_infoBS ++ ", " ++ show destringid ++ ")"

  DetailedSyscallEnter_keyctl
    SyscallEnterDetails_keyctl{ option, arg2, arg3, arg4, arg5 } ->
      "keyctl(" ++ show option ++ ", " ++ show arg2 ++ ", " ++ show arg3 ++ ", " ++ show arg4 ++ ", " ++ show arg5 ++ ")"

  DetailedSyscallEnter_select
    SyscallEnterDetails_select{ n, inp, outp, exp_, tvp } ->
      "select(" ++ show n ++ ", " ++ show inp ++ ", " ++ show outp ++ ", " ++ show exp_ ++ ", " ++ show tvp ++ ")"

  DetailedSyscallEnter_pselect6
    SyscallEnterDetails_pselect6{ n, inp, outp, exp_, tsp, sig } ->
      "pselect6(" ++ show n ++ ", " ++ show inp ++ ", " ++ show outp ++ ", " ++ show exp_ ++ ", " ++ show tsp ++ ", " ++ show sig ++ ")"

  DetailedSyscallEnter_mq_open
    SyscallEnterDetails_mq_open{ u_nameBS, oflag, mode, u_attr } ->
      "mq_open(" ++ show u_nameBS ++ ", " ++ show oflag ++ ", " ++ show mode ++ ", " ++ show u_attr ++ ")"

  DetailedSyscallEnter_mq_unlink
    SyscallEnterDetails_mq_unlink{ u_nameBS } ->
      "mq_unlink(" ++ show u_nameBS ++ ")"

  DetailedSyscallEnter_bpf
    SyscallEnterDetails_bpf{ cmd, uattr, size } ->
      "bpf(" ++ show cmd ++ ", " ++ show uattr ++ ", " ++ show size ++ ")"

  DetailedSyscallEnter_capget
    SyscallEnterDetails_capget{ header, dataptr } ->
      "capget(" ++ show header ++ ", " ++ show dataptr ++ ")"

  DetailedSyscallEnter_capset
    SyscallEnterDetails_capset{ header, data_ } ->
      "capset(" ++ show header ++ ", " ++ show data_ ++ ")"

  DetailedSyscallEnter_rt_sigtimedwait
    SyscallEnterDetails_rt_sigtimedwait{ uthese, uinfo, uts, sigsetsize } ->
      "rt_sigtimedwait(" ++ show uthese ++ ", " ++ show uinfo ++ ", " ++ show uts ++ ", " ++ show sigsetsize ++ ")"

  DetailedSyscallEnter_rt_sigqueueinfo
    SyscallEnterDetails_rt_sigqueueinfo{ pid_, sig, uinfo } ->
      "rt_sigqueueinfo(" ++ show pid_ ++ ", " ++ show sig ++ ", " ++ show uinfo ++ ")"

  DetailedSyscallEnter_rt_tgsigqueueinfo
    SyscallEnterDetails_rt_tgsigqueueinfo{ tgid, pid_, sig, uinfo } ->
      "rt_tgsigqueueinfo(" ++ show tgid ++ ", " ++ show pid_ ++ ", " ++ show sig ++ ", " ++ show uinfo ++ ")"

  DetailedSyscallEnter_sigaltstack
    SyscallEnterDetails_sigaltstack{ uss, uoss } ->
      "sigaltstack(" ++ show uss ++ ", " ++ show uoss ++ ")"

  DetailedSyscallEnter_mq_timedsend
    SyscallEnterDetails_mq_timedsend{ mqdes, u_msg_ptrBS, msg_len, msg_prio, u_abs_timeout } ->
      "mq_timedsend(" ++ show mqdes ++ ", " ++ show u_msg_ptrBS ++ ", " ++ show msg_len ++ ", " ++ show msg_prio ++ ", " ++ show u_abs_timeout ++ ")"

  DetailedSyscallEnter_mq_timedreceive
    SyscallEnterDetails_mq_timedreceive{ mqdes, u_msg_ptrBS, msg_len, u_msg_prio, u_abs_timeout } ->
      "mq_timedreceive(" ++ show mqdes ++ ", " ++ show u_msg_ptrBS ++ ", " ++ show msg_len ++ ", " ++ show u_msg_prio ++ ", " ++ show u_abs_timeout ++ ")"

  DetailedSyscallEnter_mq_notify
    SyscallEnterDetails_mq_notify{ mqdes, u_notification } ->
      "mq_notify(" ++ show mqdes ++ ", " ++ show u_notification ++ ")"

  DetailedSyscallEnter_mq_getsetattr
    SyscallEnterDetails_mq_getsetattr{ mqdes, u_mqstat, u_omqstat } ->
      "mq_getsetattr(" ++ show mqdes ++ ", " ++ show u_mqstat ++ ", " ++ show u_omqstat ++ ")"

  DetailedSyscallEnter_unimplemented syscall syscallArgs ->
    "unimplemented_syscall_details(" ++ show syscall ++ ", " ++ show syscallArgs ++ ")"


foreign import ccall unsafe "string.h strerror" c_strerror :: CInt -> IO (Ptr CChar)

-- | Like "Foreign.C.Error"'s @errnoToIOError@, but getting only the string.
strError :: ERRNO -> IO String
strError (ERRNO errno) = c_strerror errno >>= peekCString


formatDetailedSyscallExit :: DetailedSyscallExit -> String
formatDetailedSyscallExit = \case

  DetailedSyscallExit_open
    SyscallExitDetails_open{ enterDetail = SyscallEnterDetails_open{ pathnameBS, flags, mode }, fd } ->
      "open(" ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ") = " ++ show fd

  DetailedSyscallExit_openat
    SyscallExitDetails_openat{ enterDetail = SyscallEnterDetails_openat{ dirfd, pathnameBS, flags, mode }, fd } ->
      "openat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ") = " ++ show fd

  DetailedSyscallExit_creat
    SyscallExitDetails_creat{ enterDetail = SyscallEnterDetails_creat{ pathnameBS, mode }, fd } ->
      "creat(" ++ show pathnameBS ++ ", " ++ show mode ++ ") = " ++ show fd

  DetailedSyscallExit_pipe
    SyscallExitDetails_pipe{ enterDetail = SyscallEnterDetails_pipe{}, readfd, writefd } ->
      "pipe([" ++ show readfd ++ ", " ++ show writefd ++ "])"

  DetailedSyscallExit_pipe2
    SyscallExitDetails_pipe2{ enterDetail = SyscallEnterDetails_pipe2{ flags }, readfd, writefd } ->
      "pipe([" ++ show readfd ++ ", " ++ show writefd ++ "], " ++ show flags ++ ")"

  DetailedSyscallExit_access
    SyscallExitDetails_access{ enterDetail = SyscallEnterDetails_access{ pathnameBS, accessMode } } ->
      "access(" ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ")"

  DetailedSyscallExit_faccessat
    SyscallExitDetails_faccessat
    { enterDetail = SyscallEnterDetails_faccessat{ dirfd, pathnameBS, accessMode, flags } } ->
      "faccessat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ", " ++ show flags ++ ")"

  DetailedSyscallExit_write
    SyscallExitDetails_write{ enterDetail = SyscallEnterDetails_write{ fd, bufContents, count }, writtenCount } ->
      "write(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ") = " ++ show writtenCount

  DetailedSyscallExit_read
    SyscallExitDetails_read{ enterDetail = SyscallEnterDetails_read{ fd, count }, readCount, bufContents } ->
      "read(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ") = " ++ show readCount

  DetailedSyscallExit_close
    SyscallExitDetails_close{ enterDetail = SyscallEnterDetails_close{ fd } } ->
      "close(" ++ show fd ++ ")"

  DetailedSyscallExit_rename
    SyscallExitDetails_rename{ enterDetail = SyscallEnterDetails_rename{ oldpathBS, newpathBS } } ->
      "rename(" ++ show oldpathBS ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallExit_renameat
    SyscallExitDetails_renameat
    { enterDetail = SyscallEnterDetails_renameat{ olddirfd, oldpathBS, newdirfd, newpathBS } } ->
      "renameat(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallExit_renameat2
    SyscallExitDetails_renameat2
    { enterDetail = SyscallEnterDetails_renameat2{ olddirfd, oldpathBS, newdirfd, newpathBS, flags } } ->
      "renameat2(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                 ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallExit_stat
    SyscallExitDetails_stat{ enterDetail = SyscallEnterDetails_stat{ pathnameBS }, stat } ->
      "stat(" ++ show pathnameBS ++ ", " ++ hShow stat ++ ")"

  DetailedSyscallExit_fstat
    SyscallExitDetails_fstat{ enterDetail = SyscallEnterDetails_fstat{ fd }, stat } ->
      "fstat(" ++ show fd ++ ", " ++ hShow stat ++ ")"

  DetailedSyscallExit_lstat
    SyscallExitDetails_lstat{ enterDetail = SyscallEnterDetails_lstat{ pathnameBS }, stat } ->
      "lstat(" ++ show pathnameBS ++ ", " ++ hShow stat ++ ")"

  DetailedSyscallExit_newfstatat
    SyscallExitDetails_newfstatat{ enterDetail = SyscallEnterDetails_newfstatat{ dirfd, pathnameBS, flags }, stat } ->
      "newfstatat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ hShow stat ++ ", " ++ show flags ++ ")"

  DetailedSyscallExit_execve
    SyscallExitDetails_execve{ optionalEnterDetail, execveResult } ->
      -- TODO implement remembering arguments
      let arguments = case optionalEnterDetail of
            Just SyscallEnterDetails_execve{ filenameBS, argvList, envpList } ->
              show filenameBS ++ ", " ++ show argvList ++ ", " ++ show envpList
            Nothing -> "TODO implement remembering arguments"
      in "execve(" ++ arguments ++ ") = " ++ show execveResult

  DetailedSyscallExit_exit
    SyscallExitDetails_exit{ enterDetail = SyscallEnterDetails_exit{ status }} ->
      "exit(" ++ show status ++ ")"

  DetailedSyscallExit_exit_group
    SyscallExitDetails_exit_group{ enterDetail = SyscallEnterDetails_exit_group{ status }} ->
      "exit_group(" ++ show status ++ ")"

  DetailedSyscallExit_ioperm
    SyscallExitDetails_ioperm{ enterDetail = SyscallEnterDetails_ioperm{ from, num, turn_on }, retval } ->
      "ioperm(" ++ show from ++ ", " ++ show num ++ ", " ++ show turn_on ++ ") = " ++ show retval

  DetailedSyscallExit_iopl
    SyscallExitDetails_iopl{ enterDetail = SyscallEnterDetails_iopl{ level }, retval } ->
      "iopl(" ++ show level ++ ") = " ++ show retval

  DetailedSyscallExit_modify_ldt
    SyscallExitDetails_modify_ldt{ enterDetail = SyscallEnterDetails_modify_ldt{ func, ptr, bytecount }, retval } ->
      "modify_ldt(" ++ show func ++ ", " ++ show ptr ++ ", " ++ show bytecount ++ ") = " ++ show retval

  DetailedSyscallExit_arch_prctl
    SyscallExitDetails_arch_prctl{ enterDetail = SyscallEnterDetails_arch_prctl{ option, arg2 }, retval } ->
      "arch_prctl(" ++ show option ++ ", " ++ show arg2 ++ ") = " ++ show retval

  DetailedSyscallExit_sigreturn
    SyscallExitDetails_sigreturn{ enterDetail = SyscallEnterDetails_sigreturn{  }, retval } ->
      "sigreturn() = " ++ show retval

  DetailedSyscallExit_rt_sigreturn
    SyscallExitDetails_rt_sigreturn{ enterDetail = SyscallEnterDetails_rt_sigreturn{  }, retval } ->
      "rt_sigreturn() = " ++ show retval

  DetailedSyscallExit_mmap
    SyscallExitDetails_mmap{ enterDetail = SyscallEnterDetails_mmap{ addr, len, prot, flags, fd, off }, retval } ->
      "mmap(" ++ show addr ++ ", " ++ show len ++ ", " ++ show prot ++ ", " ++ show flags ++ ", " ++ show fd ++ ", " ++ show off ++ ") = " ++ show retval

  DetailedSyscallExit_set_thread_area
    SyscallExitDetails_set_thread_area{ enterDetail = SyscallEnterDetails_set_thread_area{ u_info }, retval } ->
      "set_thread_area(" ++ show u_info ++ ") = " ++ show retval

  DetailedSyscallExit_get_thread_area
    SyscallExitDetails_get_thread_area{ enterDetail = SyscallEnterDetails_get_thread_area{ u_info }, retval } ->
      "get_thread_area(" ++ show u_info ++ ") = " ++ show retval

  DetailedSyscallExit_vm86old
    SyscallExitDetails_vm86old{ enterDetail = SyscallEnterDetails_vm86old{ user_vm86 }, retval } ->
      "vm86old(" ++ show user_vm86 ++ ") = " ++ show retval

  DetailedSyscallExit_vm86
    SyscallExitDetails_vm86{ enterDetail = SyscallEnterDetails_vm86{ cmd, arg }, retval } ->
      "vm86(" ++ show cmd ++ ", " ++ show arg ++ ") = " ++ show retval

  DetailedSyscallExit_ioprio_set
    SyscallExitDetails_ioprio_set{ enterDetail = SyscallEnterDetails_ioprio_set{ which, who, ioprio }, retval } ->
      "ioprio_set(" ++ show which ++ ", " ++ show who ++ ", " ++ show ioprio ++ ") = " ++ show retval

  DetailedSyscallExit_ioprio_get
    SyscallExitDetails_ioprio_get{ enterDetail = SyscallEnterDetails_ioprio_get{ which, who }, retval } ->
      "ioprio_get(" ++ show which ++ ", " ++ show who ++ ") = " ++ show retval

  DetailedSyscallExit_getrandom
    SyscallExitDetails_getrandom{ enterDetail = SyscallEnterDetails_getrandom{ bufBS, count, flags }, retval } ->
      "getrandom(" ++ show bufBS ++ ", " ++ show count ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_pciconfig_read
    SyscallExitDetails_pciconfig_read{ enterDetail = SyscallEnterDetails_pciconfig_read{ bus, dfn, off, len, buf }, retval } ->
      "pciconfig_read(" ++ show bus ++ ", " ++ show dfn ++ ", " ++ show off ++ ", " ++ show len ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_pciconfig_write
    SyscallExitDetails_pciconfig_write{ enterDetail = SyscallEnterDetails_pciconfig_write{ bus, dfn, off, len, buf }, retval } ->
      "pciconfig_write(" ++ show bus ++ ", " ++ show dfn ++ ", " ++ show off ++ ", " ++ show len ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_io_setup
    SyscallExitDetails_io_setup{ enterDetail = SyscallEnterDetails_io_setup{ nr_events, ctxp }, retval } ->
      "io_setup(" ++ show nr_events ++ ", " ++ show ctxp ++ ") = " ++ show retval

  DetailedSyscallExit_io_destroy
    SyscallExitDetails_io_destroy{ enterDetail = SyscallEnterDetails_io_destroy{ ctx }, retval } ->
      "io_destroy(" ++ show ctx ++ ") = " ++ show retval

  DetailedSyscallExit_io_submit
    SyscallExitDetails_io_submit{ enterDetail = SyscallEnterDetails_io_submit{ ctx_id, nr, iocbpp }, retval } ->
      "io_submit(" ++ show ctx_id ++ ", " ++ show nr ++ ", " ++ show iocbpp ++ ") = " ++ show retval

  DetailedSyscallExit_io_cancel
    SyscallExitDetails_io_cancel{ enterDetail = SyscallEnterDetails_io_cancel{ ctx_id, iocb, result }, retval } ->
      "io_cancel(" ++ show ctx_id ++ ", " ++ show iocb ++ ", " ++ show result ++ ") = " ++ show retval

  DetailedSyscallExit_io_getevents
    SyscallExitDetails_io_getevents{ enterDetail = SyscallEnterDetails_io_getevents{ ctx_id, min_nr, nr, events, timeout }, retval } ->
      "io_getevents(" ++ show ctx_id ++ ", " ++ show min_nr ++ ", " ++ show nr ++ ", " ++ show events ++ ", " ++ show timeout ++ ") = " ++ show retval

  DetailedSyscallExit_io_pgetevents
    SyscallExitDetails_io_pgetevents{ enterDetail = SyscallEnterDetails_io_pgetevents{ ctx_id, min_nr, nr, events, timeout, usig }, retval } ->
      "io_pgetevents(" ++ show ctx_id ++ ", " ++ show min_nr ++ ", " ++ show nr ++ ", " ++ show events ++ ", " ++ show timeout ++ ", " ++ show usig ++ ") = " ++ show retval

  DetailedSyscallExit_bdflush
    SyscallExitDetails_bdflush{ enterDetail = SyscallEnterDetails_bdflush{ func, data_ }, retval } ->
      "bdflush(" ++ show func ++ ", " ++ show data_ ++ ") = " ++ show retval

  DetailedSyscallExit_getcwd
    SyscallExitDetails_getcwd{ enterDetail = SyscallEnterDetails_getcwd{ bufBS, size }, retval } ->
      "getcwd(" ++ show bufBS ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_lookup_dcookie
    SyscallExitDetails_lookup_dcookie{ enterDetail = SyscallEnterDetails_lookup_dcookie{ cookie64, bufBS, len }, retval } ->
      "lookup_dcookie(" ++ show cookie64 ++ ", " ++ show bufBS ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_eventfd2
    SyscallExitDetails_eventfd2{ enterDetail = SyscallEnterDetails_eventfd2{ count, flags }, retval } ->
      "eventfd2(" ++ show count ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_eventfd
    SyscallExitDetails_eventfd{ enterDetail = SyscallEnterDetails_eventfd{ count }, retval } ->
      "eventfd(" ++ show count ++ ") = " ++ show retval

  DetailedSyscallExit_epoll_create1
    SyscallExitDetails_epoll_create1{ enterDetail = SyscallEnterDetails_epoll_create1{ flags }, retval } ->
      "epoll_create1(" ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_epoll_create
    SyscallExitDetails_epoll_create{ enterDetail = SyscallEnterDetails_epoll_create{ size }, retval } ->
      "epoll_create(" ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_epoll_ctl
    SyscallExitDetails_epoll_ctl{ enterDetail = SyscallEnterDetails_epoll_ctl{ epfd, op, fd, event }, retval } ->
      "epoll_ctl(" ++ show epfd ++ ", " ++ show op ++ ", " ++ show fd ++ ", " ++ show event ++ ") = " ++ show retval

  DetailedSyscallExit_epoll_wait
    SyscallExitDetails_epoll_wait{ enterDetail = SyscallEnterDetails_epoll_wait{ epfd, events, maxevents, timeout }, retval } ->
      "epoll_wait(" ++ show epfd ++ ", " ++ show events ++ ", " ++ show maxevents ++ ", " ++ show timeout ++ ") = " ++ show retval

  DetailedSyscallExit_epoll_pwait
    SyscallExitDetails_epoll_pwait{ enterDetail = SyscallEnterDetails_epoll_pwait{ epfd, events, maxevents, timeout, sigmask, sigsetsize }, retval } ->
      "epoll_pwait(" ++ show epfd ++ ", " ++ show events ++ ", " ++ show maxevents ++ ", " ++ show timeout ++ ", " ++ show sigmask ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_uselib
    SyscallExitDetails_uselib{ enterDetail = SyscallEnterDetails_uselib{ libraryBS }, retval } ->
      "uselib(" ++ show libraryBS ++ ") = " ++ show retval

  DetailedSyscallExit_execveat
    SyscallExitDetails_execveat{ enterDetail = SyscallEnterDetails_execveat{ fd, filenameBS, argv, envp, flags }, retval } ->
      "execveat(" ++ show fd ++ ", " ++ show filenameBS ++ ", " ++ show argv ++ ", " ++ show envp ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_fcntl
    SyscallExitDetails_fcntl{ enterDetail = SyscallEnterDetails_fcntl{ fd, cmd, arg }, retval } ->
      "fcntl(" ++ show fd ++ ", " ++ show cmd ++ ", " ++ show arg ++ ") = " ++ show retval

  DetailedSyscallExit_fcntl64
    SyscallExitDetails_fcntl64{ enterDetail = SyscallEnterDetails_fcntl64{ fd, cmd, arg }, retval } ->
      "fcntl64(" ++ show fd ++ ", " ++ show cmd ++ ", " ++ show arg ++ ") = " ++ show retval

  DetailedSyscallExit_name_to_handle_at
    SyscallExitDetails_name_to_handle_at{ enterDetail = SyscallEnterDetails_name_to_handle_at{ dfd, nameBS, handle, mnt_id, flag }, retval } ->
      "name_to_handle_at(" ++ show dfd ++ ", " ++ show nameBS ++ ", " ++ show handle ++ ", " ++ show mnt_id ++ ", " ++ show flag ++ ") = " ++ show retval

  DetailedSyscallExit_open_by_handle_at
    SyscallExitDetails_open_by_handle_at{ enterDetail = SyscallEnterDetails_open_by_handle_at{ mountdirfd, handle, flags }, retval } ->
      "open_by_handle_at(" ++ show mountdirfd ++ ", " ++ show handle ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_dup3
    SyscallExitDetails_dup3{ enterDetail = SyscallEnterDetails_dup3{ oldfd, newfd, flags }, retval } ->
      "dup3(" ++ show oldfd ++ ", " ++ show newfd ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_dup2
    SyscallExitDetails_dup2{ enterDetail = SyscallEnterDetails_dup2{ oldfd, newfd }, retval } ->
      "dup2(" ++ show oldfd ++ ", " ++ show newfd ++ ") = " ++ show retval

  DetailedSyscallExit_dup
    SyscallExitDetails_dup{ enterDetail = SyscallEnterDetails_dup{ fildes }, retval } ->
      "dup(" ++ show fildes ++ ") = " ++ show retval

  DetailedSyscallExit_sysfs
    SyscallExitDetails_sysfs{ enterDetail = SyscallEnterDetails_sysfs{ option, arg1, arg2 }, retval } ->
      "sysfs(" ++ show option ++ ", " ++ show arg1 ++ ", " ++ show arg2 ++ ") = " ++ show retval

  DetailedSyscallExit_ioctl
    SyscallExitDetails_ioctl{ enterDetail = SyscallEnterDetails_ioctl{ fd, cmd, arg }, retval } ->
      "ioctl(" ++ show fd ++ ", " ++ show cmd ++ ", " ++ show arg ++ ") = " ++ show retval

  DetailedSyscallExit_flock
    SyscallExitDetails_flock{ enterDetail = SyscallEnterDetails_flock{ fd, cmd }, retval } ->
      "flock(" ++ show fd ++ ", " ++ show cmd ++ ") = " ++ show retval

  DetailedSyscallExit_mknodat
    SyscallExitDetails_mknodat{ enterDetail = SyscallEnterDetails_mknodat{ dfd, filenameBS, mode, dev }, retval } ->
      "mknodat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show mode ++ ", " ++ show dev ++ ") = " ++ show retval

  DetailedSyscallExit_mknod
    SyscallExitDetails_mknod{ enterDetail = SyscallEnterDetails_mknod{ filenameBS, mode, dev }, retval } ->
      "mknod(" ++ show filenameBS ++ ", " ++ show mode ++ ", " ++ show dev ++ ") = " ++ show retval

  DetailedSyscallExit_mkdirat
    SyscallExitDetails_mkdirat{ enterDetail = SyscallEnterDetails_mkdirat{ dfd, pathnameBS, mode }, retval } ->
      "mkdirat(" ++ show dfd ++ ", " ++ show pathnameBS ++ ", " ++ show mode ++ ") = " ++ show retval

  DetailedSyscallExit_mkdir
    SyscallExitDetails_mkdir{ enterDetail = SyscallEnterDetails_mkdir{ pathnameBS, mode }, retval } ->
      "mkdir(" ++ show pathnameBS ++ ", " ++ show mode ++ ") = " ++ show retval

  DetailedSyscallExit_rmdir
    SyscallExitDetails_rmdir{ enterDetail = SyscallEnterDetails_rmdir{ pathnameBS }, retval } ->
      "rmdir(" ++ show pathnameBS ++ ") = " ++ show retval

  DetailedSyscallExit_unlinkat
    SyscallExitDetails_unlinkat{ enterDetail = SyscallEnterDetails_unlinkat{ dfd, pathnameBS, flag }, retval } ->
      "unlinkat(" ++ show dfd ++ ", " ++ show pathnameBS ++ ", " ++ show flag ++ ") = " ++ show retval

  DetailedSyscallExit_unlink
    SyscallExitDetails_unlink{ enterDetail = SyscallEnterDetails_unlink{ pathnameBS }, retval } ->
      "unlink(" ++ show pathnameBS ++ ") = " ++ show retval

  DetailedSyscallExit_symlinkat
    SyscallExitDetails_symlinkat{ enterDetail = SyscallEnterDetails_symlinkat{ oldnameBS, newdfd, newnameBS }, retval } ->
      "symlinkat(" ++ show oldnameBS ++ ", " ++ show newdfd ++ ", " ++ show newnameBS ++ ") = " ++ show retval

  DetailedSyscallExit_symlink
    SyscallExitDetails_symlink{ enterDetail = SyscallEnterDetails_symlink{ oldnameBS, newnameBS }, retval } ->
      "symlink(" ++ show oldnameBS ++ ", " ++ show newnameBS ++ ") = " ++ show retval

  DetailedSyscallExit_linkat
    SyscallExitDetails_linkat{ enterDetail = SyscallEnterDetails_linkat{ olddfd, oldnameBS, newdfd, newnameBS, flags }, retval } ->
      "linkat(" ++ show olddfd ++ ", " ++ show oldnameBS ++ ", " ++ show newdfd ++ ", " ++ show newnameBS ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_link
    SyscallExitDetails_link{ enterDetail = SyscallEnterDetails_link{ oldnameBS, newnameBS }, retval } ->
      "link(" ++ show oldnameBS ++ ", " ++ show newnameBS ++ ") = " ++ show retval

  DetailedSyscallExit_umount
    SyscallExitDetails_umount{ enterDetail = SyscallEnterDetails_umount{ nameBS, flags }, retval } ->
      "umount(" ++ show nameBS ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_oldumount
    SyscallExitDetails_oldumount{ enterDetail = SyscallEnterDetails_oldumount{ nameBS }, retval } ->
      "oldumount(" ++ show nameBS ++ ") = " ++ show retval

  DetailedSyscallExit_mount
    SyscallExitDetails_mount{ enterDetail = SyscallEnterDetails_mount{ dev_nameBS, dir_nameBS, type_BS, flags, data_ }, retval } ->
      "mount(" ++ show dev_nameBS ++ ", " ++ show dir_nameBS ++ ", " ++ show type_BS ++ ", " ++ show flags ++ ", " ++ show data_ ++ ") = " ++ show retval

  DetailedSyscallExit_pivot_root
    SyscallExitDetails_pivot_root{ enterDetail = SyscallEnterDetails_pivot_root{ new_rootBS, put_oldBS }, retval } ->
      "pivot_root(" ++ show new_rootBS ++ ", " ++ show put_oldBS ++ ") = " ++ show retval

  DetailedSyscallExit_fanotify_init
    SyscallExitDetails_fanotify_init{ enterDetail = SyscallEnterDetails_fanotify_init{ flags, event_f_flags }, retval } ->
      "fanotify_init(" ++ show flags ++ ", " ++ show event_f_flags ++ ") = " ++ show retval

  DetailedSyscallExit_fanotify_mark
    SyscallExitDetails_fanotify_mark{ enterDetail = SyscallEnterDetails_fanotify_mark{ fanotify_fd, flags, mask, dfd, pathnameBS }, retval } ->
      "fanotify_mark(" ++ show fanotify_fd ++ ", " ++ show flags ++ ", " ++ show mask ++ ", " ++ show dfd ++ ", " ++ show pathnameBS ++ ") = " ++ show retval

  DetailedSyscallExit_inotify_init1
    SyscallExitDetails_inotify_init1{ enterDetail = SyscallEnterDetails_inotify_init1{ flags }, retval } ->
      "inotify_init1(" ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_inotify_init
    SyscallExitDetails_inotify_init{ enterDetail = SyscallEnterDetails_inotify_init{  }, retval } ->
      "inotify_init() = " ++ show retval

  DetailedSyscallExit_inotify_add_watch
    SyscallExitDetails_inotify_add_watch{ enterDetail = SyscallEnterDetails_inotify_add_watch{ fd, pathnameBS, mask }, retval } ->
      "inotify_add_watch(" ++ show fd ++ ", " ++ show pathnameBS ++ ", " ++ show mask ++ ") = " ++ show retval

  DetailedSyscallExit_inotify_rm_watch
    SyscallExitDetails_inotify_rm_watch{ enterDetail = SyscallEnterDetails_inotify_rm_watch{ fd, wd }, retval } ->
      "inotify_rm_watch(" ++ show fd ++ ", " ++ show wd ++ ") = " ++ show retval

  DetailedSyscallExit_truncate
    SyscallExitDetails_truncate{ enterDetail = SyscallEnterDetails_truncate{ pathBS, length_ }, retval } ->
      "truncate(" ++ show pathBS ++ ", " ++ show length_ ++ ") = " ++ show retval

  DetailedSyscallExit_ftruncate
    SyscallExitDetails_ftruncate{ enterDetail = SyscallEnterDetails_ftruncate{ fd, length_ }, retval } ->
      "ftruncate(" ++ show fd ++ ", " ++ show length_ ++ ") = " ++ show retval

  DetailedSyscallExit_truncate64
    SyscallExitDetails_truncate64{ enterDetail = SyscallEnterDetails_truncate64{ pathBS, length_ }, retval } ->
      "truncate64(" ++ show pathBS ++ ", " ++ show length_ ++ ") = " ++ show retval

  DetailedSyscallExit_ftruncate64
    SyscallExitDetails_ftruncate64{ enterDetail = SyscallEnterDetails_ftruncate64{ fd, length_ }, retval } ->
      "ftruncate64(" ++ show fd ++ ", " ++ show length_ ++ ") = " ++ show retval

  DetailedSyscallExit_fallocate
    SyscallExitDetails_fallocate{ enterDetail = SyscallEnterDetails_fallocate{ fd, mode, offset, len }, retval } ->
      "fallocate(" ++ show fd ++ ", " ++ show mode ++ ", " ++ show offset ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_chdir
    SyscallExitDetails_chdir{ enterDetail = SyscallEnterDetails_chdir{ filenameBS }, retval } ->
      "chdir(" ++ show filenameBS ++ ") = " ++ show retval

  DetailedSyscallExit_fchdir
    SyscallExitDetails_fchdir{ enterDetail = SyscallEnterDetails_fchdir{ fd }, retval } ->
      "fchdir(" ++ show fd ++ ") = " ++ show retval

  DetailedSyscallExit_chroot
    SyscallExitDetails_chroot{ enterDetail = SyscallEnterDetails_chroot{ filenameBS }, retval } ->
      "chroot(" ++ show filenameBS ++ ") = " ++ show retval

  DetailedSyscallExit_fchmod
    SyscallExitDetails_fchmod{ enterDetail = SyscallEnterDetails_fchmod{ fd, mode }, retval } ->
      "fchmod(" ++ show fd ++ ", " ++ show mode ++ ") = " ++ show retval

  DetailedSyscallExit_fchmodat
    SyscallExitDetails_fchmodat{ enterDetail = SyscallEnterDetails_fchmodat{ dfd, filenameBS, mode }, retval } ->
      "fchmodat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show mode ++ ") = " ++ show retval

  DetailedSyscallExit_chmod
    SyscallExitDetails_chmod{ enterDetail = SyscallEnterDetails_chmod{ filenameBS, mode }, retval } ->
      "chmod(" ++ show filenameBS ++ ", " ++ show mode ++ ") = " ++ show retval

  DetailedSyscallExit_fchownat
    SyscallExitDetails_fchownat{ enterDetail = SyscallEnterDetails_fchownat{ dfd, filenameBS, user, group, flag }, retval } ->
      "fchownat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show user ++ ", " ++ show group ++ ", " ++ show flag ++ ") = " ++ show retval

  DetailedSyscallExit_chown
    SyscallExitDetails_chown{ enterDetail = SyscallEnterDetails_chown{ filenameBS, user, group }, retval } ->
      "chown(" ++ show filenameBS ++ ", " ++ show user ++ ", " ++ show group ++ ") = " ++ show retval

  DetailedSyscallExit_lchown
    SyscallExitDetails_lchown{ enterDetail = SyscallEnterDetails_lchown{ filenameBS, user, group }, retval } ->
      "lchown(" ++ show filenameBS ++ ", " ++ show user ++ ", " ++ show group ++ ") = " ++ show retval

  DetailedSyscallExit_fchown
    SyscallExitDetails_fchown{ enterDetail = SyscallEnterDetails_fchown{ fd, user, group }, retval } ->
      "fchown(" ++ show fd ++ ", " ++ show user ++ ", " ++ show group ++ ") = " ++ show retval

  DetailedSyscallExit_vhangup
    SyscallExitDetails_vhangup{ enterDetail = SyscallEnterDetails_vhangup{  }, retval } ->
      "vhangup() = " ++ show retval

  DetailedSyscallExit_quotactl
    SyscallExitDetails_quotactl{ enterDetail = SyscallEnterDetails_quotactl{ cmd, specialBS, id_, addr }, retval } ->
      "quotactl(" ++ show cmd ++ ", " ++ show specialBS ++ ", " ++ show id_ ++ ", " ++ show addr ++ ") = " ++ show retval

  DetailedSyscallExit_lseek
    SyscallExitDetails_lseek{ enterDetail = SyscallEnterDetails_lseek{ fd, offset, whence }, retval } ->
      "lseek(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show whence ++ ") = " ++ show retval

  DetailedSyscallExit_pread64
    SyscallExitDetails_pread64{ enterDetail = SyscallEnterDetails_pread64{ fd, bufBS, count, pos }, retval } ->
      "pread64(" ++ show fd ++ ", " ++ show bufBS ++ ", " ++ show count ++ ", " ++ show pos ++ ") = " ++ show retval

  DetailedSyscallExit_pwrite64
    SyscallExitDetails_pwrite64{ enterDetail = SyscallEnterDetails_pwrite64{ fd, bufBS, count, pos }, retval } ->
      "pwrite64(" ++ show fd ++ ", " ++ show bufBS ++ ", " ++ show count ++ ", " ++ show pos ++ ") = " ++ show retval

  DetailedSyscallExit_readv
    SyscallExitDetails_readv{ enterDetail = SyscallEnterDetails_readv{ fd, vec, vlen }, retval } ->
      "readv(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ") = " ++ show retval

  DetailedSyscallExit_writev
    SyscallExitDetails_writev{ enterDetail = SyscallEnterDetails_writev{ fd, vec, vlen }, retval } ->
      "writev(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ") = " ++ show retval

  DetailedSyscallExit_preadv
    SyscallExitDetails_preadv{ enterDetail = SyscallEnterDetails_preadv{ fd, vec, vlen, pos_l, pos_h }, retval } ->
      "preadv(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ") = " ++ show retval

  DetailedSyscallExit_preadv2
    SyscallExitDetails_preadv2{ enterDetail = SyscallEnterDetails_preadv2{ fd, vec, vlen, pos_l, pos_h, flags }, retval } ->
      "preadv2(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_pwritev
    SyscallExitDetails_pwritev{ enterDetail = SyscallEnterDetails_pwritev{ fd, vec, vlen, pos_l, pos_h }, retval } ->
      "pwritev(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ") = " ++ show retval

  DetailedSyscallExit_pwritev2
    SyscallExitDetails_pwritev2{ enterDetail = SyscallEnterDetails_pwritev2{ fd, vec, vlen, pos_l, pos_h, flags }, retval } ->
      "pwritev2(" ++ show fd ++ ", " ++ show vec ++ ", " ++ show vlen ++ ", " ++ show pos_l ++ ", " ++ show pos_h ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_sendfile
    SyscallExitDetails_sendfile{ enterDetail = SyscallEnterDetails_sendfile{ out_fd, in_fd, offset, count }, retval } ->
      "sendfile(" ++ show out_fd ++ ", " ++ show in_fd ++ ", " ++ show offset ++ ", " ++ show count ++ ") = " ++ show retval

  DetailedSyscallExit_sendfile64
    SyscallExitDetails_sendfile64{ enterDetail = SyscallEnterDetails_sendfile64{ out_fd, in_fd, offset, count }, retval } ->
      "sendfile64(" ++ show out_fd ++ ", " ++ show in_fd ++ ", " ++ show offset ++ ", " ++ show count ++ ") = " ++ show retval

  DetailedSyscallExit_copy_file_range
    SyscallExitDetails_copy_file_range{ enterDetail = SyscallEnterDetails_copy_file_range{ fd_in, off_in, fd_out, off_out, len, flags }, retval } ->
      "copy_file_range(" ++ show fd_in ++ ", " ++ show off_in ++ ", " ++ show fd_out ++ ", " ++ show off_out ++ ", " ++ show len ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_getdents
    SyscallExitDetails_getdents{ enterDetail = SyscallEnterDetails_getdents{ fd, dirent, count }, retval } ->
      "getdents(" ++ show fd ++ ", " ++ show dirent ++ ", " ++ show count ++ ") = " ++ show retval

  DetailedSyscallExit_getdents64
    SyscallExitDetails_getdents64{ enterDetail = SyscallEnterDetails_getdents64{ fd, dirent, count }, retval } ->
      "getdents64(" ++ show fd ++ ", " ++ show dirent ++ ", " ++ show count ++ ") = " ++ show retval

  DetailedSyscallExit_poll
    SyscallExitDetails_poll{ enterDetail = SyscallEnterDetails_poll{ ufds, nfds, timeout_msecs }, retval } ->
      "poll(" ++ show ufds ++ ", " ++ show nfds ++ ", " ++ show timeout_msecs ++ ") = " ++ show retval

  DetailedSyscallExit_ppoll
    SyscallExitDetails_ppoll{ enterDetail = SyscallEnterDetails_ppoll{ ufds, nfds, tsp, sigmask, sigsetsize }, retval } ->
      "ppoll(" ++ show ufds ++ ", " ++ show nfds ++ ", " ++ show tsp ++ ", " ++ show sigmask ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_signalfd4
    SyscallExitDetails_signalfd4{ enterDetail = SyscallEnterDetails_signalfd4{ ufd, user_mask, sizemask, flags }, retval } ->
      "signalfd4(" ++ show ufd ++ ", " ++ show user_mask ++ ", " ++ show sizemask ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_signalfd
    SyscallExitDetails_signalfd{ enterDetail = SyscallEnterDetails_signalfd{ ufd, user_mask, sizemask }, retval } ->
      "signalfd(" ++ show ufd ++ ", " ++ show user_mask ++ ", " ++ show sizemask ++ ") = " ++ show retval

  DetailedSyscallExit_vmsplice
    SyscallExitDetails_vmsplice{ enterDetail = SyscallEnterDetails_vmsplice{ fd, uiov, nr_segs, flags }, retval } ->
      "vmsplice(" ++ show fd ++ ", " ++ show uiov ++ ", " ++ show nr_segs ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_splice
    SyscallExitDetails_splice{ enterDetail = SyscallEnterDetails_splice{ fd_in, off_in, fd_out, off_out, len, flags }, retval } ->
      "splice(" ++ show fd_in ++ ", " ++ show off_in ++ ", " ++ show fd_out ++ ", " ++ show off_out ++ ", " ++ show len ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_tee
    SyscallExitDetails_tee{ enterDetail = SyscallEnterDetails_tee{ fdin, fdout, len, flags }, retval } ->
      "tee(" ++ show fdin ++ ", " ++ show fdout ++ ", " ++ show len ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_readlinkat
    SyscallExitDetails_readlinkat{ enterDetail = SyscallEnterDetails_readlinkat{ dfd, pathnameBS, bufBS, bufsiz }, retval } ->
      "readlinkat(" ++ show dfd ++ ", " ++ show pathnameBS ++ ", " ++ show bufBS ++ ", " ++ show bufsiz ++ ") = " ++ show retval

  DetailedSyscallExit_readlink
    SyscallExitDetails_readlink{ enterDetail = SyscallEnterDetails_readlink{ pathBS, bufBS, bufsiz }, retval } ->
      "readlink(" ++ show pathBS ++ ", " ++ show bufBS ++ ", " ++ show bufsiz ++ ") = " ++ show retval

  DetailedSyscallExit_stat64
    SyscallExitDetails_stat64{ enterDetail = SyscallEnterDetails_stat64{ filenameBS, statbuf }, retval } ->
      "stat64(" ++ show filenameBS ++ ", " ++ show statbuf ++ ") = " ++ show retval

  DetailedSyscallExit_lstat64
    SyscallExitDetails_lstat64{ enterDetail = SyscallEnterDetails_lstat64{ filenameBS, statbuf }, retval } ->
      "lstat64(" ++ show filenameBS ++ ", " ++ show statbuf ++ ") = " ++ show retval

  DetailedSyscallExit_fstat64
    SyscallExitDetails_fstat64{ enterDetail = SyscallEnterDetails_fstat64{ fd, statbuf }, retval } ->
      "fstat64(" ++ show fd ++ ", " ++ show statbuf ++ ") = " ++ show retval

  DetailedSyscallExit_fstatat64
    SyscallExitDetails_fstatat64{ enterDetail = SyscallEnterDetails_fstatat64{ dfd, filenameBS, statbuf, flag }, retval } ->
      "fstatat64(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show statbuf ++ ", " ++ show flag ++ ") = " ++ show retval

  DetailedSyscallExit_statx
    SyscallExitDetails_statx{ enterDetail = SyscallEnterDetails_statx{ dfd, filenameBS, flags, mask, buffer }, retval } ->
      "statx(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show flags ++ ", " ++ show mask ++ ", " ++ show buffer ++ ") = " ++ show retval

  DetailedSyscallExit_statfs
    SyscallExitDetails_statfs{ enterDetail = SyscallEnterDetails_statfs{ pathnameBS, buf }, retval } ->
      "statfs(" ++ show pathnameBS ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_statfs64
    SyscallExitDetails_statfs64{ enterDetail = SyscallEnterDetails_statfs64{ pathnameBS, sz, buf }, retval } ->
      "statfs64(" ++ show pathnameBS ++ ", " ++ show sz ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_fstatfs
    SyscallExitDetails_fstatfs{ enterDetail = SyscallEnterDetails_fstatfs{ fd, buf }, retval } ->
      "fstatfs(" ++ show fd ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_fstatfs64
    SyscallExitDetails_fstatfs64{ enterDetail = SyscallEnterDetails_fstatfs64{ fd, sz, buf }, retval } ->
      "fstatfs64(" ++ show fd ++ ", " ++ show sz ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_ustat
    SyscallExitDetails_ustat{ enterDetail = SyscallEnterDetails_ustat{ dev, ubuf }, retval } ->
      "ustat(" ++ show dev ++ ", " ++ show ubuf ++ ") = " ++ show retval

  DetailedSyscallExit_sync
    SyscallExitDetails_sync{ enterDetail = SyscallEnterDetails_sync{  }, retval } ->
      "sync() = " ++ show retval

  DetailedSyscallExit_syncfs
    SyscallExitDetails_syncfs{ enterDetail = SyscallEnterDetails_syncfs{ fd }, retval } ->
      "syncfs(" ++ show fd ++ ") = " ++ show retval

  DetailedSyscallExit_fsync
    SyscallExitDetails_fsync{ enterDetail = SyscallEnterDetails_fsync{ fd }, retval } ->
      "fsync(" ++ show fd ++ ") = " ++ show retval

  DetailedSyscallExit_fdatasync
    SyscallExitDetails_fdatasync{ enterDetail = SyscallEnterDetails_fdatasync{ fd }, retval } ->
      "fdatasync(" ++ show fd ++ ") = " ++ show retval

  DetailedSyscallExit_sync_file_range
    SyscallExitDetails_sync_file_range{ enterDetail = SyscallEnterDetails_sync_file_range{ fd, offset, nbytes, flags }, retval } ->
      "sync_file_range(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show nbytes ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_sync_file_range2
    SyscallExitDetails_sync_file_range2{ enterDetail = SyscallEnterDetails_sync_file_range2{ fd, flags, offset, nbytes }, retval } ->
      "sync_file_range2(" ++ show fd ++ ", " ++ show flags ++ ", " ++ show offset ++ ", " ++ show nbytes ++ ") = " ++ show retval

  DetailedSyscallExit_timerfd_create
    SyscallExitDetails_timerfd_create{ enterDetail = SyscallEnterDetails_timerfd_create{ clockid, flags }, retval } ->
      "timerfd_create(" ++ show clockid ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_timerfd_settime
    SyscallExitDetails_timerfd_settime{ enterDetail = SyscallEnterDetails_timerfd_settime{ ufd, flags, utmr, otmr }, retval } ->
      "timerfd_settime(" ++ show ufd ++ ", " ++ show flags ++ ", " ++ show utmr ++ ", " ++ show otmr ++ ") = " ++ show retval

  DetailedSyscallExit_timerfd_gettime
    SyscallExitDetails_timerfd_gettime{ enterDetail = SyscallEnterDetails_timerfd_gettime{ ufd, otmr }, retval } ->
      "timerfd_gettime(" ++ show ufd ++ ", " ++ show otmr ++ ") = " ++ show retval

  DetailedSyscallExit_userfaultfd
    SyscallExitDetails_userfaultfd{ enterDetail = SyscallEnterDetails_userfaultfd{ flags }, retval } ->
      "userfaultfd(" ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_utimensat
    SyscallExitDetails_utimensat{ enterDetail = SyscallEnterDetails_utimensat{ dfd, filenameBS, utimes, flags }, retval } ->
      "utimensat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show utimes ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_futimesat
    SyscallExitDetails_futimesat{ enterDetail = SyscallEnterDetails_futimesat{ dfd, filenameBS, utimes }, retval } ->
      "futimesat(" ++ show dfd ++ ", " ++ show filenameBS ++ ", " ++ show utimes ++ ") = " ++ show retval

  DetailedSyscallExit_utimes
    SyscallExitDetails_utimes{ enterDetail = SyscallEnterDetails_utimes{ filenameBS, utimes }, retval } ->
      "utimes(" ++ show filenameBS ++ ", " ++ show utimes ++ ") = " ++ show retval

  DetailedSyscallExit_utime
    SyscallExitDetails_utime{ enterDetail = SyscallEnterDetails_utime{ filenameBS, times }, retval } ->
      "utime(" ++ show filenameBS ++ ", " ++ show times ++ ") = " ++ show retval

  DetailedSyscallExit_setxattr
    SyscallExitDetails_setxattr{ enterDetail = SyscallEnterDetails_setxattr{ pathnameBS, nameBS, value, size, flags }, retval } ->
      "setxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_lsetxattr
    SyscallExitDetails_lsetxattr{ enterDetail = SyscallEnterDetails_lsetxattr{ pathnameBS, nameBS, value, size, flags }, retval } ->
      "lsetxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_fsetxattr
    SyscallExitDetails_fsetxattr{ enterDetail = SyscallEnterDetails_fsetxattr{ fd, nameBS, value, size, flags }, retval } ->
      "fsetxattr(" ++ show fd ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_getxattr
    SyscallExitDetails_getxattr{ enterDetail = SyscallEnterDetails_getxattr{ pathnameBS, nameBS, value, size }, retval } ->
      "getxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_lgetxattr
    SyscallExitDetails_lgetxattr{ enterDetail = SyscallEnterDetails_lgetxattr{ pathnameBS, nameBS, value, size }, retval } ->
      "lgetxattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_fgetxattr
    SyscallExitDetails_fgetxattr{ enterDetail = SyscallEnterDetails_fgetxattr{ fd, nameBS, value, size }, retval } ->
      "fgetxattr(" ++ show fd ++ ", " ++ show nameBS ++ ", " ++ show value ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_listxattr
    SyscallExitDetails_listxattr{ enterDetail = SyscallEnterDetails_listxattr{ pathnameBS, listBS, size }, retval } ->
      "listxattr(" ++ show pathnameBS ++ ", " ++ show listBS ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_llistxattr
    SyscallExitDetails_llistxattr{ enterDetail = SyscallEnterDetails_llistxattr{ pathnameBS, listBS, size }, retval } ->
      "llistxattr(" ++ show pathnameBS ++ ", " ++ show listBS ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_flistxattr
    SyscallExitDetails_flistxattr{ enterDetail = SyscallEnterDetails_flistxattr{ fd, listBS, size }, retval } ->
      "flistxattr(" ++ show fd ++ ", " ++ show listBS ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_removexattr
    SyscallExitDetails_removexattr{ enterDetail = SyscallEnterDetails_removexattr{ pathnameBS, nameBS }, retval } ->
      "removexattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ") = " ++ show retval

  DetailedSyscallExit_lremovexattr
    SyscallExitDetails_lremovexattr{ enterDetail = SyscallEnterDetails_lremovexattr{ pathnameBS, nameBS }, retval } ->
      "lremovexattr(" ++ show pathnameBS ++ ", " ++ show nameBS ++ ") = " ++ show retval

  DetailedSyscallExit_fremovexattr
    SyscallExitDetails_fremovexattr{ enterDetail = SyscallEnterDetails_fremovexattr{ fd, nameBS }, retval } ->
      "fremovexattr(" ++ show fd ++ ", " ++ show nameBS ++ ") = " ++ show retval

  DetailedSyscallExit_msgget
    SyscallExitDetails_msgget{ enterDetail = SyscallEnterDetails_msgget{ key, msgflg }, retval } ->
      "msgget(" ++ show key ++ ", " ++ show msgflg ++ ") = " ++ show retval

  DetailedSyscallExit_msgctl
    SyscallExitDetails_msgctl{ enterDetail = SyscallEnterDetails_msgctl{ msqid, cmd, buf }, retval } ->
      "msgctl(" ++ show msqid ++ ", " ++ show cmd ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_msgsnd
    SyscallExitDetails_msgsnd{ enterDetail = SyscallEnterDetails_msgsnd{ msqid, msgp, msgsz, msgflg }, retval } ->
      "msgsnd(" ++ show msqid ++ ", " ++ show msgp ++ ", " ++ show msgsz ++ ", " ++ show msgflg ++ ") = " ++ show retval

  DetailedSyscallExit_msgrcv
    SyscallExitDetails_msgrcv{ enterDetail = SyscallEnterDetails_msgrcv{ msqid, msgp, msgsz, msgtyp, msgflg }, retval } ->
      "msgrcv(" ++ show msqid ++ ", " ++ show msgp ++ ", " ++ show msgsz ++ ", " ++ show msgtyp ++ ", " ++ show msgflg ++ ") = " ++ show retval

  DetailedSyscallExit_semget
    SyscallExitDetails_semget{ enterDetail = SyscallEnterDetails_semget{ key, nsems, semflg }, retval } ->
      "semget(" ++ show key ++ ", " ++ show nsems ++ ", " ++ show semflg ++ ") = " ++ show retval

  DetailedSyscallExit_semctl
    SyscallExitDetails_semctl{ enterDetail = SyscallEnterDetails_semctl{ semid, semnum, cmd, arg }, retval } ->
      "semctl(" ++ show semid ++ ", " ++ show semnum ++ ", " ++ show cmd ++ ", " ++ show arg ++ ") = " ++ show retval

  DetailedSyscallExit_semtimedop
    SyscallExitDetails_semtimedop{ enterDetail = SyscallEnterDetails_semtimedop{ semid, tsops, nsops, timeout }, retval } ->
      "semtimedop(" ++ show semid ++ ", " ++ show tsops ++ ", " ++ show nsops ++ ", " ++ show timeout ++ ") = " ++ show retval

  DetailedSyscallExit_semop
    SyscallExitDetails_semop{ enterDetail = SyscallEnterDetails_semop{ semid, tsops, nsops }, retval } ->
      "semop(" ++ show semid ++ ", " ++ show tsops ++ ", " ++ show nsops ++ ") = " ++ show retval

  DetailedSyscallExit_shmget
    SyscallExitDetails_shmget{ enterDetail = SyscallEnterDetails_shmget{ key, size, shmflg }, retval } ->
      "shmget(" ++ show key ++ ", " ++ show size ++ ", " ++ show shmflg ++ ") = " ++ show retval

  DetailedSyscallExit_shmctl
    SyscallExitDetails_shmctl{ enterDetail = SyscallEnterDetails_shmctl{ shmid, cmd, buf }, retval } ->
      "shmctl(" ++ show shmid ++ ", " ++ show cmd ++ ", " ++ show buf ++ ") = " ++ show retval

  DetailedSyscallExit_shmat
    SyscallExitDetails_shmat{ enterDetail = SyscallEnterDetails_shmat{ shmid, shmaddrBS, shmflg }, retval } ->
      "shmat(" ++ show shmid ++ ", " ++ show shmaddrBS ++ ", " ++ show shmflg ++ ") = " ++ show retval

  DetailedSyscallExit_shmdt
    SyscallExitDetails_shmdt{ enterDetail = SyscallEnterDetails_shmdt{ shmaddrBS }, retval } ->
      "shmdt(" ++ show shmaddrBS ++ ") = " ++ show retval

  DetailedSyscallExit_ipc
    SyscallExitDetails_ipc{ enterDetail = SyscallEnterDetails_ipc{ call, first_, second_, third, ptr, fifth }, retval } ->
      "ipc(" ++ show call ++ ", " ++ show first_ ++ ", " ++ show second_ ++ ", " ++ show third ++ ", " ++ show ptr ++ ", " ++ show fifth ++ ") = " ++ show retval

  DetailedSyscallExit_acct
    SyscallExitDetails_acct{ enterDetail = SyscallEnterDetails_acct{ nameBS }, retval } ->
      "acct(" ++ show nameBS ++ ") = " ++ show retval

  DetailedSyscallExit_perf_event_open
    SyscallExitDetails_perf_event_open{ enterDetail = SyscallEnterDetails_perf_event_open{ attr_uptr, pid_, cpu, group_fd, flags }, retval } ->
      "perf_event_open(" ++ show attr_uptr ++ ", " ++ show pid_ ++ ", " ++ show cpu ++ ", " ++ show group_fd ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_personality
    SyscallExitDetails_personality{ enterDetail = SyscallEnterDetails_personality{ personality }, retval } ->
      "personality(" ++ show personality ++ ") = " ++ show retval

  DetailedSyscallExit_waitid
    SyscallExitDetails_waitid{ enterDetail = SyscallEnterDetails_waitid{ which, upid, infop, options, ru }, retval } ->
      "waitid(" ++ show which ++ ", " ++ show upid ++ ", " ++ show infop ++ ", " ++ show options ++ ", " ++ show ru ++ ") = " ++ show retval

  DetailedSyscallExit_wait4
    SyscallExitDetails_wait4{ enterDetail = SyscallEnterDetails_wait4{ upid, stat_addr, options, ru }, retval } ->
      "wait4(" ++ show upid ++ ", " ++ show stat_addr ++ ", " ++ show options ++ ", " ++ show ru ++ ") = " ++ show retval

  DetailedSyscallExit_waitpid
    SyscallExitDetails_waitpid{ enterDetail = SyscallEnterDetails_waitpid{ pid_, stat_addr, options }, retval } ->
      "waitpid(" ++ show pid_ ++ ", " ++ show stat_addr ++ ", " ++ show options ++ ") = " ++ show retval

  DetailedSyscallExit_set_tid_address
    SyscallExitDetails_set_tid_address{ enterDetail = SyscallEnterDetails_set_tid_address{ tidptr }, retval } ->
      "set_tid_address(" ++ show tidptr ++ ") = " ++ show retval

  DetailedSyscallExit_fork
    SyscallExitDetails_fork{ enterDetail = SyscallEnterDetails_fork{  }, retval } ->
      "fork() = " ++ show retval

  DetailedSyscallExit_vfork
    SyscallExitDetails_vfork{ enterDetail = SyscallEnterDetails_vfork{  }, retval } ->
      "vfork() = " ++ show retval

  DetailedSyscallExit_clone
    SyscallExitDetails_clone{ enterDetail = SyscallEnterDetails_clone{ clone_flags, newsp, parent_tidptr, child_tidptr, tls }, retval } ->
      "clone(" ++ show clone_flags ++ ", " ++ show newsp ++ ", " ++ show parent_tidptr ++ ", " ++ show child_tidptr ++ ", " ++ show tls ++ ") = " ++ show retval

  DetailedSyscallExit_unshare
    SyscallExitDetails_unshare{ enterDetail = SyscallEnterDetails_unshare{ unshare_flags }, retval } ->
      "unshare(" ++ show unshare_flags ++ ") = " ++ show retval

  DetailedSyscallExit_set_robust_list
    SyscallExitDetails_set_robust_list{ enterDetail = SyscallEnterDetails_set_robust_list{ head_, len }, retval } ->
      "set_robust_list(" ++ show head_ ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_get_robust_list
    SyscallExitDetails_get_robust_list{ enterDetail = SyscallEnterDetails_get_robust_list{ pid_, head_ptr, len_ptr }, retval } ->
      "get_robust_list(" ++ show pid_ ++ ", " ++ show head_ptr ++ ", " ++ show len_ptr ++ ") = " ++ show retval

  DetailedSyscallExit_futex
    SyscallExitDetails_futex{ enterDetail = SyscallEnterDetails_futex{ uaddr, op, val, utime, uaddr2, val3 }, retval } ->
      "futex(" ++ show uaddr ++ ", " ++ show op ++ ", " ++ show val ++ ", " ++ show utime ++ ", " ++ show uaddr2 ++ ", " ++ show val3 ++ ") = " ++ show retval

  DetailedSyscallExit_getgroups
    SyscallExitDetails_getgroups{ enterDetail = SyscallEnterDetails_getgroups{ gidsetsize, grouplist }, retval } ->
      "getgroups(" ++ show gidsetsize ++ ", " ++ show grouplist ++ ") = " ++ show retval

  DetailedSyscallExit_setgroups
    SyscallExitDetails_setgroups{ enterDetail = SyscallEnterDetails_setgroups{ gidsetsize, grouplist }, retval } ->
      "setgroups(" ++ show gidsetsize ++ ", " ++ show grouplist ++ ") = " ++ show retval

  DetailedSyscallExit_kcmp
    SyscallExitDetails_kcmp{ enterDetail = SyscallEnterDetails_kcmp{ pid1, pid2, type_, idx1, idx2 }, retval } ->
      "kcmp(" ++ show pid1 ++ ", " ++ show pid2 ++ ", " ++ show type_ ++ ", " ++ show idx1 ++ ", " ++ show idx2 ++ ") = " ++ show retval

  DetailedSyscallExit_kexec_load
    SyscallExitDetails_kexec_load{ enterDetail = SyscallEnterDetails_kexec_load{ entry, nr_segments, segments, flags }, retval } ->
      "kexec_load(" ++ show entry ++ ", " ++ show nr_segments ++ ", " ++ show segments ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_kexec_file_load
    SyscallExitDetails_kexec_file_load{ enterDetail = SyscallEnterDetails_kexec_file_load{ kernel_fd, initrd_fd, cmdline_len, cmdline_ptrBS, flags }, retval } ->
      "kexec_file_load(" ++ show kernel_fd ++ ", " ++ show initrd_fd ++ ", " ++ show cmdline_len ++ ", " ++ show cmdline_ptrBS ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_delete_module
    SyscallExitDetails_delete_module{ enterDetail = SyscallEnterDetails_delete_module{ name_userBS, flags }, retval } ->
      "delete_module(" ++ show name_userBS ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_init_module
    SyscallExitDetails_init_module{ enterDetail = SyscallEnterDetails_init_module{ umod, len, uargsBS }, retval } ->
      "init_module(" ++ show umod ++ ", " ++ show len ++ ", " ++ show uargsBS ++ ") = " ++ show retval

  DetailedSyscallExit_finit_module
    SyscallExitDetails_finit_module{ enterDetail = SyscallEnterDetails_finit_module{ fd, uargsBS, flags }, retval } ->
      "finit_module(" ++ show fd ++ ", " ++ show uargsBS ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_setns
    SyscallExitDetails_setns{ enterDetail = SyscallEnterDetails_setns{ fd, nstype }, retval } ->
      "setns(" ++ show fd ++ ", " ++ show nstype ++ ") = " ++ show retval

  DetailedSyscallExit_syslog
    SyscallExitDetails_syslog{ enterDetail = SyscallEnterDetails_syslog{ type_, bufBS, len }, retval } ->
      "syslog(" ++ show type_ ++ ", " ++ show bufBS ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_ptrace
    SyscallExitDetails_ptrace{ enterDetail = SyscallEnterDetails_ptrace{ request, pid_, addr, data_ }, retval } ->
      "ptrace(" ++ show request ++ ", " ++ show pid_ ++ ", " ++ show addr ++ ", " ++ show data_ ++ ") = " ++ show retval

  DetailedSyscallExit_reboot
    SyscallExitDetails_reboot{ enterDetail = SyscallEnterDetails_reboot{ magic1, magic2, cmd, arg }, retval } ->
      "reboot(" ++ show magic1 ++ ", " ++ show magic2 ++ ", " ++ show cmd ++ ", " ++ show arg ++ ") = " ++ show retval

  DetailedSyscallExit_rseq
    SyscallExitDetails_rseq{ enterDetail = SyscallEnterDetails_rseq{ rseq, rseq_len, flags, sig }, retval } ->
      "rseq(" ++ show rseq ++ ", " ++ show rseq_len ++ ", " ++ show flags ++ ", " ++ show sig ++ ") = " ++ show retval

  DetailedSyscallExit_nice
    SyscallExitDetails_nice{ enterDetail = SyscallEnterDetails_nice{ increment }, retval } ->
      "nice(" ++ show increment ++ ") = " ++ show retval

  DetailedSyscallExit_sched_setscheduler
    SyscallExitDetails_sched_setscheduler{ enterDetail = SyscallEnterDetails_sched_setscheduler{ pid_, policy, param }, retval } ->
      "sched_setscheduler(" ++ show pid_ ++ ", " ++ show policy ++ ", " ++ show param ++ ") = " ++ show retval

  DetailedSyscallExit_sched_setparam
    SyscallExitDetails_sched_setparam{ enterDetail = SyscallEnterDetails_sched_setparam{ pid_, param }, retval } ->
      "sched_setparam(" ++ show pid_ ++ ", " ++ show param ++ ") = " ++ show retval

  DetailedSyscallExit_sched_setattr
    SyscallExitDetails_sched_setattr{ enterDetail = SyscallEnterDetails_sched_setattr{ pid_, uattr, flags }, retval } ->
      "sched_setattr(" ++ show pid_ ++ ", " ++ show uattr ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_sched_getscheduler
    SyscallExitDetails_sched_getscheduler{ enterDetail = SyscallEnterDetails_sched_getscheduler{ pid_ }, retval } ->
      "sched_getscheduler(" ++ show pid_ ++ ") = " ++ show retval

  DetailedSyscallExit_sched_getparam
    SyscallExitDetails_sched_getparam{ enterDetail = SyscallEnterDetails_sched_getparam{ pid_, param }, retval } ->
      "sched_getparam(" ++ show pid_ ++ ", " ++ show param ++ ") = " ++ show retval

  DetailedSyscallExit_sched_getattr
    SyscallExitDetails_sched_getattr{ enterDetail = SyscallEnterDetails_sched_getattr{ pid_, uattr, size, flags }, retval } ->
      "sched_getattr(" ++ show pid_ ++ ", " ++ show uattr ++ ", " ++ show size ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_sched_setaffinity
    SyscallExitDetails_sched_setaffinity{ enterDetail = SyscallEnterDetails_sched_setaffinity{ pid_, len, user_mask_ptr }, retval } ->
      "sched_setaffinity(" ++ show pid_ ++ ", " ++ show len ++ ", " ++ show user_mask_ptr ++ ") = " ++ show retval

  DetailedSyscallExit_sched_getaffinity
    SyscallExitDetails_sched_getaffinity{ enterDetail = SyscallEnterDetails_sched_getaffinity{ pid_, len, user_mask_ptr }, retval } ->
      "sched_getaffinity(" ++ show pid_ ++ ", " ++ show len ++ ", " ++ show user_mask_ptr ++ ") = " ++ show retval

  DetailedSyscallExit_sched_yield
    SyscallExitDetails_sched_yield{ enterDetail = SyscallEnterDetails_sched_yield{  }, retval } ->
      "sched_yield() = " ++ show retval

  DetailedSyscallExit_sched_get_priority_max
    SyscallExitDetails_sched_get_priority_max{ enterDetail = SyscallEnterDetails_sched_get_priority_max{ policy }, retval } ->
      "sched_get_priority_max(" ++ show policy ++ ") = " ++ show retval

  DetailedSyscallExit_sched_get_priority_min
    SyscallExitDetails_sched_get_priority_min{ enterDetail = SyscallEnterDetails_sched_get_priority_min{ policy }, retval } ->
      "sched_get_priority_min(" ++ show policy ++ ") = " ++ show retval

  DetailedSyscallExit_sched_rr_get_interval
    SyscallExitDetails_sched_rr_get_interval{ enterDetail = SyscallEnterDetails_sched_rr_get_interval{ pid_, interval }, retval } ->
      "sched_rr_get_interval(" ++ show pid_ ++ ", " ++ show interval ++ ") = " ++ show retval

  DetailedSyscallExit_membarrier
    SyscallExitDetails_membarrier{ enterDetail = SyscallEnterDetails_membarrier{ cmd, flags }, retval } ->
      "membarrier(" ++ show cmd ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_seccomp
    SyscallExitDetails_seccomp{ enterDetail = SyscallEnterDetails_seccomp{ op, flags, uargs }, retval } ->
      "seccomp(" ++ show op ++ ", " ++ show flags ++ ", " ++ show uargs ++ ") = " ++ show retval

  DetailedSyscallExit_restart_syscall
    SyscallExitDetails_restart_syscall{ enterDetail = SyscallEnterDetails_restart_syscall{  }, retval } ->
      "restart_syscall() = " ++ show retval

  DetailedSyscallExit_rt_sigprocmask
    SyscallExitDetails_rt_sigprocmask{ enterDetail = SyscallEnterDetails_rt_sigprocmask{ how, nset, oset, sigsetsize }, retval } ->
      "rt_sigprocmask(" ++ show how ++ ", " ++ show nset ++ ", " ++ show oset ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_rt_sigpending
    SyscallExitDetails_rt_sigpending{ enterDetail = SyscallEnterDetails_rt_sigpending{ uset, sigsetsize }, retval } ->
      "rt_sigpending(" ++ show uset ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_kill
    SyscallExitDetails_kill{ enterDetail = SyscallEnterDetails_kill{ pid_, sig }, retval } ->
      "kill(" ++ show pid_ ++ ", " ++ show sig ++ ") = " ++ show retval

  DetailedSyscallExit_tgkill
    SyscallExitDetails_tgkill{ enterDetail = SyscallEnterDetails_tgkill{ tgid, pid_, sig }, retval } ->
      "tgkill(" ++ show tgid ++ ", " ++ show pid_ ++ ", " ++ show sig ++ ") = " ++ show retval

  DetailedSyscallExit_tkill
    SyscallExitDetails_tkill{ enterDetail = SyscallEnterDetails_tkill{ pid_, sig }, retval } ->
      "tkill(" ++ show pid_ ++ ", " ++ show sig ++ ") = " ++ show retval

  DetailedSyscallExit_sigpending
    SyscallExitDetails_sigpending{ enterDetail = SyscallEnterDetails_sigpending{ uset }, retval } ->
      "sigpending(" ++ show uset ++ ") = " ++ show retval

  DetailedSyscallExit_sigprocmask
    SyscallExitDetails_sigprocmask{ enterDetail = SyscallEnterDetails_sigprocmask{ how, nset, oset }, retval } ->
      "sigprocmask(" ++ show how ++ ", " ++ show nset ++ ", " ++ show oset ++ ") = " ++ show retval

  DetailedSyscallExit_rt_sigaction
    SyscallExitDetails_rt_sigaction{ enterDetail = SyscallEnterDetails_rt_sigaction{ sig, act, oact, sigsetsize }, retval } ->
      "rt_sigaction(" ++ show sig ++ ", " ++ show act ++ ", " ++ show oact ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_sigaction
    SyscallExitDetails_sigaction{ enterDetail = SyscallEnterDetails_sigaction{ sig, act, oact }, retval } ->
      "sigaction(" ++ show sig ++ ", " ++ show act ++ ", " ++ show oact ++ ") = " ++ show retval

  DetailedSyscallExit_sgetmask
    SyscallExitDetails_sgetmask{ enterDetail = SyscallEnterDetails_sgetmask{  }, retval } ->
      "sgetmask() = " ++ show retval

  DetailedSyscallExit_ssetmask
    SyscallExitDetails_ssetmask{ enterDetail = SyscallEnterDetails_ssetmask{ newmask }, retval } ->
      "ssetmask(" ++ show newmask ++ ") = " ++ show retval

  DetailedSyscallExit_signal
    SyscallExitDetails_signal{ enterDetail = SyscallEnterDetails_signal{ sig, handler }, retval } ->
      "signal(" ++ show sig ++ ", " ++ show handler ++ ") = " ++ show retval

  DetailedSyscallExit_pause
    SyscallExitDetails_pause{ enterDetail = SyscallEnterDetails_pause{  }, retval } ->
      "pause() = " ++ show retval

  DetailedSyscallExit_rt_sigsuspend
    SyscallExitDetails_rt_sigsuspend{ enterDetail = SyscallEnterDetails_rt_sigsuspend{ unewset, sigsetsize }, retval } ->
      "rt_sigsuspend(" ++ show unewset ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_sigsuspend
    SyscallExitDetails_sigsuspend{ enterDetail = SyscallEnterDetails_sigsuspend{ mask }, retval } ->
      "sigsuspend(" ++ show mask ++ ") = " ++ show retval

  DetailedSyscallExit_setpriority
    SyscallExitDetails_setpriority{ enterDetail = SyscallEnterDetails_setpriority{ which, who, niceval }, retval } ->
      "setpriority(" ++ show which ++ ", " ++ show who ++ ", " ++ show niceval ++ ") = " ++ show retval

  DetailedSyscallExit_getpriority
    SyscallExitDetails_getpriority{ enterDetail = SyscallEnterDetails_getpriority{ which, who }, retval } ->
      "getpriority(" ++ show which ++ ", " ++ show who ++ ") = " ++ show retval

  DetailedSyscallExit_setregid
    SyscallExitDetails_setregid{ enterDetail = SyscallEnterDetails_setregid{ rgid, egid }, retval } ->
      "setregid(" ++ show rgid ++ ", " ++ show egid ++ ") = " ++ show retval

  DetailedSyscallExit_setgid
    SyscallExitDetails_setgid{ enterDetail = SyscallEnterDetails_setgid{ gid }, retval } ->
      "setgid(" ++ show gid ++ ") = " ++ show retval

  DetailedSyscallExit_setreuid
    SyscallExitDetails_setreuid{ enterDetail = SyscallEnterDetails_setreuid{ ruid, euid }, retval } ->
      "setreuid(" ++ show ruid ++ ", " ++ show euid ++ ") = " ++ show retval

  DetailedSyscallExit_setuid
    SyscallExitDetails_setuid{ enterDetail = SyscallEnterDetails_setuid{ uid }, retval } ->
      "setuid(" ++ show uid ++ ") = " ++ show retval

  DetailedSyscallExit_setresuid
    SyscallExitDetails_setresuid{ enterDetail = SyscallEnterDetails_setresuid{ ruid, euid, suid }, retval } ->
      "setresuid(" ++ show ruid ++ ", " ++ show euid ++ ", " ++ show suid ++ ") = " ++ show retval

  DetailedSyscallExit_getresuid
    SyscallExitDetails_getresuid{ enterDetail = SyscallEnterDetails_getresuid{ ruidp, euidp, suidp }, retval } ->
      "getresuid(" ++ show ruidp ++ ", " ++ show euidp ++ ", " ++ show suidp ++ ") = " ++ show retval

  DetailedSyscallExit_setresgid
    SyscallExitDetails_setresgid{ enterDetail = SyscallEnterDetails_setresgid{ rgid, egid, sgid }, retval } ->
      "setresgid(" ++ show rgid ++ ", " ++ show egid ++ ", " ++ show sgid ++ ") = " ++ show retval

  DetailedSyscallExit_getresgid
    SyscallExitDetails_getresgid{ enterDetail = SyscallEnterDetails_getresgid{ rgidp, egidp, sgidp }, retval } ->
      "getresgid(" ++ show rgidp ++ ", " ++ show egidp ++ ", " ++ show sgidp ++ ") = " ++ show retval

  DetailedSyscallExit_setfsuid
    SyscallExitDetails_setfsuid{ enterDetail = SyscallEnterDetails_setfsuid{ uid }, retval } ->
      "setfsuid(" ++ show uid ++ ") = " ++ show retval

  DetailedSyscallExit_setfsgid
    SyscallExitDetails_setfsgid{ enterDetail = SyscallEnterDetails_setfsgid{ gid }, retval } ->
      "setfsgid(" ++ show gid ++ ") = " ++ show retval

  DetailedSyscallExit_getpid
    SyscallExitDetails_getpid{ enterDetail = SyscallEnterDetails_getpid{  }, retval } ->
      "getpid() = " ++ show retval

  DetailedSyscallExit_gettid
    SyscallExitDetails_gettid{ enterDetail = SyscallEnterDetails_gettid{  }, retval } ->
      "gettid() = " ++ show retval

  DetailedSyscallExit_getppid
    SyscallExitDetails_getppid{ enterDetail = SyscallEnterDetails_getppid{  }, retval } ->
      "getppid() = " ++ show retval

  DetailedSyscallExit_getuid
    SyscallExitDetails_getuid{ enterDetail = SyscallEnterDetails_getuid{  }, retval } ->
      "getuid() = " ++ show retval

  DetailedSyscallExit_geteuid
    SyscallExitDetails_geteuid{ enterDetail = SyscallEnterDetails_geteuid{  }, retval } ->
      "geteuid() = " ++ show retval

  DetailedSyscallExit_getgid
    SyscallExitDetails_getgid{ enterDetail = SyscallEnterDetails_getgid{  }, retval } ->
      "getgid() = " ++ show retval

  DetailedSyscallExit_getegid
    SyscallExitDetails_getegid{ enterDetail = SyscallEnterDetails_getegid{  }, retval } ->
      "getegid() = " ++ show retval

  DetailedSyscallExit_times
    SyscallExitDetails_times{ enterDetail = SyscallEnterDetails_times{ tbuf }, retval } ->
      "times(" ++ show tbuf ++ ") = " ++ show retval

  DetailedSyscallExit_setpgid
    SyscallExitDetails_setpgid{ enterDetail = SyscallEnterDetails_setpgid{ pid_, pgid }, retval } ->
      "setpgid(" ++ show pid_ ++ ", " ++ show pgid ++ ") = " ++ show retval

  DetailedSyscallExit_getpgid
    SyscallExitDetails_getpgid{ enterDetail = SyscallEnterDetails_getpgid{ pid_ }, retval } ->
      "getpgid(" ++ show pid_ ++ ") = " ++ show retval

  DetailedSyscallExit_getpgrp
    SyscallExitDetails_getpgrp{ enterDetail = SyscallEnterDetails_getpgrp{  }, retval } ->
      "getpgrp() = " ++ show retval

  DetailedSyscallExit_getsid
    SyscallExitDetails_getsid{ enterDetail = SyscallEnterDetails_getsid{ pid_ }, retval } ->
      "getsid(" ++ show pid_ ++ ") = " ++ show retval

  DetailedSyscallExit_setsid
    SyscallExitDetails_setsid{ enterDetail = SyscallEnterDetails_setsid{  }, retval } ->
      "setsid() = " ++ show retval

  DetailedSyscallExit_uname
    SyscallExitDetails_uname{ enterDetail = SyscallEnterDetails_uname{ name }, retval } ->
      "uname(" ++ show name ++ ") = " ++ show retval

  DetailedSyscallExit_olduname
    SyscallExitDetails_olduname{ enterDetail = SyscallEnterDetails_olduname{ name }, retval } ->
      "olduname(" ++ show name ++ ") = " ++ show retval

  DetailedSyscallExit_sethostname
    SyscallExitDetails_sethostname{ enterDetail = SyscallEnterDetails_sethostname{ nameBS, len }, retval } ->
      "sethostname(" ++ show nameBS ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_gethostname
    SyscallExitDetails_gethostname{ enterDetail = SyscallEnterDetails_gethostname{ nameBS, len }, retval } ->
      "gethostname(" ++ show nameBS ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_setdomainname
    SyscallExitDetails_setdomainname{ enterDetail = SyscallEnterDetails_setdomainname{ nameBS, len }, retval } ->
      "setdomainname(" ++ show nameBS ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_getrlimit
    SyscallExitDetails_getrlimit{ enterDetail = SyscallEnterDetails_getrlimit{ resource, rlim }, retval } ->
      "getrlimit(" ++ show resource ++ ", " ++ show rlim ++ ") = " ++ show retval

  DetailedSyscallExit_prlimit64
    SyscallExitDetails_prlimit64{ enterDetail = SyscallEnterDetails_prlimit64{ pid_, resource, new_rlim, old_rlim }, retval } ->
      "prlimit64(" ++ show pid_ ++ ", " ++ show resource ++ ", " ++ show new_rlim ++ ", " ++ show old_rlim ++ ") = " ++ show retval

  DetailedSyscallExit_setrlimit
    SyscallExitDetails_setrlimit{ enterDetail = SyscallEnterDetails_setrlimit{ resource, rlim }, retval } ->
      "setrlimit(" ++ show resource ++ ", " ++ show rlim ++ ") = " ++ show retval

  DetailedSyscallExit_getrusage
    SyscallExitDetails_getrusage{ enterDetail = SyscallEnterDetails_getrusage{ who, ru }, retval } ->
      "getrusage(" ++ show who ++ ", " ++ show ru ++ ") = " ++ show retval

  DetailedSyscallExit_umask
    SyscallExitDetails_umask{ enterDetail = SyscallEnterDetails_umask{ mask }, retval } ->
      "umask(" ++ show mask ++ ") = " ++ show retval

  DetailedSyscallExit_prctl
    SyscallExitDetails_prctl{ enterDetail = SyscallEnterDetails_prctl{ option, arg2, arg3, arg4, arg5 }, retval } ->
      "prctl(" ++ show option ++ ", " ++ show arg2 ++ ", " ++ show arg3 ++ ", " ++ show arg4 ++ ", " ++ show arg5 ++ ") = " ++ show retval

  DetailedSyscallExit_getcpu
    SyscallExitDetails_getcpu{ enterDetail = SyscallEnterDetails_getcpu{ cpup, nodep, unused }, retval } ->
      "getcpu(" ++ show cpup ++ ", " ++ show nodep ++ ", " ++ show unused ++ ") = " ++ show retval

  DetailedSyscallExit_sysinfo
    SyscallExitDetails_sysinfo{ enterDetail = SyscallEnterDetails_sysinfo{ info }, retval } ->
      "sysinfo(" ++ show info ++ ") = " ++ show retval

  DetailedSyscallExit_nanosleep
    SyscallExitDetails_nanosleep{ enterDetail = SyscallEnterDetails_nanosleep{ rqtp, rmtp }, retval } ->
      "nanosleep(" ++ show rqtp ++ ", " ++ show rmtp ++ ") = " ++ show retval

  DetailedSyscallExit_getitimer
    SyscallExitDetails_getitimer{ enterDetail = SyscallEnterDetails_getitimer{ which, value }, retval } ->
      "getitimer(" ++ show which ++ ", " ++ show value ++ ") = " ++ show retval

  DetailedSyscallExit_alarm
    SyscallExitDetails_alarm{ enterDetail = SyscallEnterDetails_alarm{ seconds }, retval } ->
      "alarm(" ++ show seconds ++ ") = " ++ show retval

  DetailedSyscallExit_setitimer
    SyscallExitDetails_setitimer{ enterDetail = SyscallEnterDetails_setitimer{ which, value, ovalue }, retval } ->
      "setitimer(" ++ show which ++ ", " ++ show value ++ ", " ++ show ovalue ++ ") = " ++ show retval

  DetailedSyscallExit_clock_settime
    SyscallExitDetails_clock_settime{ enterDetail = SyscallEnterDetails_clock_settime{ which_clock, tp }, retval } ->
      "clock_settime(" ++ show which_clock ++ ", " ++ show tp ++ ") = " ++ show retval

  DetailedSyscallExit_clock_gettime
    SyscallExitDetails_clock_gettime{ enterDetail = SyscallEnterDetails_clock_gettime{ which_clock, tp }, retval } ->
      "clock_gettime(" ++ show which_clock ++ ", " ++ show tp ++ ") = " ++ show retval

  DetailedSyscallExit_clock_getres
    SyscallExitDetails_clock_getres{ enterDetail = SyscallEnterDetails_clock_getres{ which_clock, tp }, retval } ->
      "clock_getres(" ++ show which_clock ++ ", " ++ show tp ++ ") = " ++ show retval

  DetailedSyscallExit_clock_nanosleep
    SyscallExitDetails_clock_nanosleep{ enterDetail = SyscallEnterDetails_clock_nanosleep{ which_clock, flags, rqtp, rmtp }, retval } ->
      "clock_nanosleep(" ++ show which_clock ++ ", " ++ show flags ++ ", " ++ show rqtp ++ ", " ++ show rmtp ++ ") = " ++ show retval

  DetailedSyscallExit_timer_create
    SyscallExitDetails_timer_create{ enterDetail = SyscallEnterDetails_timer_create{ which_clock, timer_event_spec, created_timer_id }, retval } ->
      "timer_create(" ++ show which_clock ++ ", " ++ show timer_event_spec ++ ", " ++ show created_timer_id ++ ") = " ++ show retval

  DetailedSyscallExit_timer_gettime
    SyscallExitDetails_timer_gettime{ enterDetail = SyscallEnterDetails_timer_gettime{ timer_id, setting }, retval } ->
      "timer_gettime(" ++ show timer_id ++ ", " ++ show setting ++ ") = " ++ show retval

  DetailedSyscallExit_timer_getoverrun
    SyscallExitDetails_timer_getoverrun{ enterDetail = SyscallEnterDetails_timer_getoverrun{ timer_id }, retval } ->
      "timer_getoverrun(" ++ show timer_id ++ ") = " ++ show retval

  DetailedSyscallExit_timer_settime
    SyscallExitDetails_timer_settime{ enterDetail = SyscallEnterDetails_timer_settime{ timer_id, flags, new_setting, old_setting }, retval } ->
      "timer_settime(" ++ show timer_id ++ ", " ++ show flags ++ ", " ++ show new_setting ++ ", " ++ show old_setting ++ ") = " ++ show retval

  DetailedSyscallExit_timer_delete
    SyscallExitDetails_timer_delete{ enterDetail = SyscallEnterDetails_timer_delete{ timer_id }, retval } ->
      "timer_delete(" ++ show timer_id ++ ") = " ++ show retval

  DetailedSyscallExit_clock_adjtime
    SyscallExitDetails_clock_adjtime{ enterDetail = SyscallEnterDetails_clock_adjtime{ which_clock, utx }, retval } ->
      "clock_adjtime(" ++ show which_clock ++ ", " ++ show utx ++ ") = " ++ show retval

  DetailedSyscallExit_time
    SyscallExitDetails_time{ enterDetail = SyscallEnterDetails_time{ tloc }, retval } ->
      "time(" ++ show tloc ++ ") = " ++ show retval

  DetailedSyscallExit_stime
    SyscallExitDetails_stime{ enterDetail = SyscallEnterDetails_stime{ tptr }, retval } ->
      "stime(" ++ show tptr ++ ") = " ++ show retval

  DetailedSyscallExit_gettimeofday
    SyscallExitDetails_gettimeofday{ enterDetail = SyscallEnterDetails_gettimeofday{ tv, tz }, retval } ->
      "gettimeofday(" ++ show tv ++ ", " ++ show tz ++ ") = " ++ show retval

  DetailedSyscallExit_settimeofday
    SyscallExitDetails_settimeofday{ enterDetail = SyscallEnterDetails_settimeofday{ tv, tz }, retval } ->
      "settimeofday(" ++ show tv ++ ", " ++ show tz ++ ") = " ++ show retval

  DetailedSyscallExit_adjtimex
    SyscallExitDetails_adjtimex{ enterDetail = SyscallEnterDetails_adjtimex{ txc_p }, retval } ->
      "adjtimex(" ++ show txc_p ++ ") = " ++ show retval

  DetailedSyscallExit_fadvise64_64
    SyscallExitDetails_fadvise64_64{ enterDetail = SyscallEnterDetails_fadvise64_64{ fd, offset, len, advice }, retval } ->
      "fadvise64_64(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show len ++ ", " ++ show advice ++ ") = " ++ show retval

  DetailedSyscallExit_fadvise64
    SyscallExitDetails_fadvise64{ enterDetail = SyscallEnterDetails_fadvise64{ fd, offset, len, advice }, retval } ->
      "fadvise64(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show len ++ ", " ++ show advice ++ ") = " ++ show retval

  DetailedSyscallExit_madvise
    SyscallExitDetails_madvise{ enterDetail = SyscallEnterDetails_madvise{ start, len_in, behavior }, retval } ->
      "madvise(" ++ show start ++ ", " ++ show len_in ++ ", " ++ show behavior ++ ") = " ++ show retval

  DetailedSyscallExit_memfd_create
    SyscallExitDetails_memfd_create{ enterDetail = SyscallEnterDetails_memfd_create{ unameBS, flags }, retval } ->
      "memfd_create(" ++ show unameBS ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_mbind
    SyscallExitDetails_mbind{ enterDetail = SyscallEnterDetails_mbind{ start, len, mode, nmask, maxnode, flags }, retval } ->
      "mbind(" ++ show start ++ ", " ++ show len ++ ", " ++ show mode ++ ", " ++ show nmask ++ ", " ++ show maxnode ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_set_mempolicy
    SyscallExitDetails_set_mempolicy{ enterDetail = SyscallEnterDetails_set_mempolicy{ mode, nmask, maxnode }, retval } ->
      "set_mempolicy(" ++ show mode ++ ", " ++ show nmask ++ ", " ++ show maxnode ++ ") = " ++ show retval

  DetailedSyscallExit_migrate_pages
    SyscallExitDetails_migrate_pages{ enterDetail = SyscallEnterDetails_migrate_pages{ pid_, maxnode, old_nodes, new_nodes }, retval } ->
      "migrate_pages(" ++ show pid_ ++ ", " ++ show maxnode ++ ", " ++ show old_nodes ++ ", " ++ show new_nodes ++ ") = " ++ show retval

  DetailedSyscallExit_get_mempolicy
    SyscallExitDetails_get_mempolicy{ enterDetail = SyscallEnterDetails_get_mempolicy{ policy, nmask, maxnode, addr, flags }, retval } ->
      "get_mempolicy(" ++ show policy ++ ", " ++ show nmask ++ ", " ++ show maxnode ++ ", " ++ show addr ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_move_pages
    SyscallExitDetails_move_pages{ enterDetail = SyscallEnterDetails_move_pages{ pid_, nr_pages, pages, nodes, status, flags }, retval } ->
      "move_pages(" ++ show pid_ ++ ", " ++ show nr_pages ++ ", " ++ show pages ++ ", " ++ show nodes ++ ", " ++ show status ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_mincore
    SyscallExitDetails_mincore{ enterDetail = SyscallEnterDetails_mincore{ start, len, vec }, retval } ->
      "mincore(" ++ show start ++ ", " ++ show len ++ ", " ++ show vec ++ ") = " ++ show retval

  DetailedSyscallExit_mlock
    SyscallExitDetails_mlock{ enterDetail = SyscallEnterDetails_mlock{ start, len }, retval } ->
      "mlock(" ++ show start ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_mlock2
    SyscallExitDetails_mlock2{ enterDetail = SyscallEnterDetails_mlock2{ start, len, flags }, retval } ->
      "mlock2(" ++ show start ++ ", " ++ show len ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_munlock
    SyscallExitDetails_munlock{ enterDetail = SyscallEnterDetails_munlock{ start, len }, retval } ->
      "munlock(" ++ show start ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_mlockall
    SyscallExitDetails_mlockall{ enterDetail = SyscallEnterDetails_mlockall{ flags }, retval } ->
      "mlockall(" ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_munlockall
    SyscallExitDetails_munlockall{ enterDetail = SyscallEnterDetails_munlockall{  }, retval } ->
      "munlockall() = " ++ show retval

  DetailedSyscallExit_brk
    SyscallExitDetails_brk{ enterDetail = SyscallEnterDetails_brk{ brk }, retval } ->
      "brk(" ++ show brk ++ ") = " ++ show retval

  DetailedSyscallExit_munmap
    SyscallExitDetails_munmap{ enterDetail = SyscallEnterDetails_munmap{ addr, len }, retval } ->
      "munmap(" ++ show addr ++ ", " ++ show len ++ ") = " ++ show retval

  DetailedSyscallExit_remap_file_pages
    SyscallExitDetails_remap_file_pages{ enterDetail = SyscallEnterDetails_remap_file_pages{ start, size, prot, pgoff, flags }, retval } ->
      "remap_file_pages(" ++ show start ++ ", " ++ show size ++ ", " ++ show prot ++ ", " ++ show pgoff ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_mprotect
    SyscallExitDetails_mprotect{ enterDetail = SyscallEnterDetails_mprotect{ start, len, prot }, retval } ->
      "mprotect(" ++ show start ++ ", " ++ show len ++ ", " ++ show prot ++ ") = " ++ show retval

  DetailedSyscallExit_pkey_mprotect
    SyscallExitDetails_pkey_mprotect{ enterDetail = SyscallEnterDetails_pkey_mprotect{ start, len, prot, pkey }, retval } ->
      "pkey_mprotect(" ++ show start ++ ", " ++ show len ++ ", " ++ show prot ++ ", " ++ show pkey ++ ") = " ++ show retval

  DetailedSyscallExit_pkey_alloc
    SyscallExitDetails_pkey_alloc{ enterDetail = SyscallEnterDetails_pkey_alloc{ flags, init_val }, retval } ->
      "pkey_alloc(" ++ show flags ++ ", " ++ show init_val ++ ") = " ++ show retval

  DetailedSyscallExit_pkey_free
    SyscallExitDetails_pkey_free{ enterDetail = SyscallEnterDetails_pkey_free{ pkey }, retval } ->
      "pkey_free(" ++ show pkey ++ ") = " ++ show retval

  DetailedSyscallExit_mremap
    SyscallExitDetails_mremap{ enterDetail = SyscallEnterDetails_mremap{ addr, old_len, new_len, flags, new_addr }, retval } ->
      "mremap(" ++ show addr ++ ", " ++ show old_len ++ ", " ++ show new_len ++ ", " ++ show flags ++ ", " ++ show new_addr ++ ") = " ++ show retval

  DetailedSyscallExit_msync
    SyscallExitDetails_msync{ enterDetail = SyscallEnterDetails_msync{ start, len, flags }, retval } ->
      "msync(" ++ show start ++ ", " ++ show len ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_process_vm_readv
    SyscallExitDetails_process_vm_readv{ enterDetail = SyscallEnterDetails_process_vm_readv{ pid_, lvec, liovcnt, rvec, riovcnt, flags }, retval } ->
      "process_vm_readv(" ++ show pid_ ++ ", " ++ show lvec ++ ", " ++ show liovcnt ++ ", " ++ show rvec ++ ", " ++ show riovcnt ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_process_vm_writev
    SyscallExitDetails_process_vm_writev{ enterDetail = SyscallEnterDetails_process_vm_writev{ pid_, lvec, liovcnt, rvec, riovcnt, flags }, retval } ->
      "process_vm_writev(" ++ show pid_ ++ ", " ++ show lvec ++ ", " ++ show liovcnt ++ ", " ++ show rvec ++ ", " ++ show riovcnt ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_readahead
    SyscallExitDetails_readahead{ enterDetail = SyscallEnterDetails_readahead{ fd, offset, count }, retval } ->
      "readahead(" ++ show fd ++ ", " ++ show offset ++ ", " ++ show count ++ ") = " ++ show retval

  DetailedSyscallExit_swapoff
    SyscallExitDetails_swapoff{ enterDetail = SyscallEnterDetails_swapoff{ specialfileBS }, retval } ->
      "swapoff(" ++ show specialfileBS ++ ") = " ++ show retval

  DetailedSyscallExit_swapon
    SyscallExitDetails_swapon{ enterDetail = SyscallEnterDetails_swapon{ specialfileBS, swap_flags }, retval } ->
      "swapon(" ++ show specialfileBS ++ ", " ++ show swap_flags ++ ") = " ++ show retval

  DetailedSyscallExit_socket
    SyscallExitDetails_socket{ enterDetail = SyscallEnterDetails_socket{ family, type_, protocol }, retval } ->
      "socket(" ++ show family ++ ", " ++ show type_ ++ ", " ++ show protocol ++ ") = " ++ show retval

  DetailedSyscallExit_socketpair
    SyscallExitDetails_socketpair{ enterDetail = SyscallEnterDetails_socketpair{ family, type_, protocol, usockvec }, retval } ->
      "socketpair(" ++ show family ++ ", " ++ show type_ ++ ", " ++ show protocol ++ ", " ++ show usockvec ++ ") = " ++ show retval

  DetailedSyscallExit_bind
    SyscallExitDetails_bind{ enterDetail = SyscallEnterDetails_bind{ fd, umyaddr, addrlen }, retval } ->
      "bind(" ++ show fd ++ ", " ++ show umyaddr ++ ", " ++ show addrlen ++ ") = " ++ show retval

  DetailedSyscallExit_listen
    SyscallExitDetails_listen{ enterDetail = SyscallEnterDetails_listen{ fd, backlog }, retval } ->
      "listen(" ++ show fd ++ ", " ++ show backlog ++ ") = " ++ show retval

  DetailedSyscallExit_accept4
    SyscallExitDetails_accept4{ enterDetail = SyscallEnterDetails_accept4{ fd, upeer_sockaddr, upeer_addrlen, flags }, retval } ->
      "accept4(" ++ show fd ++ ", " ++ show upeer_sockaddr ++ ", " ++ show upeer_addrlen ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_accept
    SyscallExitDetails_accept{ enterDetail = SyscallEnterDetails_accept{ fd, upeer_sockaddr, upeer_addrlen }, retval } ->
      "accept(" ++ show fd ++ ", " ++ show upeer_sockaddr ++ ", " ++ show upeer_addrlen ++ ") = " ++ show retval

  DetailedSyscallExit_connect
    SyscallExitDetails_connect{ enterDetail = SyscallEnterDetails_connect{ fd, uservaddr, addrlen }, retval } ->
      "connect(" ++ show fd ++ ", " ++ show uservaddr ++ ", " ++ show addrlen ++ ") = " ++ show retval

  DetailedSyscallExit_getsockname
    SyscallExitDetails_getsockname{ enterDetail = SyscallEnterDetails_getsockname{ fd, usockaddr, usockaddr_len }, retval } ->
      "getsockname(" ++ show fd ++ ", " ++ show usockaddr ++ ", " ++ show usockaddr_len ++ ") = " ++ show retval

  DetailedSyscallExit_getpeername
    SyscallExitDetails_getpeername{ enterDetail = SyscallEnterDetails_getpeername{ fd, usockaddr, usockaddr_len }, retval } ->
      "getpeername(" ++ show fd ++ ", " ++ show usockaddr ++ ", " ++ show usockaddr_len ++ ") = " ++ show retval

  DetailedSyscallExit_sendto
    SyscallExitDetails_sendto{ enterDetail = SyscallEnterDetails_sendto{ fd, buff, len, flags, addr, addr_len }, retval } ->
      "sendto(" ++ show fd ++ ", " ++ show buff ++ ", " ++ show len ++ ", " ++ show flags ++ ", " ++ show addr ++ ", " ++ show addr_len ++ ") = " ++ show retval

  DetailedSyscallExit_send
    SyscallExitDetails_send{ enterDetail = SyscallEnterDetails_send{ fd, buff, len, flags }, retval } ->
      "send(" ++ show fd ++ ", " ++ show buff ++ ", " ++ show len ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_recvfrom
    SyscallExitDetails_recvfrom{ enterDetail = SyscallEnterDetails_recvfrom{ fd, ubuf, size, flags, addr, addr_len }, retval } ->
      "recvfrom(" ++ show fd ++ ", " ++ show ubuf ++ ", " ++ show size ++ ", " ++ show flags ++ ", " ++ show addr ++ ", " ++ show addr_len ++ ") = " ++ show retval

  DetailedSyscallExit_recv
    SyscallExitDetails_recv{ enterDetail = SyscallEnterDetails_recv{ fd, ubuf, size, flags }, retval } ->
      "recv(" ++ show fd ++ ", " ++ show ubuf ++ ", " ++ show size ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_setsockopt
    SyscallExitDetails_setsockopt{ enterDetail = SyscallEnterDetails_setsockopt{ fd, level, optname, optvalBS, optlen }, retval } ->
      "setsockopt(" ++ show fd ++ ", " ++ show level ++ ", " ++ show optname ++ ", " ++ show optvalBS ++ ", " ++ show optlen ++ ") = " ++ show retval

  DetailedSyscallExit_getsockopt
    SyscallExitDetails_getsockopt{ enterDetail = SyscallEnterDetails_getsockopt{ fd, level, optname, optvalBS, optlen }, retval } ->
      "getsockopt(" ++ show fd ++ ", " ++ show level ++ ", " ++ show optname ++ ", " ++ show optvalBS ++ ", " ++ show optlen ++ ") = " ++ show retval

  DetailedSyscallExit_shutdown
    SyscallExitDetails_shutdown{ enterDetail = SyscallEnterDetails_shutdown{ fd, how }, retval } ->
      "shutdown(" ++ show fd ++ ", " ++ show how ++ ") = " ++ show retval

  DetailedSyscallExit_sendmsg
    SyscallExitDetails_sendmsg{ enterDetail = SyscallEnterDetails_sendmsg{ fd, msg, flags }, retval } ->
      "sendmsg(" ++ show fd ++ ", " ++ show msg ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_sendmmsg
    SyscallExitDetails_sendmmsg{ enterDetail = SyscallEnterDetails_sendmmsg{ fd, mmsg, vlen, flags }, retval } ->
      "sendmmsg(" ++ show fd ++ ", " ++ show mmsg ++ ", " ++ show vlen ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_recvmsg
    SyscallExitDetails_recvmsg{ enterDetail = SyscallEnterDetails_recvmsg{ fd, msg, flags }, retval } ->
      "recvmsg(" ++ show fd ++ ", " ++ show msg ++ ", " ++ show flags ++ ") = " ++ show retval

  DetailedSyscallExit_recvmmsg
    SyscallExitDetails_recvmmsg{ enterDetail = SyscallEnterDetails_recvmmsg{ fd, mmsg, vlen, flags, timeout }, retval } ->
      "recvmmsg(" ++ show fd ++ ", " ++ show mmsg ++ ", " ++ show vlen ++ ", " ++ show flags ++ ", " ++ show timeout ++ ") = " ++ show retval

  DetailedSyscallExit_socketcall
    SyscallExitDetails_socketcall{ enterDetail = SyscallEnterDetails_socketcall{ call, args }, retval } ->
      "socketcall(" ++ show call ++ ", " ++ show args ++ ") = " ++ show retval

  DetailedSyscallExit_add_key
    SyscallExitDetails_add_key{ enterDetail = SyscallEnterDetails_add_key{ _typeBS, _descriptionBS, _payload, plen, ringid }, retval } ->
      "add_key(" ++ show _typeBS ++ ", " ++ show _descriptionBS ++ ", " ++ show _payload ++ ", " ++ show plen ++ ", " ++ show ringid ++ ") = " ++ show retval

  DetailedSyscallExit_request_key
    SyscallExitDetails_request_key{ enterDetail = SyscallEnterDetails_request_key{ _typeBS, _descriptionBS, _callout_infoBS, destringid }, retval } ->
      "request_key(" ++ show _typeBS ++ ", " ++ show _descriptionBS ++ ", " ++ show _callout_infoBS ++ ", " ++ show destringid ++ ") = " ++ show retval

  DetailedSyscallExit_keyctl
    SyscallExitDetails_keyctl{ enterDetail = SyscallEnterDetails_keyctl{ option, arg2, arg3, arg4, arg5 }, retval } ->
      "keyctl(" ++ show option ++ ", " ++ show arg2 ++ ", " ++ show arg3 ++ ", " ++ show arg4 ++ ", " ++ show arg5 ++ ") = " ++ show retval

  DetailedSyscallExit_select
    SyscallExitDetails_select{ enterDetail = SyscallEnterDetails_select{ n, inp, outp, exp_, tvp }, retval } ->
      "select(" ++ show n ++ ", " ++ show inp ++ ", " ++ show outp ++ ", " ++ show exp_ ++ ", " ++ show tvp ++ ") = " ++ show retval

  DetailedSyscallExit_pselect6
    SyscallExitDetails_pselect6{ enterDetail = SyscallEnterDetails_pselect6{ n, inp, outp, exp_, tsp, sig }, retval } ->
      "pselect6(" ++ show n ++ ", " ++ show inp ++ ", " ++ show outp ++ ", " ++ show exp_ ++ ", " ++ show tsp ++ ", " ++ show sig ++ ") = " ++ show retval

  DetailedSyscallExit_mq_open
    SyscallExitDetails_mq_open{ enterDetail = SyscallEnterDetails_mq_open{ u_nameBS, oflag, mode, u_attr }, retval } ->
      "mq_open(" ++ show u_nameBS ++ ", " ++ show oflag ++ ", " ++ show mode ++ ", " ++ show u_attr ++ ") = " ++ show retval

  DetailedSyscallExit_mq_unlink
    SyscallExitDetails_mq_unlink{ enterDetail = SyscallEnterDetails_mq_unlink{ u_nameBS }, retval } ->
      "mq_unlink(" ++ show u_nameBS ++ ") = " ++ show retval

  DetailedSyscallExit_bpf
    SyscallExitDetails_bpf{ enterDetail = SyscallEnterDetails_bpf{ cmd, uattr, size }, retval } ->
      "bpf(" ++ show cmd ++ ", " ++ show uattr ++ ", " ++ show size ++ ") = " ++ show retval

  DetailedSyscallExit_capget
    SyscallExitDetails_capget{ enterDetail = SyscallEnterDetails_capget{ header, dataptr }, retval } ->
      "capget(" ++ show header ++ ", " ++ show dataptr ++ ") = " ++ show retval

  DetailedSyscallExit_capset
    SyscallExitDetails_capset{ enterDetail = SyscallEnterDetails_capset{ header, data_ }, retval } ->
      "capset(" ++ show header ++ ", " ++ show data_ ++ ") = " ++ show retval

  DetailedSyscallExit_rt_sigtimedwait
    SyscallExitDetails_rt_sigtimedwait{ enterDetail = SyscallEnterDetails_rt_sigtimedwait{ uthese, uinfo, uts, sigsetsize }, retval } ->
      "rt_sigtimedwait(" ++ show uthese ++ ", " ++ show uinfo ++ ", " ++ show uts ++ ", " ++ show sigsetsize ++ ") = " ++ show retval

  DetailedSyscallExit_rt_sigqueueinfo
    SyscallExitDetails_rt_sigqueueinfo{ enterDetail = SyscallEnterDetails_rt_sigqueueinfo{ pid_, sig, uinfo }, retval } ->
      "rt_sigqueueinfo(" ++ show pid_ ++ ", " ++ show sig ++ ", " ++ show uinfo ++ ") = " ++ show retval

  DetailedSyscallExit_rt_tgsigqueueinfo
    SyscallExitDetails_rt_tgsigqueueinfo{ enterDetail = SyscallEnterDetails_rt_tgsigqueueinfo{ tgid, pid_, sig, uinfo }, retval } ->
      "rt_tgsigqueueinfo(" ++ show tgid ++ ", " ++ show pid_ ++ ", " ++ show sig ++ ", " ++ show uinfo ++ ") = " ++ show retval

  DetailedSyscallExit_sigaltstack
    SyscallExitDetails_sigaltstack{ enterDetail = SyscallEnterDetails_sigaltstack{ uss, uoss }, retval } ->
      "sigaltstack(" ++ show uss ++ ", " ++ show uoss ++ ") = " ++ show retval

  DetailedSyscallExit_mq_timedsend
    SyscallExitDetails_mq_timedsend{ enterDetail = SyscallEnterDetails_mq_timedsend{ mqdes, u_msg_ptrBS, msg_len, msg_prio, u_abs_timeout }, retval } ->
      "mq_timedsend(" ++ show mqdes ++ ", " ++ show u_msg_ptrBS ++ ", " ++ show msg_len ++ ", " ++ show msg_prio ++ ", " ++ show u_abs_timeout ++ ") = " ++ show retval

  DetailedSyscallExit_mq_timedreceive
    SyscallExitDetails_mq_timedreceive{ enterDetail = SyscallEnterDetails_mq_timedreceive{ mqdes, u_msg_ptrBS, msg_len, u_msg_prio, u_abs_timeout }, retval } ->
      "mq_timedreceive(" ++ show mqdes ++ ", " ++ show u_msg_ptrBS ++ ", " ++ show msg_len ++ ", " ++ show u_msg_prio ++ ", " ++ show u_abs_timeout ++ ") = " ++ show retval

  DetailedSyscallExit_mq_notify
    SyscallExitDetails_mq_notify{ enterDetail = SyscallEnterDetails_mq_notify{ mqdes, u_notification }, retval } ->
      "mq_notify(" ++ show mqdes ++ ", " ++ show u_notification ++ ") = " ++ show retval

  DetailedSyscallExit_mq_getsetattr
    SyscallExitDetails_mq_getsetattr{ enterDetail = SyscallEnterDetails_mq_getsetattr{ mqdes, u_mqstat, u_omqstat }, retval } ->
      "mq_getsetattr(" ++ show mqdes ++ ", " ++ show u_mqstat ++ ", " ++ show u_omqstat ++ ") = " ++ show retval

  DetailedSyscallExit_unimplemented syscall syscallArgs result ->
    "unimplemented_syscall_details(" ++ show syscall ++ ", " ++ show syscallArgs ++ ") = " ++ show result


getFormattedSyscallEnterDetails :: Syscall -> SyscallArgs -> CPid -> IO String
getFormattedSyscallEnterDetails syscall syscallArgs pid =
  case syscall of
    UnknownSyscall number -> do
      pure $ "unknown_syscall_" ++ show number ++ "(" ++ show syscallArgs ++ ")"
    KnownSyscall knownSyscall -> do
      detailed <- getSyscallEnterDetails knownSyscall syscallArgs pid
      pure $ formatDetailedSyscallEnter detailed


getFormattedSyscallExitDetails :: Syscall -> SyscallArgs -> CPid -> IO String
getFormattedSyscallExitDetails syscall syscallArgs pid =
  case syscall of
    UnknownSyscall number -> do
      pure $ "unknown_syscall_" ++ show number ++ "(" ++ show syscallArgs ++ ")"
    KnownSyscall knownSyscall -> do

      eDetailed <- getSyscallExitDetails knownSyscall syscallArgs pid

      case eDetailed of
        Right detailedExit -> pure $ formatDetailedSyscallExit detailedExit
        Left errno -> do
          strErr <- strError errno
          let formattedErrno = " (" ++ strErr ++ ")"
          -- TODO implement remembering arguments
          pure $ syscallName knownSyscall ++ "(TODO implement remembering arguments) = -1" ++ formattedErrno


-- TODO Make a version of this that takes a CreateProcess.
--      Note that `System.Linux.Ptrace.traceProcess` isn't good enough,
--      because it is racy:
--      It uses PTHREAD_ATTACH, which sends SIGSTOP to the started
--      process. By that time, the process may already have exited.

traceForkExecvFullPath :: [String] -> IO ExitCode
traceForkExecvFullPath args = do
  (exitCode, ()) <-
    sourceTraceForkExecvFullPathWithSink args (printSyscallOrSignalNameConduit .| CL.sinkNull)
  return exitCode


-- | Like the partial `T.decodeUtf8`, with `HasCallStack`.
decodeUtf8OrError :: (HasCallStack) => ByteString -> Text
decodeUtf8OrError bs = case T.decodeUtf8' bs of
  Left err -> error $ "Could not decode as UTF-8: " ++ show err ++ "; ByteString was : " ++ show bs
  Right text -> text


getFdPath :: CPid -> CInt -> IO FilePath
getFdPath pid fd = do
  let procFdPath = "/proc/" ++ show pid ++ "/fd/" ++ show fd
  readSymbolicLink procFdPath


getExePath :: CPid -> IO FilePath
getExePath pid = do
  let procExePath = "/proc/" ++ show pid ++ "/exe"
  readSymbolicLink procExePath


data FileWriteEvent
  = FileOpen ByteString -- ^ name used to open the file
  | FileWrite
  | FileClose
  | FileRename ByteString -- ^ new (target) name
  deriving (Eq, Ord, Show)

-- | Uses raw trace events to produce more focused events aimed at analysing file writes.
-- Output events are accompanied by corresponding absolute file paths.
--
-- NOTES:
-- * only calls to `write` are currently used as a marker for writes and syscalls
--   `pwrite`, `writev`, `pwritev` are not taken into account
fileWritesConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (FilePath, FileWriteEvent) m ()
fileWritesConduit = go
  where
    go =
      await >>= \case
        Just (pid, SyscallStop (SyscallExit (KnownSyscall syscall, syscallArgs))) -> do
          detailedSyscallExit <- liftIO $ getSyscallExitDetails syscall syscallArgs pid
          case detailedSyscallExit of
            Right (DetailedSyscallExit_open SyscallExitDetails_open
                   { enterDetail = SyscallEnterDetails_open { pathnameBS }
                   , fd }) ->
              yieldFdEvent pid fd (FileOpen pathnameBS)
            Right (DetailedSyscallExit_openat SyscallExitDetails_openat
                   { enterDetail = SyscallEnterDetails_openat { pathnameBS }
                   , fd }) ->
              yieldFdEvent pid fd (FileOpen pathnameBS)
            Right (DetailedSyscallExit_creat SyscallExitDetails_creat
                   { enterDetail = SyscallEnterDetails_creat { pathnameBS }
                   , fd }) ->
              yieldFdEvent pid fd (FileOpen pathnameBS)
            _ -> return ()
          go
        Just (pid, SyscallStop (SyscallEnter (KnownSyscall syscall, syscallArgs))) -> do
          detailedSyscallEnter <- liftIO $ getSyscallEnterDetails syscall syscallArgs pid
          case detailedSyscallEnter of
            DetailedSyscallEnter_write SyscallEnterDetails_write { fd } ->
              yieldFdEvent pid fd FileWrite
            DetailedSyscallEnter_close SyscallEnterDetails_close { fd } ->
              yieldFdEvent pid fd FileClose
            DetailedSyscallEnter_rename SyscallEnterDetails_rename { oldpathBS, newpathBS } -> do
              path <- liftIO $ resolveToPidCwd pid (T.unpack $ decodeUtf8OrError oldpathBS)
              yield (path, FileRename newpathBS)
            _ -> return ()
          go
        Just _ ->
          go -- ignore other events
        Nothing ->
          return ()
    yieldFdEvent pid fd event = do
      path <- liftIO $ getFdPath pid fd
      yield (path, event)

resolveToPidCwd :: Show a => a -> FilePath -> IO FilePath
resolveToPidCwd pid path = do
  let procFdPath = "/proc/" ++ show pid ++ "/cwd"
  wd <- liftIO $ readSymbolicLink procFdPath
  canonicalizePath $ wd </> path


data FileWriteBehavior
  = NoWrites
  | NonatomicWrite
  | AtomicWrite FilePath
  -- ^ path tells temporary file name that was used
  | Unexpected String
  deriving (Eq, Ord, Show)

-- uses state machine implemented as recursive functions
analyzeWrites :: [FileWriteEvent] -> FileWriteBehavior
analyzeWrites es = checkOpen es
  where
    checkOpen events =
      case events of
        [] -> NoWrites
        -- we could see a `close` syscall for a pipe descriptor
        -- with no `open` for it thus we just ignore it
        FileClose : rest -> checkOpen rest
        FileOpen _ : rest -> checkWrites rest
        unexpected : _ -> unexpectedEvent "FileOpen" unexpected
    checkWrites events =
      case events of
        [] -> Unexpected $ "FileClose was expected but not seen"
        FileClose : rest -> checkOpen rest
        FileWrite : rest -> checkAfterWrite rest
        unexpected : _ -> unexpectedEvent "FileClose or FileWrite" unexpected
    checkAfterWrite events =
      case events of
        [] -> Unexpected $ "FileClose was expected but not seen"
        FileWrite : rest -> checkAfterWrite rest
        FileClose : rest -> checkRename rest
        unexpected : _ -> unexpectedEvent "FileClose or FileWrite" unexpected
    -- when it happens that a path gets more than 1 sequence open-write-close
    -- for it we need to check whether there was a `rename` after the 1st one
    -- and then check the result of the next one and combine them accordingly
    -- e.g. atomic + non-atomic -> non-atomic
    checkRename events =
      case events of
        FileRename path : rest ->
          case checkOpen rest of
            NoWrites ->
              -- we write original path here which swapped
              -- with oldpath in `atomicWritesSink`
              AtomicWrite (T.unpack $ decodeUtf8OrError path)
            other ->
              other
        noRenames ->
          case checkOpen noRenames of
            NoWrites -> NonatomicWrite
            other -> other
    unexpectedEvent expected real =
      Unexpected $ "expected " ++ expected ++ ", but " ++
                   show real ++ " was seen"

atomicWritesSink :: (MonadIO m) => ConduitT (CPid, TraceEvent) Void m (Map FilePath FileWriteBehavior)
atomicWritesSink =
  extract <$> (fileWritesConduit .| foldlC collectWrite Map.empty)
  where
    collectWrite :: Map FilePath [FileWriteEvent] -> (FilePath, FileWriteEvent) -> Map FilePath [FileWriteEvent]
    collectWrite m (fp, e) = Map.alter (Just . maybe [e] (e:)) fp m
    extract :: Map FilePath [FileWriteEvent] -> Map FilePath FileWriteBehavior
    extract m =
      let (noRenames, renames) =
            partitionEithers . map (analyzeWrites' . second reverse) $ Map.toList m
      in Map.fromList noRenames <> Map.fromList (map (second AtomicWrite) renames)
    -- this function (in addition to what `analyzeWrites` does) treats atomic writes
    -- in a special way: those include a rename and we need to put atomic writes under
    -- a path which is a target of a corresponding rename
    -- so in the end we swap path in `AtomicWrite` and its corresponding map key
    analyzeWrites' (src, es) = case analyzeWrites es of
      AtomicWrite target -> Right (target, src)
      other -> Left (src, other)

-- | Passes through all syscalls and signals that come by,
-- printing them, including details where available.
printSyscallOrSignalNameConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, TraceEvent) m ()
printSyscallOrSignalNameConduit = CL.iterM $ \(pid, event) -> do
  liftIO $ case event of

    SyscallStop enterOrExit -> case enterOrExit of

      SyscallEnter (syscall, syscallArgs) -> do
        formatted <- getFormattedSyscallEnterDetails syscall syscallArgs pid
        putStrLn $ show [pid] ++ " Entering syscall: " ++ show syscall
          ++ (if formatted /= "" then ", details: " ++ formatted else "")

      SyscallExit (syscall, syscallArgs) -> do
        formatted <- getFormattedSyscallExitDetails syscall syscallArgs pid
        putStrLn $ show [pid] ++ " Exited syscall: " ++ show syscall
          ++ (if formatted /= "" then ", details: " ++ formatted else "")

    PTRACE_EVENT_Stop ptraceEvent -> do
      putStrLn $ show [pid] ++ " Got event: " ++ show ptraceEvent

    GroupStop sig -> do
      putStrLn $ show [pid] ++ " Got group stop: " ++ prettySignal sig

    SignalDeliveryStop sig -> do
      putStrLn $ show [pid] ++ " Got signal: " ++ prettySignal sig

    Death fullStatus -> do
      putStrLn $ show [pid] ++ " Process exited with status: " ++ show fullStatus


procToArgv :: (HasCallStack) => FilePath -> [String] -> IO [String]
procToArgv name args = do
  exists <- doesFileExist name
  path <- if
    | exists -> pure name
    | otherwise -> do
        mbExe <- findExecutable name
        case mbExe of
          Nothing -> die $ "Cannot find executable: " ++ name
          Just path -> pure path
  pure (path:args)


traceForkProcess :: (HasCallStack) => FilePath -> [String] -> IO ExitCode
traceForkProcess name args = do
  argv <- procToArgv name args
  traceForkExecvFullPath argv


-- | The terminology in here is oriented on `man 2 ptrace`.
data SyscallStopType
  = SyscallEnter (Syscall, SyscallArgs)
  | SyscallExit (Syscall, SyscallArgs) -- ^ contains the args from when the syscall was entered
  deriving (Eq, Ord, Show)


data PTRACE_EVENT
  = PTRACE_EVENT_VFORK CPid -- ^ PID of the new child
  | PTRACE_EVENT_FORK CPid -- ^ PID of the new child
  | PTRACE_EVENT_CLONE CPid -- ^ PID of the new child
  | PTRACE_EVENT_VFORK_DONE CPid -- ^ PID of the new child
  | PTRACE_EVENT_EXEC
  | PTRACE_EVENT_EXIT
  | PTRACE_EVENT_STOP
  | PTRACE_EVENT_SECCOMP
  | PTRACE_EVENT_OTHER -- TODO make this carry the number
  deriving (Eq, Ord, Show)


-- | The terminology in here is oriented on `man 2 ptrace`.
data TraceEvent
  = SyscallStop SyscallStopType
  | PTRACE_EVENT_Stop PTRACE_EVENT -- TODO change this to carry detail information with each event, e.g. what pid was clone()d
  | GroupStop Signal
  | SignalDeliveryStop Signal
  | Death ExitCode -- ^ @exit()@ or killed by signal; means the PID has vanished from the system now
  deriving (Eq, Ord, Show)


-- | Entering and exiting syscalls always happens in turns;
-- we must keep track of that.
--
-- As per `man 2 ptrace`:
--
-- > Syscall-enter-stop and syscall-exit-stop are indistinguishable from each
-- > other by the tracer.
-- > The tracer needs to keep track of the sequence of ptrace-stops in order
-- > to not misinterpret syscall-enter-stop as syscall-exit-stop or vice versa.
-- > The rule is that syscall-enter-stop is always followed by syscall-exit-stop,
-- > PTRACE_EVENT stop or the tracee's death; no other kinds of ptrace-stop
-- > can occur in between.
-- >
-- > If after syscall-enter-stop, the tracer uses a restarting command other than
-- > PTRACE_SYSCALL, syscall-exit-stop is not generated.
--
-- We use this data structure to track it.
data TraceState = TraceState
  { currentSyscalls :: !(Map CPid (Syscall, SyscallArgs)) -- ^ must be removed from the map if (it's present and the next @ptrace()@ invocation is not @PTRACE_SYSCALL@)
  } deriving (Eq, Ord, Show)


initialTraceState :: TraceState
initialTraceState =
  TraceState
    { currentSyscalls = Map.empty
    }


-- Observing ptrace events
--
-- As per `man 2 ptrace`:
--
--     If the tracer sets PTRACE_O_TRACE_* options, the tracee will enter ptrace-stops called PTRACE_EVENT stops.
--
--     PTRACE_EVENT stops are observed by the tracer as waitpid(2) returning with
--     WIFSTOPPED(status), and WSTOPSIG(status) returns SIGTRAP. An additional bit
--     is set in the higher byte of the status word: the value `status>>8` will be
--
--         (SIGTRAP | PTRACE_EVENT_foo << 8).
--
-- Note that this only happens for when `PTRACE_O_TRACE_*` was enabled
-- for each corresponding event (`ptrace_setoptions` in Haskell).

-- Exting children:
--
-- As per `man 2 ptrace`:
--
--     PTRACE_EVENT_EXIT
--         Stop before exit (including death from exit_group(2)),
--         signal death, or exit caused by execve(2) in a multi‐ threaded process.
--         PTRACE_GETEVENTMSG returns the exit status. Registers can be examined
--         (unlike when "real" exit happens).
--         The tracee is still alive; it needs to be PTRACE_CONTed
--         or PTRACE_DETACHed to finish exiting.


-- TODO: Use these values from the `linux-ptrace` package instead.


_PTRACE_EVENT_FORK :: CInt
_PTRACE_EVENT_FORK = 1

_PTRACE_EVENT_VFORK :: CInt
_PTRACE_EVENT_VFORK = 2

_PTRACE_EVENT_CLONE :: CInt
_PTRACE_EVENT_CLONE = 3

_PTRACE_EVENT_EXEC :: CInt
_PTRACE_EVENT_EXEC = 4

_PTRACE_EVENT_VFORKDONE :: CInt
_PTRACE_EVENT_VFORKDONE = 5

_PTRACE_EVENT_EXIT :: CInt
_PTRACE_EVENT_EXIT = 6

_PTRACE_EVENT_STOP :: CInt
_PTRACE_EVENT_STOP = 128


-- TODO Don't rely on this symbol from the `linux-ptrace` package
foreign import ccall safe "ptrace" c_ptrace :: CInt -> CPid -> Ptr a -> Ptr b -> IO CLong


-- TODO: Use this values from the `linux-ptrace` package instead.
_PTRACE_GETSIGINFO :: CInt
_PTRACE_GETSIGINFO = 0x4202


-- | Uses @PTRACE_GETSIGINFO@ to check whether the current stop is a
-- group-stop.
--
-- PRE:
-- Must be called only if we're in a ptrace-stop and the signal is one
-- of SIGSTOP, SIGTSTP, SIGTTIN, or SIGTTOU (as per @man 2 ptrace@).
ptrace_GETSIGINFO_isGroupStop :: CPid -> IO Bool
ptrace_GETSIGINFO_isGroupStop pid = alloca $ \ptr -> do
  -- From `man 2 ptrace`:
  --     ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo)
  --     ...
  --     If PTRACE_GETSIGINFO fails with EINVAL,
  --     then it is definitely a group-stop.
  resetErrno -- ptrace() requires setting errno to 0 before the call
  res <- c_ptrace _PTRACE_GETSIGINFO pid (wordPtrToPtr 0) (ptr :: Ptr ())
  errno <- getErrno
  pure $ res == -1 && errno == eINVAL


waitForTraceEvent :: (HasCallStack) => TraceState -> IO (TraceState, (CPid, TraceEvent))
waitForTraceEvent state@TraceState{ currentSyscalls } = do

  -- Using `AllChildren` (`__WALL`), as `man 2 ptrace` recommends and
  -- like `strace` does.
  mr <- waitpidFullStatus (-1) [AllChildren]
  case mr of
    -- This can occur when the caller incorrectly runs this on a non-traced process
    -- that exited by itself.
    Nothing -> error "waitForTraceEvent: no PID was returned by waitpid"
    Just (returnedPid, status, FullStatus fullStatus) -> do -- TODO must we have different logic if any other pid (e.g. thread, child process of traced process) was returned?
      -- What event occurred; loop if not a syscall or signal
      (newState, event) <- case status of
        -- `Exited` means that the process chose to exit by itself,
        -- as in calling `exit()` (as opposed to e.g. getting killed
        -- by a signal).
        Exited i -> do
          case i of
            0 -> pure (state, Death $ ExitSuccess)
            _ -> pure (state, Death $ ExitFailure i)
        Continued -> error $ "waitForTraceEvent: BUG: Continued status appeared even though WCONTINUE was not passed to waitpid"
        -- Note that `Signaled` means that the process was *terminated*
        -- by a signal.
        -- Signals that come in without killing the process appear in
        -- the `Stopped` case.
        Signaled _sig -> pure (state, Death $ ExitFailure (fromIntegral fullStatus))
        Stopped sig -> do
          let signalAllowsGroupStop =
                -- As per `man 2 ptrace`, only these signals are stopping
                -- signals and allow group stops.
                sig `elem` [sigSTOP, sigTSTP, sigTTIN, sigTTOU]
          isGroupStop <-
            if not signalAllowsGroupStop
              then pure False
              else ptrace_GETSIGINFO_isGroupStop returnedPid

          if
            | sig == (sigTRAP .|. 0x80) -> case Map.lookup returnedPid currentSyscalls of
                Just callAndArgs -> pure (state{ currentSyscalls = Map.delete returnedPid currentSyscalls }, SyscallStop (SyscallExit callAndArgs))
                Nothing -> do
                  callAndArgs <- getEnteredSyscall returnedPid
                  pure (state{ currentSyscalls = Map.insert returnedPid callAndArgs currentSyscalls }, SyscallStop (SyscallEnter callAndArgs))
            | sig == sigTRAP -> if
                -- For each special PTRACE_EVENT_* we want to catch here,
                -- remember in needs to be enabled first via `ptrace_setoptions`.

                -- Note: One way of many:
                -- Technically we already know that it's `sigTRAP`,
                -- from just above (`waitpidFullStatus` does the the same masking
                -- we do here). `strace` just does an equivalent `switch` on
                -- `status >> 16` to check the `PTRACE_EVENT_*` values).
                -- We express it as `(status>>8) == (SIGTRAP | PTRACE_EVENT_foo << 8)`
                -- because that's how the `ptrace` man page expresses this check.
                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_EXIT `shiftL` 8)) -> do
                    -- As discussed above, the child is still alive when
                    -- this happens, and termination will only occur after
                    -- the child is restarted with ptrace().
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_EXIT)

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_CLONE `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_CLONE (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_FORK `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_FORK (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_VFORK `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_VFORK (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_VFORKDONE `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_VFORK_DONE (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_EXEC `shiftL` 8)) -> do
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_EXEC)

                | otherwise -> do
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_OTHER)

            | isGroupStop -> do
                pure (state, GroupStop sig)

            | otherwise -> do
                -- A signal was sent towards the tracee.
                -- We tell the caller about it, so they can deliver it or
                -- filter it away (chosen by whether they pass it to their
                -- next `ptrace_*` (e.g. `ptrace_syscall`) invocation.
                return (state, SignalDeliveryStop sig) -- continue waiting for syscall

      return (newState, (returnedPid, event))


prettySignal :: Signal -> String
prettySignal s =
  case Map.lookup s signalMap of
    Nothing -> "Unknown signal: " ++ show s
    Just (_longName, shortName) -> shortName


data Syscall
  = KnownSyscall KnownSyscall
  | UnknownSyscall !Word64
  deriving (Eq, Ord, Show)


data SyscallArgs = SyscallArgs
  { arg0 :: !Word64
  , arg1 :: !Word64
  , arg2 :: !Word64
  , arg3 :: !Word64
  , arg4 :: !Word64
  , arg5 :: !Word64
  } deriving (Eq, Ord, Show)


-- A good resource for syscall numbers across all architectures is
-- https://fedora.juszkiewicz.com.pl/syscalls.html

syscallNumberToName_i386 :: Word32 -> Syscall
syscallNumberToName_i386 number =
  case Map.lookup number syscallMap_i386 of
    Just syscall -> KnownSyscall syscall
    Nothing -> UnknownSyscall (fromIntegral number)


syscallNumberToName_x64_64 :: Word64 -> Syscall
syscallNumberToName_x64_64 number =
  case Map.lookup number syscallMap_x64_64 of
    Just syscall -> KnownSyscall syscall
    Nothing -> UnknownSyscall number


-- | Returns the syscall that we just entered after
-- `waitForTraceEvent`.
--
-- PRE:
-- This must be called /only/ after `waitForTraceEvent` made us
-- /enter/ a syscall;
-- otherwise it may throw an `error` when trying to decode opcodes.
getEnteredSyscall :: CPid -> IO (Syscall, SyscallArgs)
getEnteredSyscall cpid = do
  regs <- annotatePtrace "getEnteredSyscall: ptrace_getregs" $ ptrace_getregs cpid
  case regs of
    X86 regs_i386@X86Regs{ orig_eax } -> do
      let syscall = syscallNumberToName_i386 orig_eax
      let args =
            SyscallArgs
              { arg0 = fromIntegral $ ebx regs_i386
              , arg1 = fromIntegral $ ecx regs_i386
              , arg2 = fromIntegral $ edx regs_i386
              , arg3 = fromIntegral $ esi regs_i386
              , arg4 = fromIntegral $ edi regs_i386
              , arg5 = fromIntegral $ ebp regs_i386
              }
      pure (syscall, args)
    X86_64 regs_x86_64@X86_64Regs{ orig_rax, rip } -> do
      -- Check whether it's an x86_64 or a legacy i386 syscall,
      -- and look up syscall number accordingly.

      -- There are 4 ways in total you can make a syscall
      -- (see https://reverseengineering.stackexchange.com/questions/2869/how-to-use-sysenter-under-linux/2894#2894):
      --
      -- - `int $0x80`
      -- - `sysenter` (i586)
      -- - `call *%gs:0x10` (vdso trampoline)
      -- - `syscall` (amd64)
      --
      -- On 32-bit x86 Linux the vdso trampoline prefers `sysenter` over
      -- `int 0x80` when possible.
      -- See also: https://github.com/systemd/systemd/issues/11974

      -- TODO: Implement we need to implement a check for `sysenter` below,
      --       so that we cover all possible ways.

      -- Both the `syscall` instruction and the `int 0x80` instruction
      -- are 2 Bytes:
      --   syscall opcode: 0x0F 0x05
      --   int 0x80 opcode: 0xCD 0x80
      -- See
      --   https://www.felixcloutier.com/x86/syscall
      --   https://www.felixcloutier.com/x86/intn:into:int3:int1
      let syscallLocation = word64ToPtr (rip - 2) -- Word is Word64 on this arch
      -- Note: `peekBytes` has a little-endian-assumption comment in it;
      -- this may not work on big-endian (I haven't checked it)
      opcode <- peekBytes (TracedProcess cpid) syscallLocation 2

      let is_i386_mode = case opcode of
            "\x0F\x05" -> False
            "\xCD\x80" -> True
            _ -> error $ "getEnteredSyscall: BUG: Unexpected syscall opcode: " ++ show opcode

      -- We don't implement x32 support any more, because it may
      -- be removed from the Kernel soon:
      -- https://lkml.org/lkml/2018/12/10/1151

      let (syscallNumber, args) = if
            | is_i386_mode ->
                ( syscallNumberToName_i386 (fromIntegral orig_rax)
                , SyscallArgs
                    { arg0 = fromIntegral $ rbx regs_x86_64
                    , arg1 = fromIntegral $ rcx regs_x86_64
                    , arg2 = fromIntegral $ rdx regs_x86_64
                    , arg3 = fromIntegral $ rsi regs_x86_64
                    , arg4 = fromIntegral $ rdi regs_x86_64
                    , arg5 = fromIntegral $ rbp regs_x86_64
                    }
                )
            | otherwise ->
                ( syscallNumberToName_x64_64 orig_rax
                , SyscallArgs
                    { arg0 = rdi regs_x86_64
                    , arg1 = rsi regs_x86_64
                    , arg2 = rdx regs_x86_64
                    , arg3 = r10 regs_x86_64
                    , arg4 = r8 regs_x86_64
                    , arg5 = r9 regs_x86_64
                    }
                )
      pure (syscallNumber, args)

-- The opcode detection method idea above was motivated by:
--
-- * Michael Bishop (`clever` on freenode)
-- * strace (where it was subsequently removed)
--   * https://superuser.com/questions/834122/how-to-distinguish-syscalls-form-int-80h-when-using-ptrace/1403397#1403397
--   * removal: https://github.com/strace/strace/commit/1f84eefc409291354d0dc7db0866eaf27967da42#diff-3abc305048b4c1c134d1cd2e0eb7799eL113
-- * Linus Torvalds in https://lore.kernel.org/lkml/CA+55aFzcSVmdDj9Lh_gdbz1OzHyEm6ZrGPBDAJnywm2LF_eVyg@mail.gmail.com/


-- | Returns the result of a syscall that we just exited after
-- `waitForTraceEvent`, and the `errno` value on failure.
--
-- Note that the kernel has no concept of `errno`, that is a libc concept.
-- But `strace` and `man 2` syscall pages have the concept. Resources:
--
-- * https://nullprogram.com/blog/2016/09/23/
-- * https://github.com/strace/strace/blob/6170252adc146638c283705c9f252cde66ac224e/linux/x86_64/get_error.c#L26-L28
-- * https://github.com/strace/strace/blob/6170252adc146638c283705c9f252cde66ac224e/negated_errno.h#L13-L14
--
-- PRE:
-- This must be called /only/ after `waitForTraceEvent` made us
-- /exit/ a syscall;
-- the returned values may be memory garbage.
getExitedSyscallResult :: CPid -> IO (Word64, Maybe ERRNO)
getExitedSyscallResult cpid = do
  regs <- annotatePtrace "getExitedSyscallResult: ptrace_getregs" $ ptrace_getregs cpid
  let retVal = case regs of
        X86 X86Regs{ eax } -> fromIntegral eax
        X86_64 X86_64Regs{ rax } -> rax
  -- Using the same logic as musl libc here to translate Linux error return
  -- values into `-1` an `errno`:
  --     https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
  pure $
    if retVal > fromIntegral (-4096 :: CULong)
      then (fromIntegral (-1 :: Int), Just $ ERRNO $ fromIntegral (-retVal))
      else (retVal, Nothing)


foreign import ccall safe "kill" c_kill :: CPid -> Signal -> IO CInt


-- | Sends a signal to a PID the standard way (via @kill()@, not via ptrace).
sendSignal :: CPid -> Signal -> IO ()
sendSignal pid signal = do
  throwErrnoIfMinus1_ "kill" $ c_kill pid signal


-- TODO: Get thise via .hsc or `posix-waitpid` instead

_WNOHANG :: CInt
_WNOHANG = 1

_WUNTRACED :: CInt
_WUNTRACED = 2

_WCONTINUED :: CInt
_WCONTINUED = 8

__WALL :: CInt
__WALL = 0x40000000


-- TODO: Don't rely on this symbol of the posix-waitpid package
foreign import ccall safe "SystemPosixWaitpid_waitpid" c_waitpid :: CPid -> Ptr CInt -> Ptr CInt -> CInt -> IO CPid


doesProcessHaveChildren :: IO Bool
doesProcessHaveChildren = alloca $ \resultPtr -> alloca $ \fullStatusPtr -> do
  -- Non-blocking request, and we want to know of *any* child's existence.
  -- Using `__WALL`, as `man 2 ptrace` recommends and like `strace` does.
  let options = _WNOHANG .|. _WUNTRACED .|. _WCONTINUED .|. __WALL
  res <- c_waitpid (-1) resultPtr fullStatusPtr options
  errno <- getErrno
  if res == -1 && errno == eCHILD
    then return False
    else const True <$> throwErrnoIfMinus1 "c_waitpid" (pure res)
