// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define FS_SYS_read 0
#define FS_SYS_write 1
#define FS_SYS_open 2
#define FS_SYS_close 3
#define FS_SYS_stat 4
#define FS_SYS_fstat 5
#define FS_SYS_lstat 6
#define FS_SYS_poll 7
#define FS_SYS_lseek 8
#define FS_SYS_mmap 9
#define FS_SYS_mprotect 10
#define FS_SYS_munmap 11
#define FS_SYS_brk 12
#define FS_SYS_rt_sigaction 13
#define FS_SYS_rt_sigprocmask 14
#define FS_SYS_rt_sigreturn 15
#define FS_SYS_ioctl 16
#define FS_SYS_pread64 17
#define FS_SYS_pwrite64 18
#define FS_SYS_readv 19
#define FS_SYS_writev 20
#define FS_SYS_access 21
#define FS_SYS_pipe 22
#define FS_SYS_select 23
#define FS_SYS_sched_yield 24
#define FS_SYS_mremap 25
#define FS_SYS_msync 26
#define FS_SYS_mincore 27
#define FS_SYS_madvise 28
#define FS_SYS_shmget 29
#define FS_SYS_shmat 30
#define FS_SYS_shmctl 31
#define FS_SYS_dup 32
#define FS_SYS_dup2 33
#define FS_SYS_pause 34
#define FS_SYS_nanosleep 35
#define FS_SYS_getitimer 36
#define FS_SYS_alarm 37
#define FS_SYS_setitimer 38
#define FS_SYS_getpid 39
#define FS_SYS_sendfile 40
#define FS_SYS_socket 41
#define FS_SYS_connect 42
#define FS_SYS_accept 43
#define FS_SYS_sendto 44
#define FS_SYS_recvfrom 45
#define FS_SYS_sendmsg 46
#define FS_SYS_recvmsg 47
#define FS_SYS_shutdown 48
#define FS_SYS_bind 49
#define FS_SYS_listen 50
#define FS_SYS_getsockname 51
#define FS_SYS_getpeername 52
#define FS_SYS_socketpair 53
#define FS_SYS_setsockopt 54
#define FS_SYS_getsockopt 55
#define FS_SYS_clone 56
#define FS_SYS_fork 57
#define FS_SYS_vfork 58
#define FS_SYS_execve 59
#define FS_SYS_exit 60
#define FS_SYS_wait4 61
#define FS_SYS_kill 62
#define FS_SYS_uname 63
#define FS_SYS_semget 64
#define FS_SYS_semop 65
#define FS_SYS_semctl 66
#define FS_SYS_shmdt 67
#define FS_SYS_msgget 68
#define FS_SYS_msgsnd 69
#define FS_SYS_msgrcv 70
#define FS_SYS_msgctl 71
#define FS_SYS_fcntl 72
#define FS_SYS_flock 73
#define FS_SYS_fsync 74
#define FS_SYS_fdatasync 75
#define FS_SYS_truncate 76
#define FS_SYS_ftruncate 77
#define FS_SYS_getdents 78
#define FS_SYS_getcwd 79
#define FS_SYS_chdir 80
#define FS_SYS_fchdir 81
#define FS_SYS_rename 82
#define FS_SYS_mkdir 83
#define FS_SYS_rmdir 84
#define FS_SYS_creat 85
#define FS_SYS_link 86
#define FS_SYS_unlink 87
#define FS_SYS_symlink 88
#define FS_SYS_readlink 89
#define FS_SYS_chmod 90
#define FS_SYS_fchmod 91
#define FS_SYS_chown 92
#define FS_SYS_fchown 93
#define FS_SYS_lchown 94
#define FS_SYS_umask 95
#define FS_SYS_gettimeofday 96
#define FS_SYS_getrlimit 97
#define FS_SYS_getrusage 98
#define FS_SYS_sysinfo 99
#define FS_SYS_times 100
#define FS_SYS_ptrace 101
#define FS_SYS_getuid 102
#define FS_SYS_syslog 103
#define FS_SYS_getgid 104
#define FS_SYS_setuid 105
#define FS_SYS_setgid 106
#define FS_SYS_geteuid 107
#define FS_SYS_getegid 108
#define FS_SYS_setpgid 109
#define FS_SYS_getppid 110
#define FS_SYS_getpgrp 111
#define FS_SYS_setsid 112
#define FS_SYS_setreuid 113
#define FS_SYS_setregid 114
#define FS_SYS_getgroups 115
#define FS_SYS_setgroups 116
#define FS_SYS_setresuid 117
#define FS_SYS_getresuid 118
#define FS_SYS_setresgid 119
#define FS_SYS_getresgid 120
#define FS_SYS_getpgid 121
#define FS_SYS_setfsuid 122
#define FS_SYS_setfsgid 123
#define FS_SYS_getsid 124
#define FS_SYS_capget 125
#define FS_SYS_capset 126
#define FS_SYS_rt_sigpending 127
#define FS_SYS_rt_sigtimedwait 128
#define FS_SYS_rt_sigqueueinfo 129
#define FS_SYS_rt_sigsuspend 130
#define FS_SYS_sigaltstack 131
#define FS_SYS_utime 132
#define FS_SYS_mknod 133
#define FS_SYS_uselib 134
#define FS_SYS_personality 135
#define FS_SYS_ustat 136
#define FS_SYS_statfs 137
#define FS_SYS_fstatfs 138
#define FS_SYS_sysfs 139
#define FS_SYS_getpriority 140
#define FS_SYS_setpriority 141
#define FS_SYS_sched_setparam 142
#define FS_SYS_sched_getparam 143
#define FS_SYS_sched_setscheduler 144
#define FS_SYS_sched_getscheduler 145
#define FS_SYS_sched_get_priority_max 146
#define FS_SYS_sched_get_priority_min 147
#define FS_SYS_sched_rr_get_interval 148
#define FS_SYS_mlock 149
#define FS_SYS_munlock 150
#define FS_SYS_mlockall 151
#define FS_SYS_munlockall 152
#define FS_SYS_vhangup 153
#define FS_SYS_modify_ldt 154
#define FS_SYS_pivot_root 155
#define FS_SYS__sysctl 156
#define FS_SYS_prctl 157
#define FS_SYS_arch_prctl 158
#define FS_SYS_adjtimex 159
#define FS_SYS_setrlimit 160
#define FS_SYS_chroot 161
#define FS_SYS_sync 162
#define FS_SYS_acct 163
#define FS_SYS_settimeofday 164
#define FS_SYS_mount 165
#define FS_SYS_umount2 166
#define FS_SYS_swapon 167
#define FS_SYS_swapoff 168
#define FS_SYS_reboot 169
#define FS_SYS_sethostname 170
#define FS_SYS_setdomainname 171
#define FS_SYS_iopl 172
#define FS_SYS_ioperm 173
#define FS_SYS_create_module 174
#define FS_SYS_init_module 175
#define FS_SYS_delete_module 176
#define FS_SYS_get_kernel_syms 177
#define FS_SYS_query_module 178
#define FS_SYS_quotactl 179
#define FS_SYS_nfsservctl 180
#define FS_SYS_getpmsg 181
#define FS_SYS_putpmsg 182
#define FS_SYS_afs_syscall 183
#define FS_SYS_tuxcall 184
#define FS_SYS_security 185
#define FS_SYS_gettid 186
#define FS_SYS_readahead 187
#define FS_SYS_setxattr 188
#define FS_SYS_lsetxattr 189
#define FS_SYS_fsetxattr 190
#define FS_SYS_getxattr 191
#define FS_SYS_lgetxattr 192
#define FS_SYS_fgetxattr 193
#define FS_SYS_listxattr 194
#define FS_SYS_llistxattr 195
#define FS_SYS_flistxattr 196
#define FS_SYS_removexattr 197
#define FS_SYS_lremovexattr 198
#define FS_SYS_fremovexattr 199
#define FS_SYS_tkill 200
#define FS_SYS_time 201
#define FS_SYS_futex 202
#define FS_SYS_sched_setaffinity 203
#define FS_SYS_sched_getaffinity 204
#define FS_SYS_set_thread_area 205
#define FS_SYS_io_setup 206
#define FS_SYS_io_destroy 207
#define FS_SYS_io_getevents 208
#define FS_SYS_io_submit 209
#define FS_SYS_io_cancel 210
#define FS_SYS_get_thread_area 211
#define FS_SYS_lookup_dcookie 212
#define FS_SYS_epoll_create 213
#define FS_SYS_epoll_ctl_old 214
#define FS_SYS_epoll_wait_old 215
#define FS_SYS_remap_file_pages 216
#define FS_SYS_getdents64 217
#define FS_SYS_set_tid_address 218
#define FS_SYS_restart_syscall 219
#define FS_SYS_semtimedop 220
#define FS_SYS_fadvise64 221
#define FS_SYS_timer_create 222
#define FS_SYS_timer_settime 223
#define FS_SYS_timer_gettime 224
#define FS_SYS_timer_getoverrun 225
#define FS_SYS_timer_delete 226
#define FS_SYS_clock_settime 227
#define FS_SYS_clock_gettime 228
#define FS_SYS_clock_getres 229
#define FS_SYS_clock_nanosleep 230
#define FS_SYS_exit_group 231
#define FS_SYS_epoll_wait 232
#define FS_SYS_epoll_ctl 233
#define FS_SYS_tgkill 234
#define FS_SYS_utimes 235
#define FS_SYS_vserver 236
#define FS_SYS_mbind 237
#define FS_SYS_set_mempolicy 238
#define FS_SYS_get_mempolicy 239
#define FS_SYS_mq_open 240
#define FS_SYS_mq_unlink 241
#define FS_SYS_mq_timedsend 242
#define FS_SYS_mq_timedreceive 243
#define FS_SYS_mq_notify 244
#define FS_SYS_mq_getsetattr 245
#define FS_SYS_kexec_load 246
#define FS_SYS_waitid 247
#define FS_SYS_add_key 248
#define FS_SYS_request_key 249
#define FS_SYS_keyctl 250
#define FS_SYS_ioprio_set 251
#define FS_SYS_ioprio_get 252
#define FS_SYS_inotify_init 253
#define FS_SYS_inotify_add_watch 254
#define FS_SYS_inotify_rm_watch 255
#define FS_SYS_migrate_pages 256
#define FS_SYS_openat 257
#define FS_SYS_mkdirat 258
#define FS_SYS_mknodat 259
#define FS_SYS_fchownat 260
#define FS_SYS_futimesat 261
#define FS_SYS_newfstatat 262
#define FS_SYS_unlinkat 263
#define FS_SYS_renameat 264
#define FS_SYS_linkat 265
#define FS_SYS_symlinkat 266
#define FS_SYS_readlinkat 267
#define FS_SYS_fchmodat 268
#define FS_SYS_faccessat 269
#define FS_SYS_pselect6 270
#define FS_SYS_ppoll 271
#define FS_SYS_unshare 272
#define FS_SYS_set_robust_list 273
#define FS_SYS_get_robust_list 274
#define FS_SYS_splice 275
#define FS_SYS_tee 276
#define FS_SYS_sync_file_range 277
#define FS_SYS_vmsplice 278
#define FS_SYS_move_pages 279
#define FS_SYS_utimensat 280
#define FS_SYS_epoll_pwait 281
#define FS_SYS_signalfd 282
#define FS_SYS_timerfd_create 283
#define FS_SYS_eventfd 284
#define FS_SYS_fallocate 285
#define FS_SYS_timerfd_settime 286
#define FS_SYS_timerfd_gettime 287
#define FS_SYS_accept4 288
#define FS_SYS_signalfd4 289
#define FS_SYS_eventfd2 290
#define FS_SYS_epoll_create1 291
#define FS_SYS_dup3 292
#define FS_SYS_pipe2 293
#define FS_SYS_inotify_init1 294
#define FS_SYS_preadv 295
#define FS_SYS_pwritev 296
#define FS_SYS_rt_tgsigqueueinfo 297
#define FS_SYS_perf_event_open 298
#define FS_SYS_recvmmsg 299
#define FS_SYS_fanotify_init 300
#define FS_SYS_fanotify_mark 301
#define FS_SYS_prlimit64 302
#define FS_SYS_name_to_handle_at 303
#define FS_SYS_open_by_handle_at 304
#define FS_SYS_clock_adjtime 305
#define FS_SYS_syncfs 306
#define FS_SYS_sendmmsg 307
#define FS_SYS_setns 308
#define FS_SYS_getcpu 309
#define FS_SYS_process_vm_readv 310
#define FS_SYS_process_vm_writev 311
#define FS_SYS_kcmp 312
#define FS_SYS_finit_module 313
#define FS_SYS_sched_setattr 314
#define FS_SYS_sched_getattr 315
#define FS_SYS_renameat2 316
#define FS_SYS_seccomp 317
#define FS_SYS_getrandom 318
#define FS_SYS_memfd_create 319
#define FS_SYS_kexec_file_load 320
#define FS_SYS_bpf 321
#define FS_SYS_execveat 322
#define FS_SYS_userfaultfd 323
#define FS_SYS_membarrier 324
#define FS_SYS_mlock2 325
#define FS_SYS_copy_file_range 326
#define FS_SYS_preadv2 327
#define FS_SYS_pwritev2 328
#define FS_SYS_pkey_mprotect 329
#define FS_SYS_pkey_alloc 330
#define FS_SYS_pkey_free 331
#define FS_SYS_statx 332
#define FS_SYS_io_pgetevents 333
#define FS_SYS_io_rseq 334