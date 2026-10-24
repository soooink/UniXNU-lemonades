/* Bounded observational callbacks. Never alter syscall results or process policy. */
#ifndef UMI_USERSPACE_API_H
#define UMI_USERSPACE_API_H
#include <stdint.h>
#include "umi_early_trace_config.h"
#if UMI_EARLY_TRACE && XNU_BOOT_PROGRESS
void umi_user_write_observe(int fd, uint64_t user_buffer, uint64_t bytes, int error);
void umi_user_path_observe(unsigned operation, uint64_t user_path, int error, int fd);
#else
static inline void umi_user_write_observe(int fd,uint64_t p,uint64_t n,int e) {(void)fd;(void)p;(void)n;(void)e;}
static inline void umi_user_path_observe(unsigned op,uint64_t p,int e,int fd) {(void)op;(void)p;(void)e;(void)fd;}
#endif
#endif
