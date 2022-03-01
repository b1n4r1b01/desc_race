//
//  spray_stuff.h
//  desc_race_release
//
//  Created by b1n4r1b01 on 01/03/22.
//

#ifndef spray_stuff_h
#define spray_stuff_h

#include <stdio.h>

void iosurface_justin(uint32_t sz);
void iosurface_justin_ptr(uint32_t sz, uint64_t ptr, uint64_t ios, uint64_t leak_ptr);
void yeet_ios(void);
void pipe_spray_adv(uint32_t pipe_size, size_t pipe_count);
void pipe_spray_adv2(uint32_t pipe_size, size_t pipe_count, void *mem);
void close_pipes(void);
void close_pipes_except(int read_pipe);
void* read_pipes(uint32_t read_buffer_sz, int *dat_pipe);
void wirte_to_pipe(int dat_pipe, void *data, uint32_t data_size);
void read_from_pipe(int dat_pipe, void *data, uint32_t data_size);
void kmsg_spray(uint32_t msg_sz, uint32_t count);
void iosurface_stuff(void);
//uint32_t  IOSurfaceRootUserClient_uc(void);
void my_exec2(void);
int kalloc_oolpd(size_t len);

#endif /* spray_stuff_h */
