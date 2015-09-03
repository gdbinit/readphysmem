/*
 *
 *  _____           _ _____ _           _____
 * | __  |___ ___ _| |  _  | |_ _ _ ___|     |___ _____
 * |    -| -_| .'| . |   __|   | | |_ -| | | | -_|     |
 * |__|__|___|__,|___|__|  |_|_|_  |___|_|_|_|___|_|_|_|
 *                             |___|
 *
 * Created by fG! on 27/08/2015.
 * Copyright (c) 2015 fG!. All rights reserved.
 *
 * A small utility to read and write physical memory using AppleHWAccess.kext
 * available since Mavericks
 *
 * Similar to rwmem by Trammell Hudson (https://github.com/osresearch/rwmem)
 * This one uses DirectHW.kext instead
 *
 * main.m
 *
 */

#include <IOKit/IOKitLib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

#define VERSION "0.1"

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#if DEBUG == 0
#   define DEBUG_MSG(fmt, ...) do {} while (0)
#else
#   define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)
#endif

/* stuff we need to use AppleHWAccess */
#define kAppleHWAccessClass "AppleHWAccess"
#define kAppleHWRead 0
#define kAppleHWWrite 1

struct __attribute__ ((packed)) HWRequest
{
    uint32_t width;
    uint64_t offset;
    uint64_t data;
};

static void
usage(void)
{
    OUTPUT_MSG("---[ Usage ]---");
    OUTPUT_MSG("readphysmem -a address -s size [-b read_size] [-o filename]");
    OUTPUT_MSG("\nAvailable Options : ");
    OUTPUT_MSG(" -o filename  file to write binary output to");
    OUTPUT_MSG(" -b 1/2/4/8   read size, default is 8 bytes.");
    OUTPUT_MSG("    note: PCI areas for example must use 4 bytes");
    OUTPUT_MSG("\nDefault output is hexdump if no output file specified.");
    exit(-1);
}

static void
header(void)
{
    OUTPUT_MSG("     _____           _ _____ _           _____           ");
    OUTPUT_MSG("    | __  |___ ___ _| |  _  | |_ _ _ ___|     |___ _____ ");
    OUTPUT_MSG("    |    -| -_| .'| . |   __|   | | |_ -| | | | -_|     |");
    OUTPUT_MSG("    |__|__|___|__,|___|__|  |_|_|_  |___|_|_|_|___|_|_|_|");
    OUTPUT_MSG("                                |___|                    ");
    OUTPUT_MSG("                ReadPhysMem v%s - (c) fG!",VERSION);
    OUTPUT_MSG("-------------------------------------------------------------");
    OUTPUT_MSG("A OS X physical memory reader/writer using AppleHWAccess.kext");
    OUTPUT_MSG("-------------------------------------------------------------");
    OUTPUT_MSG("");
}

static kern_return_t
read_physical_mem(uint64_t address, uint64_t length, uint64_t read_size, uint8_t *out_data)
{
    kern_return_t kr = 0;
    
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }
    
    if (address + length > avail_mem)
    {
        ERROR_MSG("Requested address is out of available memory bounds.");
        return KERN_FAILURE;
    }
    
    io_service_t service = MACH_PORT_NULL;
    /* open connection to the kernel extension */
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleHWAccessClass));
    if (!service)
    {
        ERROR_MSG("Can't find AppleHWAccess service.");
        return KERN_FAILURE;
    }

    io_connect_t connect = MACH_PORT_NULL;
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to open AppleHWAccess IOService.");
        IOObjectRelease(service);
        return KERN_FAILURE;
    }

    /* Trammell on his rwmem does 4 bytes at a time
     * doing 8 here seems to work and it's 50% faster than doing it 4 bytes
     * at a time
     * At least reading the BIOS area contents doesn't give problems
     */
    
    /* XXX: to read from PCI region we need to copy 4 bytes at a time
     * check rwmem warning
     * with 8 bytes with get everything FF
     * but it works with 4 bytes as written by Trammell
     */
    /* XXX: we should also align our reads else this can go wrong on last bytes for PCI region cases */
    uint64_t quotient = length / read_size;
    uint64_t remainder = length % read_size;
    
    uint32_t in_size = (uint32_t)read_size * 8;
    struct HWRequest req_in = {in_size, address};
    struct HWRequest req_out = {0};
    
    size_t req_size = sizeof(struct HWRequest);
    
    while (req_in.offset < address + length - remainder)
    {
        /* selector = 0 for read */
        if ( (kr = IOConnectCallStructMethod(connect, kAppleHWRead, &req_in, req_size, &req_out, &req_size)) != KERN_SUCCESS)
        {
            ERROR_MSG("IOConnectCallStructMethod failed on read: %x", kr);
            break;
        }
        memcpy(out_data, &req_out.data, read_size);
        req_in.offset += read_size;
        out_data += read_size;
    }
    /* read any remaining bytes 1 by 1 */
    if (remainder > 0)
    {
        /* read one byte at a time */
        read_size = 1;
        req_in.width = (uint32_t)read_size * 8;

        while (req_in.offset < address + length)
        {
            /* selector = 0 for read */
            if ( (kr = IOConnectCallStructMethod(connect, kAppleHWRead, &req_in, req_size, &req_out, &req_size)) != KERN_SUCCESS)
            {
                ERROR_MSG("IOConnectCallStructMethod failed on read: %x", kr);
                break;
            }
            memcpy(out_data, &req_out.data, read_size);
            req_in.offset += read_size;
            out_data += read_size;
        }
    }
    
    IOServiceClose(connect);
    IOObjectRelease(connect);
    IOObjectRelease(service);
    return KERN_SUCCESS;
}

static kern_return_t
write_physical_mem(uint64_t address, uint64_t length, uint64_t write_size, uint8_t *in_data)
{
    kern_return_t kr = 0;
    
    uint64_t avail_mem = 0;
    size_t len  = sizeof(avail_mem);
    if ( sysctlbyname("hw.memsize", &avail_mem, &len, NULL, 0) != 0 )
    {
        ERROR_MSG("Failed to retrieve available memory.");
        return KERN_FAILURE;
    }
    
    if (address + length > avail_mem)
    {
        ERROR_MSG("Requested address is out of available memory bounds.");
        return KERN_FAILURE;
    }
    
    io_service_t service = MACH_PORT_NULL;
    /* open connection to the kernel extension */
    service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleHWAccessClass));
    if (!service)
    {
        ERROR_MSG("Can't find AppleHWAccess service.");
        return KERN_FAILURE;
    }
    
    io_connect_t connect = MACH_PORT_NULL;
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to open AppleHWAccess IOService.");
        IOObjectRelease(service);
        return KERN_FAILURE;
    }
    
    /* XXX: to write from PCI region we need to copy 4 bytes at a time ???? */
    /* XXX: we should also align our reads else this can go wrong on last bytes for PCI region cases */
    uint64_t quotient = length / write_size;
    uint64_t remainder = length % write_size;
    
    uint32_t in_size = (uint32_t)write_size * 8;
    struct HWRequest req_in = {in_size, address};
    struct HWRequest req_out = {0};
    
    size_t req_size = sizeof(struct HWRequest);
    
    uint8_t *data_to_write = in_data;
    
    while (req_in.offset < address + length - remainder)
    {
        /* copy data to request structure */
        memcpy((void*)&req_in.data, data_to_write, write_size);
        if ( (kr = IOConnectCallStructMethod(connect, kAppleHWWrite, &req_in, req_size, &req_out, &req_size)) != KERN_SUCCESS)
        {
            ERROR_MSG("IOConnectCallStructMethod failed on write: %x", kr);
            break;
        }
        /* advance data */
        req_in.offset += write_size;
        data_to_write += write_size;
    }
    /* read any remaining bytes 1 by 1 */
    if (remainder > 0)
    {
        /* read one byte at a time */
        write_size = 1;
        req_in.width = (uint32_t)write_size * 8;
        
        while (req_in.offset < address + length)
        {
            /* copy data to request structure */
            memcpy((void*)&req_in.data, data_to_write, write_size);
            if ( (kr = IOConnectCallStructMethod(connect, kAppleHWWrite, &req_in, req_size, &req_out, &req_size)) != KERN_SUCCESS)
            {
                ERROR_MSG("IOConnectCallStructMethod failed on write: %x", kr);
                break;
            }
            req_in.offset += write_size;
            data_to_write += write_size;
        }
    }
    
    IOServiceClose(connect);
    IOObjectRelease(connect);
    IOObjectRelease(service);
    return KERN_SUCCESS;
}

int
main(int argc, char * argv[])
{
    @autoreleasepool {

        header();
        
        static struct option long_options[]={
            { "address", required_argument, NULL, 'a' },
            { "size", required_argument, NULL, 's' },
            { "out", required_argument, NULL, 'o' },
            { "readsize", required_argument, NULL, 'b' },
            { "in", required_argument, NULL, 'i' },
            { "write", no_argument, NULL, 'w' },
            { NULL, 0, NULL, 0 }
        };
        
        int option_index = 0;
        int c = 0;
        char *outputname = NULL;
        char *input_name = NULL;
        
        uint64_t address = 0;
        size_t size = 0;
        /* default is 8 bytes */
        uint64_t read_size = 8;
        uint64_t do_write = 0;
        
        /* process command line options */
        while ((c = getopt_long(argc, argv, "a:s:o:b:i:wh", long_options, &option_index)) != -1)
        {
            switch (c)
            {
                case 'h':
                    usage();
                    return EXIT_FAILURE;
                case 'o':
                    outputname = optarg;
                    break;
                case 'i':
                    input_name = optarg;
                    break;
                case 'a':
                    address = strtoul(optarg, NULL, 0);
                    break;
                case 's':
                    size = strtoul(optarg, NULL, 0);
                    break;
                case 'b':
                    read_size = strtoull(optarg, NULL, 0);
                    break;
                case 'w':
                    do_write = 1;
                    break;
                default:
                    usage();
                    return EXIT_FAILURE;
            }
        }
        
        if (argc < 3)
        {
            usage();
        }
        
        /* we need to run this as root */
        if (getuid() != 0)
        {
            ERROR_MSG("Must be run as root to talk to AppleHWAccess.kext!");
            return EXIT_FAILURE;
        }
        
        if (size == 0)
        {
            ERROR_MSG("Size is zero. That doesn't make any sense, does it?");
            return EXIT_FAILURE;
        }

        switch (read_size) {
            case 1:
            case 2:
            case 4:
            case 8:
                break;
            default:
                ERROR_MSG("Invalid read size, must be 1,2,4,8 bytes.");
                return EXIT_FAILURE;
        }
        
        /* retrive amount of physical memory */
        uint64_t installed_mem = 0;
        size_t len  = sizeof(installed_mem);
        if (sysctlbyname("hw.memsize", &installed_mem, &len, NULL, 0) != 0)
        {
            ERROR_MSG("Failed to retrieve available memory.");
            return EXIT_FAILURE;
        }
        /* are we trying to read out of bounds? */
        if (address + size > installed_mem)
        {
            ERROR_MSG("Requested address is out of available memory bounds.");
            return EXIT_FAILURE;
        }

        /* XXX: check out requests that we know will lead to crashes? */

        if (do_write == 1)
        {
            if (input_name == NULL)
            {
                ERROR_MSG("No input file to write!");
                return EXIT_FAILURE;
            }
            OUTPUT_MSG("Trying to write contents of %s into physical address 0x%llx...", input_name, address);
            int fd = -1;
            fd = open(input_name, O_RDONLY);
            if (fd < 0)
            {
                ERROR_MSG("Cannot open %s for input.", input_name);
                return EXIT_FAILURE;
            }
            uint8_t *input_buf = NULL;
            struct stat statbuf = {0};
            if (fstat(fd, &statbuf) < 0)
            {
                ERROR_MSG("Can't fstat %s: %s.", input_name, strerror(errno));
                close(fd);
                return EXIT_FAILURE;
            }
            if ((input_buf = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
            {
                ERROR_MSG("Mmap failed on %s: %s", input_name, strerror(errno));
                close(fd);
                return KERN_FAILURE;
            }
            close(fd);
            if (write_physical_mem(address, size, read_size, input_buf) != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write to physical memory.");
                munmap(input_buf, statbuf.st_size);
                return EXIT_FAILURE;
            }
            OUTPUT_MSG("All done! Writing (should have been) successful.");
        }
        else
        {
            OUTPUT_MSG("Trying to read contents of physical address 0x%llx...", address);
            uint8_t *data_buffer = calloc(1, size);
            if (data_buffer == NULL)
            {
                ERROR_MSG("Failed to allocate output buffer.");
                return EXIT_FAILURE;
            }
            
            if (read_physical_mem(address, size, read_size, data_buffer) != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to read physical memory.");
                free(data_buffer);
                return EXIT_FAILURE;
            }
            
            /* finally, write to filename or dump to the screen */
            if (outputname != NULL)
            {
                FILE *outputfile = NULL;
                if ( (outputfile = fopen(outputname, "wb")) == NULL)
                {
                    ERROR_MSG("Cannot open %s for output!", outputname);
                    return EXIT_FAILURE;
                }
                fwrite(data_buffer, size, 1, outputfile);
                fclose(outputfile);
            }
            else
            {
                OUTPUT_MSG("Memory hex dump @ 0x%llx:\n", address);
                
                uint64_t row_address = address;
                /* how many 16 columns rows? */
                uint64_t rows = size / 16;
                uint64_t last_row = size % 16;
                /* hold the position to print inside the buffer */
                size_t cur_pos = 0;
                /* print all 16 bytes rows */
                for (uint64_t y = 0; y < rows; y++)
                {
                    printf("0x%llx ",row_address);
                    for (int x = 0; x < 16; x++, cur_pos++)
                    {
                        printf("%02x ", data_buffer[cur_pos]);
                    }
                    cur_pos -= 16;
                    printf("|");
                    for (int x = 0; x < 16; x++, cur_pos++)
                    {
                        printf("%c", isascii(data_buffer[cur_pos]) && isprint(data_buffer[cur_pos]) ? data_buffer[cur_pos] : '.');
                    }
                    printf("|\n");
                    row_address += 16;
                }
                /* whatever is left that is less than a 16 bytes column */
                if (last_row > 0)
                {
                    printf("0x%llx ",row_address);
                    for (uint64_t x = 0; x < last_row; x++, cur_pos++)
                    {
                        printf("%02x ", data_buffer[cur_pos]);
                    }
                    /* make it aligned to 16 byte column */
                    for (uint64_t x = last_row; x < 16; x++)
                    {
                        fprintf(stdout, "   ");
                    }
                    cur_pos -= last_row;
                    printf("|");
                    for (int x = 0; x < 16; x++, cur_pos++)
                    {
                        printf("%c", isascii(data_buffer[cur_pos]) && isprint(data_buffer[cur_pos]) ? data_buffer[cur_pos] : '.');
                    }
                    printf("|\n");
                }
                printf("\n");
            }
            free(data_buffer);
            OUTPUT_MSG("All done...");
        }
    }
    
    return EXIT_SUCCESS;
}
