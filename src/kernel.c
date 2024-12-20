#include "kernel.h"
#include <stddef.h>
#include <stdint.h>
#include "idt/idt.h"
#include "memory/heap/kheap.h"
#include "memory/paging/paging.h"
#include "string/string.h"
#include "fs/file.h"
#include "disk/disk.h"
#include "fs/pparser.h"
#include "disk/streamer.h"

uint16_t* video_mem = 0;
uint16_t terminal_row = 0;
uint16_t terminal_col = 0;

uint16_t terminal_make_char(char c, char colour)
{
    return (colour << 8) | c;
}

void terminal_putchar(int x, int y, char c, char colour)
{
    video_mem[(y * VGA_WIDTH) + x] = terminal_make_char(c, colour);
}

void terminal_writechar(char c, char colour)
{
    if (c == '\n')
    {
        terminal_row += 1;
        terminal_col = 0;
        return;
    }

    terminal_putchar(terminal_col, terminal_row, c, colour);
    terminal_col += 1;
    if (terminal_col >= VGA_WIDTH)
    {
        terminal_col = 0;
        terminal_row += 1;
    }
}
void terminal_initialize()
{
    video_mem = (uint16_t*)(0xB8000);
    terminal_row = 0;
    terminal_col = 0;
    for (int y = 0; y < VGA_HEIGHT; y++)
    {
        for (int x = 0; x < VGA_WIDTH; x++)
        {
            terminal_putchar(x, y, ' ', 0);
        }
    }   
}



void print(const char* str)
{
    size_t len = strlen(str);
    for (int i = 0; i < len; i++)
    {
        terminal_writechar(str[i], 15);
    }
}

void printf(const char* str, const char* param1)
{
    size_t len = strlen(str);
    //bool escape_sequence = false;
    for (int i = 0; i < len; i++)
    {
        // if(str[i] == '\\')
        // {
        //     escape_sequence = true;
        // }
        if(str[i] == '%')
        {
            if((i + 1) != len)
            {
                if(str[i + 1] == 's')
                {
                    print(param1);
                    i+=2; // skip over format specifer
                }
                // if(str[i + 1] == 'd')
                // {
                //     print((int)param1);
                //     i+=2; // skip over format specifer
                // }
                // if(str[i + 1] == 'p')
                // {
                //     print("0x");
                //     print((int)param1);
                //     i+=2; // skip over format specifer
                // }
            }
        }
        terminal_writechar(str[i], 15);
    }
}


static struct paging_4gb_chunk* kernel_chunk = 0;
void kernel_main()
{
    terminal_initialize();
    print("Hello from laptop!\ntest\n");

    // Initialize the heap
    kheap_init();

    // Initialize filesystems
    fs_init();

    // Search and initialize the disks
    disk_search_and_init();

    // Initialize the interrupt descriptor table
    idt_init();

    // Setup paging
    kernel_chunk = paging_new_4gb(PAGING_IS_WRITEABLE | PAGING_IS_PRESENT | PAGING_ACCESS_FROM_ALL);
    
    // Switch to kernel paging chunk
    paging_switch(paging_4gb_chunk_get_directory(kernel_chunk));

    // Enable paging
    enable_paging();
    
    // Enable the system interrupts
    //enable_interrupts();
    int fd = fopen("0:/data/hello.txt", "r");
    if (fd)
    {
        print("\nWe opened hello.txt, it was inside test folder!\n");
        
        void* out = kzalloc(1); // allocate 4096 bytes
        // read into out, element size 1 bytes, 10 of 1 bytes, from the filedescriptor
        fread(out, 1, 50, fd);
        printf("I just got this: %s, from a file?\n", out);
    }else{
        print("Something did not work...\n");
    }

    int fd2 = fopen("0:/data/bello.txt", "r");
    if (fd2)
    {
        print("\nWe opened hello.txt, it was inside test folder!\n");
        
        void* out = kzalloc(1); // allocate 4096 bytes
        // read into out, element size 1 bytes, 10 of 1 bytes, from the filedescriptor
        fread(out, 1, 50, fd2);
        printf("I just got this: %s, from a file?\n", out);
    }else{
        print("Something did not work...\n");
    }
    while(1) {}
}