#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdlib.h>

extern void* __cosmix_storage_annotation(void* ptr);

int main()
{
    int fd = open("test.dat", O_RDWR | O_TRUNC);
    assert(fd);

printf("After open\n");

    // write a page and a bit more
    //
    char* buf = (char*)malloc(0x1234);
    assert(buf);
    for (int i=0;i<0x1234;i++)
    {
        buf[i] = i % 256;
    }
printf("After malloc\n");
    ssize_t n = write(fd, buf, 0x1234);    
    assert (n == 0x1234);

printf("After write\n");

    // read part of the page - make sure we read the correct data
    lseek(fd, 0, SEEK_SET);
    char buf2[0x10];
    n = read(fd, buf2, 0x10);
    assert(n == 0x10);
    assert(memcmp(buf, buf2, 0x10) == 0);


printf("After read\n");

    // mmap the file
    lseek(fd, 0, SEEK_SET);
    void* addr = __cosmix_storage_annotation(mmap(0, 0x1010, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
    assert(addr != MAP_FAILED);

printf("After mmap\n");
    // read and compare that we read the correct things from the file
    assert(memcmp(addr, buf2, 0x10) == 0);

printf("After mmap read\n");
    // write using the mmap ptr
    unsigned char* x = (unsigned char*)addr;
    for (int i=0;i<0x1010;i++)
    {
        x[i] = (i+1) % 256;
    }

    // read and make sure we read the same thing
    unsigned char* buf3 = (unsigned char*)malloc(0x1010);
    lseek(fd, 0, SEEK_SET);
    n = read(fd, buf3, 0x1010);
    assert(n == 0x1010);

    for (int i=0;i<0x1010;i++)
    {
        assert(buf3[i] == (i+1)%256);
        assert(buf3[i] == x[i]);
    }

    // finally set to diff value, write and make sure we read the same thing from mmap
    for (int i=0;i<0x1010;i++)
    {
        buf3[i]++;
    }

    lseek(fd, 0, SEEK_SET);
    n = write(fd, buf3, 0x1010);
    assert(n == 0x1010);
    assert(memcmp(addr, buf3, 0x1010) == 0);

    assert (munmap(addr, 0x1010) == 0);
    free(buf);
    free(buf3);
    close(fd);

    printf ("Sanity check passed\n");
    return 0;
}
