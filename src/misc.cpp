#include <cstring>
#include <algorithm>
//These headers and our headers interfere
//Instead of putting this at the bottom of a file which works I rather put it in it's own file
#include <sys/ioctl.h>
#include <linux/fs.h>
uint64_t GetBlockSize64(int fd)
{
	uint64_t size;
	if (ioctl(fd, BLKGETSIZE64, &size)==-1) {
		printf("Error: GetBlockSize64 %s\n", strerror(errno));
		std::terminate();
	}
	return size;
}
