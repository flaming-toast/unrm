#include <stdio.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <unistd.h>

#define EXT4_IOC_UNRM _IO('f', 22)

int main(int argc, char *argv[]) {
    char cwd[1024];
    int fd;
    DIR *d;

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
	d = opendir(cwd);
	fd = dirfd(d);
	ioctl(fd, EXT4_IOC_UNRM);
    }
}
