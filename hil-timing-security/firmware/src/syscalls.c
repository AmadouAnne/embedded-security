/* Minimal newlib stubs: the firmware performs no file I/O. */
#include <errno.h>
#include <sys/stat.h>

int _close(int fd) { (void)fd; return -1; }
int _lseek(int fd, int off, int dir) { (void)fd; (void)off; (void)dir; return 0; }
int _read(int fd, char *p, int n) { (void)fd; (void)p; (void)n; return 0; }
int _write(int fd, const char *p, int n) { (void)fd; (void)p; return n; }
int _fstat(int fd, struct stat *st) { (void)fd; st->st_mode = S_IFCHR; return 0; }
int _isatty(int fd) { (void)fd; return 1; }
