#ifndef referencemonit_h__
#define referencemonit_h__

extern int my_open(const char *path, int oflags, ...);
extern ssize_t my_read(int fildes, void *buf, size_t nbyte);
extern ssize_t my_write(int fildes, void *buf, size_t nbyte);
extern ssize_t my_close(int fildes);

#endif // referencemonit_h__