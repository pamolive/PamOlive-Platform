/* Synthetic errors injected into the isolated sed smoke process only. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/acl.h>

acl_t
acl_get_fd (int fd)
{
  if (getenv ("PAMOLIVE_TEST_SED_ACL_READ_UNSUPPORTED"))
    {
      errno = EOPNOTSUPP;
      return NULL;
    }
  acl_t (*read_acl) (int) = dlsym (RTLD_NEXT, "acl_get_fd");
  if (!read_acl)
    abort ();
  return read_acl (fd);
}

int
acl_set_fd (int fd, acl_t acl)
{
  if (getenv ("PAMOLIVE_TEST_SED_ACL_WRITE_DENIED"))
    {
      errno = EPERM;
      return -1;
    }
  int (*write_acl) (int, acl_t) = dlsym (RTLD_NEXT, "acl_set_fd");
  if (!write_acl)
    abort ();
  return write_acl (fd, acl);
}
