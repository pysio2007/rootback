/*
 * Compatibility definitions for io_uring buffer cloning.
 *
 * The PinTheft PoC expects the newer clone-buffer ABI (src_off/dst_off/nr).
 * Some distro UAPI headers either lack the struct entirely or still carry the
 * older (src_fd/flags/pad) layout. The build helper renames any system struct
 * out of the way and includes this header after <linux/io_uring.h>.
 */
#ifndef ROOTBACK_IO_URING_CLONE_COMPAT
#define ROOTBACK_IO_URING_CLONE_COMPAT

#include <linux/types.h>

#ifndef IORING_REGISTER_CLONE_BUFFERS
#define IORING_REGISTER_CLONE_BUFFERS 30
#endif

struct io_uring_clone_buffers {
	__u32 src_fd;
	__u32 flags;
	__u32 src_off;
	__u32 dst_off;
	__u32 nr;
	__u32 pad[3];
};

#endif
