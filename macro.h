#ifndef __LXCFS_MACRO_H
#define __LXCFS_MACRO_H

#define lxcfs_debug_stream(stream, format, ...)                                \
	do {                                                                   \
		fprintf(stream, "%s: %d: %s: " format, __FILE__, __LINE__,     \
			__func__, __VA_ARGS__);                                \
	} while (false)

#define lxcfs_error(format, ...) lxcfs_debug_stream(stderr, format, __VA_ARGS__)

#ifdef DEBUG
#define lxcfs_debug(format, ...) lxcfs_error(format, __VA_ARGS__)
#else
#define lxcfs_debug(format, ...)
#endif /* DEBUG */

#endif /* __LXCFS_MACRO_H */
