#if SYZ_EXECUTOR

#include <fcntl.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

long syz_bpf_attach_tp(volatile long prog_fd)
{
	struct perf_event_attr p_attr;
	char config_str[256];
	int perf_event_fd, trace_id_fd;
	int bytes_read;
	int dupfd;

	trace_id_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_dup/id", O_RDONLY);
	if (trace_id_fd < 0) {
		debug("%s: openat() returned %d\n", __func__, trace_id_fd);
		return trace_id_fd;
	}

	bytes_read = read(trace_id_fd, config_str, sizeof(config_str));
	close(trace_id_fd);
	if (bytes_read < 0) {
		debug("%s: read() returned %d\n", __func__, bytes_read);
		return bytes_read;
	}

	__builtin_memset(&p_attr, 0, sizeof(p_attr));
	p_attr.type = PERF_TYPE_TRACEPOINT;
	p_attr.size = PERF_ATTR_SIZE_VER5;
	p_attr.config = atoi(config_str);
	perf_event_fd = syscall(__NR_perf_event_open, &p_attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (perf_event_fd < 0) {
		debug("%s: perf_event_open() returned %d\n", __func__, perf_event_fd);
		return perf_event_fd;
	}
	ioctl(perf_event_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	ioctl(perf_event_fd, PERF_EVENT_IOC_ENABLE, 0);

	debug("%s: bpf_prog %ld attached\n", __func__, prog_fd);

	dupfd = dup(0);
	(void)dupfd;

	return 0;
}

#endif
