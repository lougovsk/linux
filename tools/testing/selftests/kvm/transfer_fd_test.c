// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test VM file descriptor transfer via Unix Domain Sockets.
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "test_util.h"
#include "kvm_util.h"

static void send_fd(int sock, int fd)
{
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];
	struct iovec io = {
		.iov_base = "a",
		.iov_len = 1,
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));

	*((int *)CMSG_DATA(cmsg)) = fd;

	TEST_ASSERT(sendmsg(sock, &msg, 0) == 1, "sendmsg failed, errno: %d", errno);
}

static int recv_fd(int sock)
{
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];
	char dummy;
	struct iovec io = {
		.iov_base = &dummy,
		.iov_len = 1,
	};
	int fd;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	TEST_ASSERT(recvmsg(sock, &msg, 0) == 1, "recvmsg failed, errno: %d", errno);

	cmsg = CMSG_FIRSTHDR(&msg);
	TEST_ASSERT(cmsg && cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS, "No FD received");

	fd = *((int *)CMSG_DATA(cmsg));
	return fd;
}

int main(int argc, char **argv)
{
	pthread_barrierattr_t attr;
	pthread_barrier_t *barrier;
	int socks[2];
	pid_t pid;
	int ret;

	barrier = mmap(NULL, sizeof(*barrier), PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(barrier != MAP_FAILED, "mmap failed, errno: %d", errno);

	ret = pthread_barrierattr_init(&attr);
	TEST_ASSERT(!ret, "pthread_barrierattr_init failed, ret: %d", ret);

	ret = pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	TEST_ASSERT(!ret, "pthread_barrierattr_setpshared failed, ret: %d", ret);

	ret = pthread_barrier_init(barrier, &attr, 2);
	TEST_ASSERT(!ret, "pthread_barrier_init failed, ret: %d", ret);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
	TEST_ASSERT(ret == 0, "socketpair failed, errno: %d", errno);

	pid = fork();
	TEST_ASSERT(pid >= 0, "fork failed, errno: %d", errno);

	if (pid > 0) {
		struct kvm_vm *vm;

		close(socks[1]);

		vm = vm_create_barebones();

		send_fd(socks[0], vm->fd);
		close(socks[0]);

		/* Drop *ALL* refs to this VM. */
		close(vm->fd);
		close(vm->kvm_fd);
		if (vm->stats.fd >= 0)
			close(vm->stats.fd);

		pthread_barrier_wait(barrier);

		/* Trigger the exit_mm() side of the race. */
		_exit(0);
	} else {
		int vm_fd;

		close(socks[0]);

		vm_fd = recv_fd(socks[1]);
		close(socks[1]);

		pthread_barrier_wait(barrier);

		/* Drop the final ref of the VM, triggering the kvm_destroy_vm()
		 * side of the race. */
		close(vm_fd);
	}

	return 0;
}
