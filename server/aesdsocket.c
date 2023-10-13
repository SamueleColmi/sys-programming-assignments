#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORTNUM		(9000)
#define BUFFER_SIZE	(8)

static const char *file_path = "/var/tmp/aesdsocketdata";
static const char *dir_path = "/var/tmp/";
static bool daemon_mode = false;
static bool terminate = false;

static void close_connection(int io_fd, struct sockaddr_in addr)
{
	syslog(LOG_INFO, "Closed connection from %s\n", inet_ntoa(addr.sin_addr));
	close(io_fd);
}

static bool reply(int sock_fd, FILE **fp)
{
	char *msg_buffer;
	size_t buf_alloc;
	size_t buf_dim;
	char ch;

	msg_buffer = calloc(BUFFER_SIZE, sizeof(char));
	buf_alloc = BUFFER_SIZE;
	buf_dim = 1;
	if (!msg_buffer)
		return false;

	fseek(*fp, 0, SEEK_SET);

	ch = fgetc(*fp);
	while (ch != EOF)
	{
		if (buf_dim + 1 >= buf_alloc) {
			msg_buffer = realloc(msg_buffer, 2 * buf_alloc * sizeof(char)+1);
			if (!msg_buffer)
				return false;
			buf_alloc *= 2;
		}

		strncat(&msg_buffer[0], &ch, sizeof(char));
		buf_dim++;

		ch = fgetc(*fp);
	}

	if (send(sock_fd, msg_buffer, strlen(msg_buffer), 0) == -1) {
		printf("Error sending message back: (-%d) %s\n", errno, strerror(errno));
		printf("%s\n", msg_buffer);
		return false;
	} else {
		sleep(1);
	}

	free(msg_buffer);
	return true;
}

static bool communicate(int io_fd, FILE **fp)
{
	char *buffer;
	int buf_size;

	buf_size = BUFFER_SIZE * sizeof(char);
	buffer = calloc(BUFFER_SIZE + 1, sizeof(char));

	while(recv(io_fd, buffer, buf_size, 0) > 0) {
		int i = 0;
		while (buffer[i] && i <= BUFFER_SIZE) {
			fprintf(*fp, "%c", buffer[i]);
			if (buffer[i] == '\n') {
				if (!reply(io_fd, fp))
					return false;
			}
			i++;
		}
		memset(buffer, 0, buf_size);
	}

	free(buffer);
	return true;
}

static bool open_file(FILE **fp)
{
	bool ret = false;
	struct stat s;

	if (stat(dir_path, &s) == -1) {
		if (mkdir(dir_path, 0755)) {
			printf("Error creating directory %s: (-%d) %s\n", dir_path, errno, strerror(errno));
			goto exit;
		}
	}

	*fp = fopen(file_path,"a+");
	if (!*fp) {
		printf("Error opening file %s: (-%d) %s\n",file_path, errno, strerror(errno));
		goto exit;
	}

	ret = true;
exit:
	return ret;
}

static void do_communication(int io_fd)
{
	FILE *fp = NULL;

	if (!open_file(&fp))
		return;

	communicate(io_fd, &fp);
	fclose(fp);
}

static int get_connection(int srv_fd, struct sockaddr_in *addr)
{
	socklen_t addrlen = 0;
	int io_fd = -1;

	memset(addr, 0, sizeof(struct sockaddr_in));
	addrlen = sizeof(struct sockaddr_in);
	io_fd = accept(srv_fd, (struct sockaddr *) addr, &addrlen);
	if (io_fd == -1) {
		if (errno != EINTR)
			printf("Error accepting new connection: (-%d) %s\n", errno, strerror(errno));
		goto exit;
	}

	syslog(LOG_INFO, "Accepted connection from %s\n", inet_ntoa(addr->sin_addr));
exit:
	return io_fd;
}

static bool set_socket_server(int sck_fd)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = ntohs(PORTNUM);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sck_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in))) {
		printf("Error binding server socket: (-%d) %s\n", errno, strerror(errno));
		return false;
	}

	if (listen(sck_fd, 1)) {
		printf("Error listening on server socket: (-%d) %s\n", errno, strerror(errno));
		return false;
	}

	return true;
}

static int create_socket()
{
	int sck_fd = -1;
	int optval = 1;

	sck_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (sck_fd == -1) {
		printf("Error creating socket: (-%d) %s\n", errno, strerror(errno));
		goto exit;
	}

	if (setsockopt(sck_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(int))) {
		printf("Error setting socket options: (-%d) %s\n", errno, strerror(errno));
		close(sck_fd);
	}

exit:
	return sck_fd;
}

static int open_server_socket()
{
	int srv_fd = -1;

	srv_fd = create_socket();
	if (srv_fd == -1)
		goto exit;

	if (!set_socket_server(srv_fd))
		close(srv_fd);

exit:
	return srv_fd;
}

static bool run_as_daemon()
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		printf("Error forking daemon: (-%d) %s\n", errno, strerror(errno));
		return false;
	} else if (pid != 0) {
		exit(EXIT_SUCCESS);
	}

	if (setsid() == -1) {
		syslog(LOG_ERR, "Error setsid()\n");
		return false;
	}

	if (chdir("/") == -1) {
		syslog(LOG_ERR, "Error chdir");
		return false;
	}

	for (int i = 0; i < 5; i++)
		close(i);

	open("/dev/null", O_RDWR);
	dup(0);
	dup(0);

	return true;
}

static void run_server()
{
	struct sockaddr_in addr;
	int srv_fd;
	int io_fd;

	srv_fd = open_server_socket();
	if (srv_fd == -1)
		return;

	if (daemon_mode) {
		if (!run_as_daemon())
			goto exit;
		srv_fd = open_server_socket();
	}

	while (!terminate) {
		io_fd = get_connection(srv_fd, &addr);
		if (io_fd == -1)
			continue;

		do_communication(io_fd);
		close_connection(io_fd, addr);
	}

exit:
	close(srv_fd);
}

static void close_server()
{
	syslog(LOG_INFO, "Caught signal, exiting");
	remove(file_path);
}

static void signal_handler(int signum)
{
	if (signum == SIGTERM || signum == SIGINT)
		terminate = true;
}

static bool register_signals()
{
	struct sigaction action;

	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = signal_handler;

	if (sigaction(SIGTERM, &action, NULL) != 0) {
		printf("Error registering actin for SIGTERM: (-%d) %s\n", errno, strerror(errno));
		return false;
	}

	if (sigaction(SIGINT, &action, NULL) != 0) {
		printf("Error registering actin for SIGINT: (-%d) %s\n", errno, strerror(errno));
		return false;
	}

	return true;
}

void check_daemon_mode(int argc, char const *argv[])
{
	if ((argc == 2) && (strcmp("-d", argv[1]) == 0))
		daemon_mode = true;
}

int main(int argc, char const *argv[])
{
	openlog(NULL, 0, LOG_USER);

	check_daemon_mode(argc, argv);

	if (!register_signals())
		return -1;

	run_server();

	close_server();

	closelog();

	return 0;
}
