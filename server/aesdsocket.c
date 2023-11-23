#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PORTNUM		(9000)
#define BUFFER_SIZE	(8)
#define USE_AESD_CHAR_DEVICE

typedef struct node
{
	struct sockaddr_in addr;
	bool complete;
	pthread_t id;
	int io_fd;

	TAILQ_ENTRY(node) nodes;
} node_t;

typedef TAILQ_HEAD(head_s, node) head_t;

#ifdef USE_AESD_CHAR_DEVICE
static const char *device_path = "/dev/aesdchar";
#else
static const char *file_path = "/var/tmp/aesdsocketdata";
static const char *dir_path = "/var/tmp/";
static pthread_mutex_t lock;
#endif

static bool daemon_mode = false;
static bool terminate = false;
static head_t head;
static FILE *fp;

static void close_connection(int io_fd, struct sockaddr_in addr)
{
	/* syslog is thread safe */
	syslog(LOG_INFO, "Closed connection from %s\n", inet_ntoa(addr.sin_addr));
	close(io_fd);
}

static bool reply(int sock_fd)
{
	size_t allocated = BUFFER_SIZE;
	char *msg_buffer = NULL;
	size_t new_size = 0;
	bool ret = false;
	size_t used = 0;
	char *tmp = NULL;
	char *c = NULL;
	int ch = 0;

	printf("REPLY in\n");

	if (fseek(fp, 0, SEEK_SET)) {
		printf("Error: fseek failed: (-%d) %s\n", errno, strerror(errno));
		goto exit;
	}

	msg_buffer = calloc(allocated, sizeof(char));
	if (!msg_buffer) {
		printf("Error: can't allocate memory for msg_buffer: (-%d) %s\n", errno, strerror(errno));
		goto exit;
	}
	msg_buffer[used] = '\0';
	used++; // points to '\0'

	c = calloc(1, sizeof(char));
	if (!c) {
		printf("Error: can't allocate memory for char: (-%d) %s\n", errno, strerror(errno));
		goto free_buf;
	}

	printf("before while:\n---\n%s---\n", msg_buffer);
	bool once = true;
	while ((ch = fgetc(fp)) != EOF) {
		if (once) {
			printf("after while:\n---\n%s---\n", msg_buffer);
			once = false;
		}

		// *c = (char)ch;
		sprintf(c, "%c", ch);
		if (*c == '\0')
			printf("**************EOF**************\n");
		// printf("read: %c (%x)\n", *c, (unsigned)(*c));
		strncat(msg_buffer, c, sizeof(char));
		used++;

		if (used >= allocated) {
			new_size = allocated * 2;

			printf("reallocating %ld\n", new_size);
			tmp = realloc(msg_buffer, new_size);
			if (!tmp) {
				printf("Error: can't reallocate memory for msg_buffer: (-%d) %s\n", errno, strerror(errno));
				goto free_all;
			}
			msg_buffer = tmp;
			allocated = new_size;
		}
	}

	int sended = 0;
	if ((sended = send(sock_fd, msg_buffer, used - 1, 0)) == -1) {
		printf("Error: can't reply: (-%d) %s\n", errno, strerror(errno));
	} else {
		ret = true;
		printf("Sended: %d - used: %ld\n", sended, used);
	}

	printf("buffer:\n----------\n");
	printf("%s", msg_buffer);
	printf("----------\n");

free_all:
	free(c);
	// c = NULL;
free_buf:
	free(msg_buffer);
	// msg_buffer = NULL;
exit:
	return ret;
}

// static bool reply(int sock_fd)
// {
// 	char *msg_buffer;
// 	size_t buf_alloc;
// 	size_t buf_dim;
// 	bool r;
// 	int ch;

// 	r = true;
// 	msg_buffer = calloc(BUFFER_SIZE, sizeof(char));
// 	buf_alloc = BUFFER_SIZE;
// 	buf_dim = 1;
// 	if (!msg_buffer) {
// 		printf("calloc failed");
// 		return false;
// 	}

// 	char *c = malloc(sizeof(char) + 1);
// 	if (!c) {
// 		printf("malloc on char failed\n");
// 		r = false;
// 		goto exit;
// 	}

// 	if (fseek(fp, 0, SEEK_SET)) {
// 		printf("Error: fseek failed: (-%d) %s\n", errno, strerror(errno));
// 	}

// 	printf("New reply\n");
// 	printf("msg_buffer addr: %p\n", msg_buffer);
// 	while ((ch = fgetc(fp)) != EOF)
// 	{
// 		*c = (char)ch;

// 		if (buf_dim + 2 >= buf_alloc) {
// 			size_t new_size = (2 * buf_alloc * sizeof(char)) + 1;
// 			if (new_size >= sizeof(size_t) * CHAR_BIT)
// 				new_size = sizeof(size_t) * CHAR_BIT;

// 			char *tmp;
// 			printf("about to realloc (%p) with size %zu\n", msg_buffer, new_size);
// 			tmp = realloc(msg_buffer, new_size);
// 			if (!tmp) {
// 				r = false;
// 				printf("realloc failed\n");
// 				goto exit;
// 			}

// 			printf("realloc done, msg_buffer addr: %p\n", msg_buffer);
// 			msg_buffer = tmp;
// 			buf_alloc = new_size;
// 		}
// 		printf("read: %c\n", *c);
// 		strncat(msg_buffer, c, sizeof(char));
// 		printf("strncat of %c done - msg_buffer add: %p\n", *c, msg_buffer);
// 		buf_dim++;
// 	}
// 	printf("EOF reached\n");

// 	if (send(sock_fd, msg_buffer, strlen(msg_buffer), 0) == -1) {
// 		printf("Error sending message back: (-%d) %s\n", errno, strerror(errno));
// 		printf("%s\n", msg_buffer);
// 		r = false;
// 	} else {
// 		printf("reply: %s\n", msg_buffer);
// 		// sleep(1);
// 	}

// 	free(c);
// exit:
// 	free(msg_buffer);
// 	return r;
// }

static bool communicate(int io_fd)
{
	char *buffer;
	int buf_size;
	bool r;

	printf("COMMUNICATE in\n");

	r = true;
	buf_size = BUFFER_SIZE * sizeof(char);
	buffer = calloc(BUFFER_SIZE + 1, sizeof(char));	/* +1 for '\0' */
	if (!buffer) {
		printf("Error: can't allocate memory for write buffer\n");
		goto exit;
	}

#ifndef USE_AESD_CHAR_DEVICE
	pthread_mutex_lock(&lock);
#endif

	int rec = 0;
	while((rec = recv(io_fd, buffer, buf_size, 0)) > 0) {

		buffer[rec] = '\0';
		fprintf(fp, "%s", buffer); // scrive fino a '\0' escluso
		if (buffer[rec - 1] == '\n') {
			if (!reply(io_fd)) {
				printf("Error: reply\n");
				r = false;
				goto err;
			}
			printf("reply done\n");
		}
		memset(buffer, 0, buf_size);
	}


		// int i = 0;
		// while (buffer[i] && i <= BUFFER_SIZE) {
		// 	fprintf(fp, "%c", buffer[i]);
		// 	// printf("wrote: %c\n", buffer[i]);
		// 	if (buffer[i] == '\n') {
		// 		if (!reply(io_fd)) {
		// 			printf("ERROR on reply\n");
		// 			r = false;
		// 			goto err;
		// 		}
		// 	}
		// 	i++;
		// }


	// printf("stop receiving\n");

#ifndef USE_AESD_CHAR_DEVICE
	pthread_mutex_unlock(&lock);
#endif

err:
	free(buffer);
exit:
	printf("end communication\n");
	return r;
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

static bool open_file()
{
	bool ret = false;

#ifndef USE_AESD_CHAR_DEVICE
	struct stat s;
	if (stat(dir_path, &s) == -1) {
		if (mkdir(dir_path, 0755)) {
			printf("Error creating directory %s: (-%d) %s\n", dir_path, errno, strerror(errno));
			goto exit;
		}
	}

	fp = fopen(file_path,"a+");
	if (!fp) {
		printf("Error opening file %s: (-%d) %s\n",file_path, errno, strerror(errno));
		goto exit;
	}
#else
	fp = fopen(device_path, "a+");
	if (!fp) {
		printf("Error opening device %s: (-%d) %s\n", device_path, errno, strerror(errno));
		goto exit;
	}
#endif

	ret = true;
exit:
	return ret;
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

static void *thread_func(void *arg)
{
	node_t *e = (node_t *)arg;

	communicate(e->io_fd);
	// printf("Thread %ld completed\n", e->id);
	e->complete = true;

	return NULL;
}

static bool spawn_thread(int io_fd, struct sockaddr_in addr)
{
	node_t *e = NULL;
	int r = true;
	int err;

	e = malloc(sizeof(node_t));
	if (!e) {
		r = false;
		goto exit;
	}

	e->complete = false;
	e->io_fd = io_fd;
	e->addr = addr;
	if ((err = pthread_create(&(e->id), NULL, thread_func, e))) {
		printf("Error spawning worker thread: (-%d) %s\n", err, strerror(err));
		r = false;
		free(e);
		goto exit;
	} else {
		// printf("Thread %ld spawned for connection %s\n", e->id, inet_ntoa(e->addr.sin_addr));
	}

	TAILQ_INSERT_TAIL(&head, e, nodes);

exit:
	return r;
}

static void join_threads()
{
	node_t *e;
	int err;

	TAILQ_FOREACH(e, &head, nodes) {
		if (e->complete) {
			if ((err = pthread_join(e->id, NULL)) != 0)
				printf("Error joining thread with id=%ld: (-%d) %s\n", e->id, err, strerror(err));
			else
				// printf("Thread %ld joined\n", e->id);

			close_connection(e->io_fd, e->addr);
			TAILQ_REMOVE(&head, e, nodes);
			free(e);
			// e = NULL;
		}
	}
}

#ifndef USE_AESD_CHAR_DEVICE
static void *timestamp_func(void *args)
{
	char buf[40];
	time_t tmstp;

	while(true) {
		sleep(10);

		tmstp = time(NULL);

		memset(buf, 0, sizeof(char) * 40);
		strftime(buf, 40, "%a, %d %b %Y %T %z", localtime(&tmstp));

		pthread_mutex_lock(&lock);
		fprintf(fp, "timestamp:%s\n", buf);
		pthread_mutex_unlock(&lock);
	}

	return NULL;
}

static void run_timestamp_thread(pthread_t *tmstmp_id)
{
	int err;

	if ((err = pthread_create(tmstmp_id, NULL, timestamp_func, NULL)) != 0)
		printf("Error spawning timestamp thread: (-%d) %s\n", err, strerror(err));
	// else
		// printf("Timestam thread spawned\n");
}

static void kill_timestamp_thread(pthread_t tmstmp_id)
{
	int err;

	if ((err = pthread_cancel(tmstmp_id)) != 0)
		printf("Error cancelling timestamp thread: (-%d) %s\n", err, strerror(err));
	else
		printf("Timestamp Thread cancelled\n");

	if ((err = pthread_join(tmstmp_id, NULL)) != 0)
		printf("Error joining timestamp thread: (-%d) %s\n", err, strerror(err));
	else
		printf("Timestamp Thread joined\n");
}
#endif

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
			goto close_srv_fd;
		srv_fd = open_server_socket();
		if (srv_fd == -1)
			return;
	}

	// if (!open_file(&fp))
	// 	goto close_fp;

#ifndef USE_AESD_CHAR_DEVICE
	pthread_t tmstmp_id;
	int err;
	if ((err = pthread_mutex_init(&lock, NULL)) != 0) {
		printf("Error initializing mutex: (-%d) %s\n", err, strerror(err));
		goto close_fp;
	}

	run_timestamp_thread(&tmstmp_id);
#endif

	while (!terminate) {
		io_fd = get_connection(srv_fd, &addr);
		if (io_fd == -1)
			continue;

		if (!fp)
			open_file(&fp);

		if (!spawn_thread(io_fd, addr)) {
			close(io_fd); // TODO: exit on destroy mutex (?)
			goto close_fp;
		}

		join_threads();
	}

#ifndef USE_AESD_CHAR_DEVICE
	kill_timestamp_thread(tmstmp_id);

	if ((err = pthread_mutex_destroy(&lock)) != 0)
		printf("Error destroying mutex: (-%d) %s\n", err, strerror(err));
#endif

close_fp:
	fclose(fp);
close_srv_fd:
	close(srv_fd);
}

static void close_server()
{
	node_t *e;

	syslog(LOG_INFO, "Caught signal, exiting");

#ifndef USE_AESD_CHAR_DEVICE
	remove(file_path);
#endif

	while (!TAILQ_EMPTY(&head)) {
		e = TAILQ_FIRST(&head);
		TAILQ_REMOVE(&head, e, nodes);
		free(e);
		e = NULL;
	}
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
	TAILQ_INIT(&head);

	check_daemon_mode(argc, argv);

	if (!register_signals())
		return -1;

	run_server();

	close_server();

	closelog();

	return 0;
}
