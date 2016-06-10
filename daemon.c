/*
 * opm - Open Password Manager.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *    Author: Alexander Miroch
 *    Email: <alexander.miroch@gmail.com>
 */

#include "opm.h"

pid_t xdaemon_pid;
int pfd;
int (*handlers[PT_MAX])(void *, int);

void init_handlers(void) {
	int i;

	for (i = 0; i < PT_MAX; i++)
		handlers[i] = NULL;
	
	handlers[PT_ADD_ENTRY] = pt_add_entry;
	handlers[PT_REMOVE_ENTRY] = pt_remove_entry;
	handlers[PT_GET_ENTRY] = pt_get_entry;
	handlers[PT_GET_DB] = pt_get_db;
	handlers[PT_STOP] = pt_stop;
	handlers[PT_COPY] = pt_copy;
}

int pt_stop(void *data, int csk) {
	
	syslog(LOG_INFO, "Stop signal received");

	syslog(LOG_INFO, "Stopping %d",xdaemon_pid);
	if (xdaemon_pid)
		kill(xdaemon_pid, SIGTERM);

	exit(0);
}

int pt_copy(void *data, int csk) {
	char *password = (char *) data;
	int len;

	if (!xdaemon_pid)	
		return 1;

	len = strlen(password);
	if (!len) {
		syslog(LOG_ERR, "Invalid password");
		return 0;
	}

	if (write(pfd, (const void *) &len, sizeof(int)) < 0) {
		syslog(LOG_ERR, "Error writing to pipe: %s", strerror(errno));
		return 0;
	}

	if (write(pfd, (const void *) data, len) < 0) {
		syslog(LOG_ERR, "Error writing to pipe: %s", strerror(errno));
		return 0;
	}

	return 1;
}


int do_daemon(void) {
	pid_t pid;
	int f;

	syslog(LOG_ERR, "DAEMONIZE");
	
	pid = fork();
	if (pid < 0)
		emsg("Error: Can not fork");

	// Parent continue
	if (pid > 0)
		return 0;

	if (setsid() < 0)
		emsg("Error: Can not become a session leader");

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	pid = fork();
	if (pid < 0)
		emsg("Error: Can not fork");

	if (pid > 0)
		exit(0);

	umask(0);
	chdir("/");

	for (f = sysconf(_SC_OPEN_MAX); f > 0; f--)
		close (f);

	openlog("opm", LOG_NDELAY, LOG_DAEMON);
	return 1;
}

int is_daemon_started(void) {
	int fd;

	fd = do_connect();
	if (!fd)
		return 0;

	close(fd);
	return 1;
}

void start_daemon(void) {
	struct sockaddr_un addr;
	int fd, csk, pfds[2];
	int is_db_new = 0;

	*password = 0;

	is_db_new = access(database_file, 0) ? 1 : 0;
	ask_password(is_db_new);
	if (!load_database(is_db_new)) {
		fprintf(stderr, "Can not decrypt or load database\n");
		syslog(LOG_ERR, "Can not load database");
		exit(255);
	}	

	if (!do_daemon())
		return;	

	xdaemon_pid = 0;
	pfd = xdaemon(pfds, &xdaemon_pid);
	if (!pfd) 
		syslog(LOG_WARNING, "Can not start xdaemon");
	

	init_handlers();

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to create socket");
		exit(255);
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	strncpy(&addr.sun_path[1], USOCKET_NAME, sizeof(addr.sun_path) - 2);
	
	unlink(USOCKET_NAME);

	if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
		exit(255);
	}

	if (listen(fd, 32) < 0) {
		syslog(LOG_ERR, "Socket listen error: %s", strerror(errno));
		exit(255);
	
	}
	
	while (1) {
		csk = accept(fd, NULL, NULL);
		if (csk < 0) {
			syslog(LOG_ERR, "Accept error: %s", strerror(errno));
			continue;
		}

		handle_client(csk);

	}
}

void send_error(int csk) {
	send(csk, "ER", 2, 0);
}

void send_ok(int csk) {
	send(csk, "OK", 2, 0);
}

int send_reply(int csk, void *data, int len) {
	int rv;

	rv = send(csk, data, len, 0);
	if (rv < 0) {
		syslog(LOG_ERR, "Send error: %s", strerror(errno));
		return 0;
	}

	if (!rv) {
		syslog(LOG_ERR, "Client disconnected");
		return 0;
	}
	
	return 1;
}

int stop_daemon(void) {
	struct parcel pc;

        pc.type = PT_STOP;
        pc.length = 0;
	pc.data = NULL;
        if (!send_parcel(&pc))
                return 0;

	return 1;
}

void handle_client(int csk) {
	ssize_t bytes;
	unsigned int data[2];
	unsigned char *buf = NULL;
	int (*handler)(void *, int);

	bytes = recv(csk, (void *) data, sizeof(unsigned int) * 2, 0);
	if (bytes < 0) {
		syslog(LOG_ERR, "Handle client error: %s", strerror(errno));
		close(csk);
		return;
	}

	if (!bytes) {
		close(csk);
		return;
	}

	if (data[1] > MAX_PARCEL_LEN || data[0] >= PT_MAX) {
		syslog(LOG_ERR, "Invalid packet");
		close(csk);
		return;
	}

	handler = handlers[data[0]];
	if (!handler) {
		syslog(LOG_ERR, "No handler installed");
		close(csk);
		return;
	}

	if (data[1] > 0) {
		buf = malloc(sizeof(char) * data[1]);
		if (!buf) {
			syslog(LOG_ERR, "Can't alloc memory");
			close(csk);
			return;
		}

		bytes = recv(csk, (void *) buf, data[1], MSG_WAITALL);
		if (bytes < 0) {
			syslog(LOG_ERR, "Handle client error: %s", strerror(errno));
			close(csk);
			free(buf);
			return;
		}

		if (!bytes) {
			syslog(LOG_ERR, "Client closed connection");
			close(csk);
			free(buf);
			return;
		}
	}

	if (!handler(buf, csk)) {
		syslog(LOG_ERR, "Handler failed");
		send_error(csk);
		close(csk);
		free(buf);
		return;
	}

	send_ok(csk);
	close(csk);
}

int do_connect(void) {
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Can't create socket\n");
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	strncpy(&addr.sun_path[1], USOCKET_NAME, sizeof(addr.sun_path) - 2);

	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		return 0;
	}

	return fd;
}


int send_parcel(struct parcel *pc) {
	int fd, rv;

	fd = do_connect();
	if (!fd)
		return 0;

	rv = _send_parcel(fd, pc);
	if (!rv)
		return 0;

	if (!is_ok_reply(fd))
		return 0;

	close(fd);

	return 1;
}

int _send_parcel(int fd, struct parcel *pc) {
	
	if (send(fd, (void *) pc, sizeof(unsigned int) * 2, 0) < 0) {
		close(fd);
		return 0;
	}
	
	if (pc->length) {
		if (send(fd, pc->data, pc->length, 0) < 0) {
			close(fd);
			return 0;
		}
	}

	return 1;
}

int _get_parcel(int fd, struct parcel *pc) {
	unsigned int len;
	char *data;
	int rv;

        rv = recv(fd, &len, sizeof(unsigned int), 0);
        if (!rv)
                return 0;

	if (rv < 0)
		return 0;

	pc->length = len;
	pc->type = PT_REPLY;
	if (pc->length > 0) {
		if (pc->length > MAX_PARCEL_LEN) {
			fprintf(stderr, "Invalid reply\n");
			return 0;
		}

		rv = recv(fd, pc->data, pc->length, MSG_WAITALL);
		if (!rv) 
			return 0;

		if (rv < 0)
			return 0;
	}

	return 1;
}

int is_ok_reply(int fd) {
	int rv;
	char buf[2];

	rv = recv(fd, buf, 2, 0);
	if (!rv)
		return 0;

	if (rv < 0) 
		return 0;

	if (buf[0] == 'O' && buf[1] == 'K')
		return 1;

	return 0;
}

void wait_for_daemon(void) {
	int count = 0;

	do  {
		usleep(MSEC_WAIT_FOR_DAEMON * 1000);
		if (is_daemon_started())
			return;
	
	} while (++count > CNT_WAIT_FOR_DAEMON);
	
	fprintf(stderr, "Daemon wait timeout\n");
	exit(1);
}


