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

#ifndef NO_X11

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xmu/Atoms.h>

#endif

int x11_started = 0;
int break_please = 0;

void show_password(unsigned char *name, unsigned char *password) {
	printf("%s\n", name);
	fflush(stdout);
	hide();
	printf("%s", password);
	show();
	fflush(stdout);
	printf("<-- you password is hidden here\n");
	
}

int do_password(unsigned char *name, unsigned char *password, int is_console) {
#ifdef NO_X11
	show_password(name, password);
	return 1;
#endif
	if (is_console) {
		show_password(name, password);
		return 1;
	}

	struct parcel pc;

	pc.type = PT_COPY;
        pc.length = strlen(password) + 1; // capture zero byte
        pc.data = (void *) password;

        if (!send_parcel(&pc)) {
		show_password(name, password);
                return 1;
	}

	printf("Password for %s was copied to the buffer\n", name);
	return 1;
}

#ifndef NO_X11

#define MAX_EVENTS 10
int xdaemon(int *fds, pid_t *rpid) {
	int fd;
	pid_t pid;
	Window win;
        Display *dpy;
	ssize_t size, rcv_size;
	char rpassword[MAX_PASSWORD_LEN];
	int x11_fd, efd;
	struct epoll_event ee, events[MAX_EVENTS];

	x11_started = 1;

	pipe(fds);
	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return 0;
	}

	if (pid) {
		*rpid = pid;		
		close(fds[0]);
		return fds[1];
	}

	fd = fds[0];
	close(fds[1]);

	if (!setup_signals())
		return 0;

	dpy = XOpenDisplay(NULL);
	if (!dpy) {
		syslog(LOG_WARNING, "Can not open display");
		return 0;
	}

	win = XCreateSimpleWindow(dpy, DefaultRootWindow(dpy), 0, 0, 1, 1, 0, 0, 0);
	if (!win) {
		XCloseDisplay(dpy);
		syslog(LOG_ERR, "Can not create window");
		return 0;
	}
//	XSelectInput(dpy, win, PropertyChangeMask);
	XSetSelectionOwner(dpy, XA_CLIPBOARD(dpy), win, CurrentTime);

	syslog(LOG_INFO, "Started xdaemon on fd%d", fd);
	x11_fd = ConnectionNumber(dpy);


	efd = epoll_create1(0);
	if (efd < 0) {
		syslog(LOG_ERR, "Can not create epoll");
		return 0;
	}

	ee.data.fd = x11_fd;
	ee.events = EPOLLIN;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, x11_fd, &ee) < 0) {
		syslog(LOG_ERR, "Can not add epoll x11: %s", strerror(errno));
		return 0;
	}

	ee.data.fd = fd;
	ee.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ee) < 0) {
		syslog(LOG_ERR, "Can not add epoll pipe: %s", strerror(errno));
		return 0;
	}
	
	memset(rpassword, 0, MAX_PASSWORD_LEN);
	while (1) {
		int n, i;

		n = epoll_wait (efd, events, MAX_EVENTS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				syslog(LOG_WARNING, "Invalid epoll data");
				continue;
			}

			if (events[i].data.fd == fd) {
				size = read(fd, &rcv_size, sizeof(int));
				if (size != sizeof(int)) {
					syslog(LOG_WARNING, "Communication error size %d", size);
					continue;
				}

				if (rcv_size > MAX_PASSWORD_LEN) {
					syslog(LOG_WARNING, "Corrupter data received");
					continue;
				}

				size = read(fd, rpassword, rcv_size);
				if (size != rcv_size) {
					syslog(LOG_WARNING, "Communication error rcv_size %d", rcv_size);
					continue;
				}
		
				rpassword[rcv_size] = '\0';		

				XSetSelectionOwner(dpy, XA_CLIPBOARD(dpy), win, CurrentTime);
				process_x11_event(dpy, rpassword);
			} else if (events[i].data.fd == x11_fd) {

				if (!rpassword[0])
					continue;

				process_x11_event(dpy, rpassword);
			}
		

		}
	}

	XCloseDisplay(dpy);

	return 1;
}

void process_x11_event(void *data, char *password)  {
	Display *dpy = (Display *) data;
	unsigned int context, numAtoms;
	Window cwin;
	Atom pty;
	XEvent res, evt;
	Atom targets, target;
	ssize_t rcv_size;

	target = XA_STRING;
	targets = XInternAtom(dpy, "TARGETS", False);
	context = 0;
	rcv_size = strlen(password);

	while(XPending(dpy)) {
		XNextEvent(dpy, &evt);
		if (evt.type != SelectionRequest)
			return;

		cwin = evt.xselectionrequest.requestor;
		pty = evt.xselectionrequest.property;

		if (evt.xselectionrequest.target == targets) {
			Atom types[2] = { targets, target };

			numAtoms = (int) (sizeof(types) / sizeof(Atom));
			XChangeProperty(dpy, cwin, pty, XA_ATOM, 32, PropModeReplace, (unsigned char *) types, numAtoms);
		} else {
			XChangeProperty(dpy, cwin, pty, target, 8, PropModeReplace, (unsigned char *) password, rcv_size);
		}

		res.xselection.property = pty;
		res.xselection.type = SelectionNotify;
		res.xselection.display = evt.xselectionrequest.display;
		res.xselection.requestor = cwin;
		res.xselection.selection = evt.xselectionrequest.selection;
		res.xselection.target = evt.xselectionrequest.target;
		res.xselection.time = evt.xselectionrequest.time;

		XSendEvent(dpy, evt.xselectionrequest.requestor, 0, 0, &res);
		XFlush(dpy);
	}
}


void s_handler(int sig, siginfo_t *siginfo, void *context) {
}

int setup_signals(void) {
	struct sigaction act;

	memset (&act, 0, sizeof(act));
	act.sa_sigaction = &s_handler;
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGUSR1, &act, NULL) < 0) {
		syslog(LOG_ERR, "Can not setup signals");
		return 0;
	}

	return 1;
}

#else


int xdaemon(int *fds) {
	close(fds[0]);
	close(fds[1]);
	return 0;
}

int setup_signals(void) {
	return 0;
}

#endif



