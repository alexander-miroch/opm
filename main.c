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

void usage(int retcode) {
	FILE *stream = (retcode > 0) ? stderr : stdout;

	fprintf(stream, "%s", help_string);
	exit(retcode);
}

void emsg(const char *format, ...) {
	va_list args;
	va_start(args, format);

	vprintf(format, args);
	va_end(args);

	exit(255);
}

int main(int argc, char *argv[]) {
	int opt, option_index;
	int opt_add_entry = 0;
	int opt_list = 0;
	int opt_verbose = 0;
	int opt_console = 0;
	int opt_remove_entry = 0;
	int opt_stop = 0;
	char *string;

	while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
		switch (opt) {
			case 0x300:
				break;	
			case 'L':
				opt_list = 1;
				break;
			case 'A':
				opt_add_entry = 1;
				break;	
			case 'R':
				opt_remove_entry = atoi(optarg);
				break;
			case 'D':
				database_file = optarg;
				break;
			case 'c':
				opt_console = 1;
				break;
			case 'S':
				opt_stop = 1;
				break;
			case 'v':
				opt_verbose = 1;
				break;
			case 'h':
			case 'H':
				usage(0);	

			case ':':
			case '?':
				usage(1);
		}
	}

	string = argv[optind];
	if (!database_file) {
		pid_t uid;
		struct passwd *pw;

		uid = getuid();
		pw = getpwuid(uid);
		if (!pw) {
			fprintf(stderr, "Can not get your homedir\n");
			exit(1);
		}
		
		database_file = (char *) malloc(sizeof(char) * strlen(pw->pw_dir) + strlen(DEFAULT_DATABASE_FILE) + 1);
		if (!database_file) {
			fprintf(stderr, "Memory allocation error\n");
			exit(1);
		}

		strcpy(database_file, pw->pw_dir);
		strcat(database_file, "/");
		strcat(database_file, DEFAULT_DATABASE_FILE);
	}

	if (strlen(database_file) >= PATH_MAX) {
		fprintf(stderr, "Too long path for database\n");
		exit(1);
	}

	if (opt_stop) {
		if (!is_daemon_started()) {
			fprintf(stderr, "Daemon is not started\n");
			exit(1);
		}
		
		stop_daemon();
		printf("Daemon stopped\n");
		exit(0);
	}

	if (!is_daemon_started()) {
		start_daemon();
		wait_for_daemon();
	}

	if (opt_add_entry) {
		add_entry();
		exit(0);
	}

	if (opt_list) {
		if (!list_db(opt_verbose)) {
			fprintf(stderr, "Failed to list password database\n");
			exit(1);
		}
		exit(0);
	}

	if (opt_remove_entry) {
		if (!remove_entry(opt_remove_entry)) {
			fprintf(stderr, "Failed to remove entry from database\n");
			exit(1);
		}
		exit(0);
	}

	if (!get_entry(string, opt_verbose, opt_console)) {
		fprintf(stderr, "Failed to get entry\n");
		exit(1);
	}

	return 0;
}
