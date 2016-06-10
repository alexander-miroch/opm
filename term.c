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

#define gotoxy(x,y) printf("\033[%d;%dH", (x), (y))

struct termios saved_attributes;
unsigned char password[MAX_PASSWORD_LEN];

void reset_input_mode(void) {
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
}

void clear(void) {
	printf("\033[2J");
	gotoxy(1,1);
	printf("Type passhprase: ");
	fflush(stdout);
}
void clearnew(void) {
	printf("\033[2J");
	gotoxy(1,1);
	printf("You are going to create a new password database.\nPlease specify a passphrase to encrypt it:");
	fflush(stdout);
}

void hide() {
	printf("\033[22;30m");
}

void show() {
	printf("\e[m");
}

void init_term(void) {
	struct termios tattr;

	tcgetattr (STDIN_FILENO, &saved_attributes);
	atexit (reset_input_mode);

	tcgetattr (STDIN_FILENO, &tattr);
	tattr.c_lflag &= ~(ICANON | ECHO);      /* Clear ICANON and ECHO. */
	tattr.c_cc[VMIN] = 1;
	tattr.c_cc[VTIME] = 0;
	tcsetattr (STDIN_FILENO, TCSAFLUSH, &tattr);
}

void echo_off(void) {
	struct termios tattr;

	tcgetattr (STDIN_FILENO, &tattr);
	tattr.c_lflag &= ~ECHO;      /* Clear ICANON and ECHO. */
	tcsetattr (STDIN_FILENO, TCSAFLUSH, &tattr);
}

void echo_on(void) {
	struct termios tattr;

	tcgetattr (STDIN_FILENO, &tattr);
	tattr.c_lflag |= ECHO;      /* Clear ICANON and ECHO. */
	tcsetattr (STDIN_FILENO, TCSAFLUSH, &tattr);
}

unsigned int ask_entry(void) {
	char entry[MAX_ITEM_LEN];
	unsigned int rv;
	int i;

	get_input_entry("Enter item number: ", entry, MAX_ITEM_LEN);
	if (is_empty(entry)) 
		return 0;
	
	for (i = 0; i < strlen(entry); i++) {
		if (!isdigit(entry[i])) 
			return 0;
	}

	rv = atoi(entry);
	if (rv <= 0) 
		return 0;
	
	return rv;
}

void ask_password(int is_new) {
	unsigned short int len, c = 0;
	unsigned char character;

	init_term();

	if (is_new)
		clearnew();
	else
		clear();

	while (1) {
		character = getchar();
		password[c++] = character;
		if (c == MAX_PASSWORD_LEN) {
			c = 0;
			if (is_new)
				clearnew();
			else
				clear();
			continue;
		}
		
		if (character == '\n') {
			password[c - 1] = 0;
			break;
		}

		putchar('*');
        }

        putchar('\n');
        reset_input_mode();
}

int is_empty(char *line) {
	while (*line != '\0') {
		if (isspace(*line) == 0)
			return 0;

		line++;
	}
	
	return 1;
}

void get_input_entry(char *title, char *output, int maxlen) {
	int len;

	printf("%s", title);
	fgets(output, maxlen, stdin);
	
	len = strlen(output) - 1;
	if (len > 0)
		output[len] = '\0';

	if (!len)
		*output = 0;

}

void add_entry(void) {
	struct db_entry de;
	char fmt[16], ipassword[MAX_PASSWORD_LEN];

	memset((void *) &de, 0, sizeof(struct db_entry));	

	get_input_entry("Enter service name: ", de.name, MAX_DB_RECORD_LEN);
	if (is_empty(de.name)) {
		fprintf(stderr, "Service name is required\n");
		exit(1);
	}

	get_input_entry("Enter service login: ", de.login, MAX_LOGIN_LEN);
	if (is_empty(de.login)) {
		fprintf(stderr, "Login is required\n");
		exit(1);
	}

	get_input_entry("Enter service url (optional): ", de.url, MAX_DB_RECORD_LEN);

	echo_off();
	get_input_entry("Enter service password: ", de.password, MAX_PASSWORD_LEN);
	printf("\n");
	get_input_entry("Enter service password (one more time): ", ipassword, MAX_PASSWORD_LEN);
	printf("\n");
	echo_on();
	if (is_empty(de.password)) {
		fprintf(stderr, "Password is required\n");
		exit(1);
	}

	if (strcmp(ipassword, de.password)) {
		fprintf(stderr, "Password mismatch\n");
		exit(1);
	}

	get_input_entry("Enter notes (optional): ", de.notes, MAX_NOTES_LEN);

	if (!db_add_entry(&de)) {
		fprintf(stderr, "Failed to add entry\n");
		exit(1);
	}
}

void pretty_output(struct db_entry *base, int count, int is_verbose) {
	struct db_entry *de = base;
	int i;

#define FMT "%3d    %-20s (%-s %-s) %s\n"

        for (i = 0; i < count; i++) {
		if (is_verbose)
	                printf("%3d    %-20s (%-s %-s) %s\n", i + 1, de->name, de->login, de->url, de->notes);
		else
	                printf("%3d    %s\n", i + 1, de->name);
                de++;
        }
}

