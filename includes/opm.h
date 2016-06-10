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


#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <termios.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <libgen.h>
#include <linux/limits.h>
#include <pwd.h>
#include <sys/epoll.h>

extern char short_options[];
extern struct option long_options[];

extern char help_string[];

void usage(int);

#define MAX_DB_RECORD_LEN 128
#define MAX_LOGIN_LEN	  64
#define MAX_PASSWORD_LEN  64
#define MAX_NOTES_LEN	  256
#define MAX_ENTRY_LEN	  MAX_NOTES_LEN

struct db_entry {
	char name[MAX_DB_RECORD_LEN];
	char url[MAX_DB_RECORD_LEN];
	char login[MAX_LOGIN_LEN], password[MAX_PASSWORD_LEN];
	char notes[MAX_NOTES_LEN];	
};


void emsg(const char *, ...);

void start_daemon(void);
int stop_daemon(void);
int do_daemon(void);
int xdaemon(int *, pid_t *);
void wait_for_daemon(void);
int is_daemon_started(void);
void handle_client(int);
void send_error(int);
void send_ok(int);
int do_connect(void);

#define USOCKET_NAME "/com/opm/opmsock"
#define MSEC_WAIT_FOR_DAEMON 100
#define CNT_WAIT_FOR_DAEMON 10

void reset_input_mode(void);
void clear(void);
void clearnew(void);
void show_password(unsigned char *, unsigned char *);
void ask_password(int);
unsigned int ask_entry(void);
void add_entry(void);
void init_term(void);
void get_input_entry(char *, char *, int);
int is_empty(char *);
void pretty_output(struct db_entry *, int, int);

extern unsigned char password[MAX_PASSWORD_LEN];


extern char *database_file;
extern char *mapped_db;
extern unsigned int num_entries;

#define DATABASE_SIGNATURE "OPMDBDEX"
#define VERSION_CODE 0x101

struct db_header {
	unsigned char signature[8];
	unsigned int version;
	unsigned int num_entries;
	unsigned int entry_size;
	unsigned char reserved[16384];
} __attribute__((packed));

void init_header(void);

#define DEFAULT_DATABASE_FILE ".opm.db"
#define CHUNK_SIZE 4096
int load_database(int);
char *decrypt_db(FILE *, char *, unsigned int *);
int encrypt_db(FILE *, char *, char *, unsigned int);
int db_add_entry(struct db_entry *);
void init_handlers(void);
int pt_add_entry(void *, int);
int pt_remove_entry(void *, int);
int pt_get_entry(void *, int);
int pt_get_db(void *, int);
int pt_stop(void *, int);
int pt_copy(void *, int);
struct db_entry *find_free_slot(void);
int sync_db(void);
int list_db(int);
int remove_entry(int);
int get_entry(unsigned char *, int, int);

enum {
	PT_NONE,
	PT_ADD_ENTRY,
	PT_REMOVE_ENTRY,
	PT_GET_ENTRY,
	PT_GET_DB,
	PT_REPLY,
	PT_STOP,
	PT_COPY,
	PT_MAX
};

extern int (*handlers[PT_MAX])(void *, int);

struct parcel {
	unsigned int type;
	unsigned int length;
	void *data;
};

#define MAX_PARCEL_LEN		32768
#define MAX_ITEM_LEN		16

int send_parcel(struct parcel *);
int _send_parcel(int csk, struct parcel *pc);
int _get_parcel(int csk, struct parcel *pc);
int is_ok_reply(int);
int send_reply(int, void *, int);


int do_password(unsigned char *, unsigned char *, int);
int setup_signals(void);
void s_handler(int, siginfo_t *, void *);
void process_x11_event(void *, char *);
