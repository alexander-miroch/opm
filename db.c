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

char *database_file = NULL;
char *mapped_db = NULL;
struct db_header *dh = NULL;

void init_header(void) {

	dh = (struct db_header *) malloc(sizeof(struct db_header));
	if (!dh) {
		syslog(LOG_ERR, "Cant alloc memory");
		exit(1);
	}

	strncpy(dh->signature, DATABASE_SIGNATURE, strlen(DATABASE_SIGNATURE));
	dh->version = VERSION_CODE;
	dh->num_entries = 0;
	dh->entry_size = sizeof(struct db_entry);
}

int load_database(int is_db_new) {
	FILE *f;
	unsigned int size ;
	char *p;

	if (!database_file)
		return 0;

	if (is_db_new) {
		if (!creat(database_file, 0)) {
			syslog(LOG_ERR, "Can not create database file");
			return 0;
		}

		init_header();
		mapped_db = ((unsigned char *) dh) + sizeof(struct db_header);
		sync_db();

		return 1;
	}

	f = fopen(database_file, "r");
	if (!f) {
		syslog(LOG_ERR, "Can not open database file");
		return 0;
	}

	p = decrypt_db(f, password, &size);
	if (!p) {
		syslog(LOG_ERR, "Can not decrypt database");
		fclose(f);
		return 0;
	}

	fclose(f);

	if (!size) {
		init_header();
		mapped_db = ((unsigned char *) dh) + sizeof(struct db_header);
		return 1;
	}
	

	dh = (struct db_header *) p;
	mapped_db = ((unsigned char *) dh) + sizeof(struct db_header);

	if (strncmp(dh->signature, DATABASE_SIGNATURE, strlen(DATABASE_SIGNATURE))) {
		syslog(LOG_ERR, "Invalid passphrase or database is corrupted");
		return 0;
	}

	size -= sizeof(struct db_header);
	if (size % sizeof(struct db_entry)) {
		syslog(LOG_ERR, "Database is corrupted");
		return 0;
	}	

	if (dh->num_entries != (size / sizeof(struct db_entry))) {
		syslog(LOG_ERR, "Database is corrupted");
		return 0;
	}

	if (dh->version > VERSION_CODE) {
		syslog(LOG_ERR, "Database is not supported. Please upgrade the software");
		return 0;
	}

	return 1;
}

int db_add_entry(struct db_entry *de) {

	struct parcel pc;

	pc.type = PT_ADD_ENTRY;
	pc.length = sizeof(*de);
	pc.data = (void *) de;

	if (!send_parcel(&pc)) 
		return 0;

	return 1;
}

int pt_get_entry(void *data, int csk) {
	unsigned int size;
	char *string = (char *) data;
	struct db_entry *de;
	int i, cnt;
	int *idxs, idx;

	if (!mapped_db || !dh) {
		syslog(LOG_ERR, "Database is not initialized");
		return 0;
	}


	idxs = (int *) malloc(sizeof(int) * dh->num_entries);
	if (!idxs) {
		syslog(LOG_ERR, "Can not alloc memory");
		return 0;
	}

	cnt = 0;
	de = (struct db_entry *) mapped_db;
	for (i = 0; i < dh->num_entries; i++, de++) {
		if (!de->name[0]) 
			continue;

		if (!string || !*string) {
			idxs[cnt++] = i;
			continue;
		}
			
		if (strcasestr(de->name, string)) {
			idxs[cnt++] = i;
			continue;
		}

		if (strcasestr(de->login, string)) {
			idxs[cnt++] = i;
			continue;
		}
	}

	size = cnt * sizeof(struct db_entry);
	if (!send_reply(csk, (void *) &size, sizeof(unsigned int))) 
		return 0;

	if (!size)
		return 1;

	for (i = 0; i < cnt; i++) {
		idx = idxs[i];

		de = ((struct db_entry *) mapped_db) + idx;
		if (!send_reply(csk, (void *) de, sizeof(struct db_entry))) 
			return 0;
	}

	return 1;
}

int pt_get_db(void *data, int csk) {
	unsigned int size;
	char *cp;
	int i;

	size = dh->num_entries * sizeof(struct db_entry);
	if (!send_reply(csk, (void *) &size, sizeof(unsigned int))) 
		return 0;

	cp = mapped_db;
	for (i = 0; i < dh->num_entries; i++) {
		if (!*cp) {
			cp += sizeof(struct db_entry);
			continue;
		}
		if (!send_reply(csk, (void *) cp, sizeof(struct db_entry))) 
			return 0;

		cp += sizeof(struct db_entry);
	}

	return 1;
}

int pt_remove_entry(void *data, int csk) {
	struct db_entry *de;
	int *idx = (int *) data;
	int i, j;
	int removed = 0;

	if (!mapped_db || !dh) {
		syslog(LOG_ERR, "Database is not initialized");
		return 0;
	}

	if (!idx) {
		syslog(LOG_ERR, "Invalid index received");
		return 0;
	}

	de = (struct db_entry *) mapped_db;
	for (j = 0, i = 0; i < dh->num_entries; i++) {
		if (de->name[0] == '\0') {
			de++;
			continue;
		}

		++j;
		if (j == *idx) {
			syslog(LOG_ERR, "Removing %s\n",de->name);
			de->name[0] = '\0';
			dh->num_entries--;
			removed = 1;
			break;
		}
	
		de++;
	}
	
	if (!removed)
		return 0;

	if (!sync_db())
		return 0;

	return 1;
}

int pt_add_entry(void *data, int csk) {
	struct db_entry *de = (struct db_entry *) data;
	struct db_entry *fde;
	unsigned char *tmp;
	int size;

	if (!mapped_db || !dh) {
		syslog(LOG_ERR, "Database is not initialized");
		return 0;
	}

	fde = find_free_slot();
	if (!fde) {
		size = sizeof(struct db_header) + (dh->num_entries + 1) * sizeof(struct db_entry);
		tmp = (unsigned char *) realloc(dh, size);
		if (!tmp) {
			free(dh);
			syslog(LOG_ERR, "Memory allocation error");
			return 0;
		}

		dh = (struct db_header *) tmp;
		mapped_db = tmp + sizeof(struct db_header);

		fde = (struct db_entry *) (mapped_db + dh->num_entries * sizeof(struct db_entry));
	}

	dh->num_entries++;

	*fde = *de;
	if (!sync_db())
		return 0;

	return 1;
}

int sync_db(void) {
	FILE *f;
	int fd, size;
	char *cp, *dir;

	if (!database_file) {
		syslog(LOG_ERR, "Database is not defined");
		return 0;
	}

	cp = malloc(strlen(database_file) + 12);
	if (!cp) {
		syslog(LOG_ERR, "No memory");
		return 0;
	}

	strcpy(cp, database_file);
	dir = dirname(cp);

	strcpy(cp, dir);
	strcat(cp, "/.opm.XXXXXX");

	fd = mkstemp(cp);
	if (fd < 0) {
		syslog(LOG_ERR, "Can't create tmp-file in /tmp");
		free(cp);
		return 0;
	}
	
	f = fdopen(fd, "w");
	if (!f) {
		syslog(LOG_ERR, "Can't create tmp-file in /tmp");
		free(cp);
		close(fd);
		return 0;
	}	

	size = sizeof(struct db_header) + sizeof(struct db_entry) * dh->num_entries;
	if (!encrypt_db(f, (char *) dh, password, size)) {
		syslog(LOG_ERR, "Error upon saving db");
		free(cp);
		fclose(f);
		close(fd);
		return 0;
	}
	
	fclose(f);
	close(fd);

	if (rename(cp, database_file) < 0) {
		syslog(LOG_ERR, "Can't rename db: %s", strerror(errno));
		unlink(cp);
		free(cp);
		return 0;
	}

	unlink(cp);
	free(cp);

        return 1;
}

int remove_entry(int idx) {
	struct parcel pc;

	pc.type = PT_REMOVE_ENTRY;
	pc.length = sizeof(idx);
	pc.data = (void *) &idx;

        if (!send_parcel(&pc)) {
                return 0;
	}
	

	return 1;
}

int list_db(int is_verbose) {
	struct parcel pc;
	int rv, fd, i;
	struct db_entry *de;
	unsigned int nums;

        pc.type = PT_GET_DB;
        pc.length = 0;

	fd = do_connect();
	if (!fd)
		return 0;

        if (!_send_parcel(fd, &pc)) {
		close(fd);
                return 0;
	}

	pc.data = malloc(sizeof(char) * MAX_PARCEL_LEN);
	if (!pc.data) {
		close(fd);
		return 0;
	}
	
	if (!_get_parcel(fd, &pc)) {
		close(fd);
		free(pc.data);
		return 0;
	}
	
	close(fd);	

	if (!pc.length) {
		printf("No entries\n");
		free(pc.data);
		return 1;
	}
	
	if (pc.length % sizeof(struct db_entry) || pc.type != PT_REPLY) {
		fprintf(stderr, "Communication error");
		free(pc.data);
		return 0;
	}
		
	nums = pc.length / sizeof(struct db_entry);
	pretty_output((struct db_entry *) pc.data, nums, is_verbose);

	close(fd);
	free(pc.data);

        return 1;
}

int get_entry(unsigned char *string, int is_verbose, int is_console) {
	struct parcel pc;
	int rv, fd, i;
	int slen;
	struct db_entry *de;
	unsigned int nums, choice;
	

	slen = string ? strlen(string) : -1;
	if (slen > MAX_ENTRY_LEN)
		return 0;

	pc.type = PT_GET_ENTRY;
        pc.length = slen + 1;
	pc.data = NULL;
	if (pc.length) {
		pc.data = malloc(sizeof(char) * slen + 1);
		if (!pc.data) 
			return 0;
		
		strncpy(pc.data, string, slen + 1);
	}

        fd = do_connect();
        if (!fd) {
		if (pc.data)
			free(pc.data);
                return 0;
	}

        if (!_send_parcel(fd, &pc)) {
		if (pc.data)
			free(pc.data);
                close(fd);
                return 0;
        }

	if (pc.data)
		free(pc.data);

        pc.data = malloc(sizeof(char) * MAX_PARCEL_LEN);
        if (!pc.data) {
                close(fd);
                return 0;
        }

        if (!_get_parcel(fd, &pc)) {
                close(fd);
                free(pc.data);
                return 0;
        }

        close(fd);

        if (!pc.length) {
                printf("Entry not found\n");
                free(pc.data);
                return 1;
        }

	if (pc.length % sizeof(struct db_entry) || pc.type != PT_REPLY) {
		fprintf(stderr, "Communication error");
		free(pc.data);
		return 0;
        }

        nums = pc.length / sizeof(struct db_entry);

	if (nums > 1) {
		pretty_output((struct db_entry *) pc.data, nums, is_verbose);
		choice = ask_entry();
		if (choice > nums || !choice) {
			fprintf(stderr, "Invalid input\n");
			free(pc.data);
			return 0;
		}

		de = ((struct db_entry *) pc.data) + (choice - 1);

	} else {
		de = (struct db_entry *) pc.data;
	}

	free(pc.data);
	if (!do_password(de->name, de->password, is_console)) {
		fprintf(stderr, "Failed to process password\n");
		return 0;
	}

	return 1;
}


struct db_entry *find_free_slot(void) {
	struct db_entry *de;
	int i;

	if (!mapped_db || !dh) 
		return NULL;

	de = (struct db_entry *) mapped_db;
	for (i = 0; i < dh->num_entries; i++) {
		if (de->name[0] == '\0') 
			return de;
		de++;	
	}

	return NULL;
}

