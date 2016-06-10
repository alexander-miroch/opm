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

char short_options[]="AD:HhLvR:cS";

struct option long_options[] = {
    {"verbose",      0, 0, 'v'},
    {"list",     0, 0, 'L'},
    {"add",    0, 0, 'A'},
    {"remove", 1, 0, 'R' },
    {"console", 0, 0, 'c' },
    {"database",    1, 0, 'D'},
    {"stop",	   0, 0, 'S' },
    {"help",      0, 0, 'H'},
    {0, 0, 0, 0}
};

char help_string[] = 
"OPM is a console password manager\n"
"Usage: opm [-vHc] [-D database] [-L | -A | -S | -R number] [service-pattern]\n"
"\t-L, --list\t\tlist records in database\n"
"\t-A, --add\t\tadd item to database\n"
"\t-R, --remove <itemno>\tremove item from database\n"
"\t-D, --database <file>\tspecify database filename\n"
"\t-S, --stop\t\tstop daemon\n"
"\t-c, --console\t\tuse console output rather than Xserver\n"
"\t-v, --verbose\t\tverbose output\n"
"\t-h, --help\t\tthis help\n";
