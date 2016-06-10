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

static unsigned char ivec[] = "A1B2C3D4E5X6Y7Z8abcefdpoqDEFEND1";

int encrypt_db(FILE *f, char *ibuf, char *key, unsigned int size) {
	unsigned int blocksize;
	EVP_CIPHER_CTX ctx;
	unsigned char *read_buf;
	unsigned char *cipher_buf, *cp;
	int out_len, total_buf_size, total_len, len;

	EVP_CipherInit(&ctx, EVP_aes_256_cbc(), key, ivec, 1);
        blocksize = EVP_CIPHER_CTX_block_size(&ctx);
        total_buf_size = CHUNK_SIZE + blocksize;
        cipher_buf = malloc(total_buf_size);
	if (!cipher_buf) {
		syslog(LOG_ERR, "Failed to alloc memory");
		return 0;
	}

	total_len = 0;
	cp = ibuf;
	while (1) {
		len = (total_len + CHUNK_SIZE >= size) ? (size - total_len) : CHUNK_SIZE;	
		if (!EVP_CipherUpdate(&ctx, cipher_buf, &out_len, cp, len)) {
			syslog(LOG_ERR, "Failed to update cipher");
			EVP_CIPHER_CTX_cleanup(&ctx);
			free(cipher_buf);
			return 0;
		}

		if (!fwrite(cipher_buf, sizeof(unsigned char), out_len, f)) {
			syslog(LOG_ERR, "File write error");
			EVP_CIPHER_CTX_cleanup(&ctx);
			free(cipher_buf);
			return 0;
		}

		cp += len;
		total_len += len;

		if (len != CHUNK_SIZE)
			break;
		
	}
		
	if (!EVP_CipherFinal(&ctx, cipher_buf, &out_len)) {
		syslog(LOG_ERR, "Failed to encrypt");
		free(cipher_buf);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}

	if (!fwrite(cipher_buf, sizeof(unsigned char), out_len, f)) {
		syslog(LOG_ERR, "File write error");
		free(cipher_buf);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_cleanup(&ctx);
	free(cipher_buf);

	return 1;
}


char *decrypt_db(FILE *f, char *key, unsigned int *size) {
	unsigned int blocksize;
	EVP_CIPHER_CTX ctx;
	unsigned char *read_buf;
	unsigned char *cipher_buf, *cp, *tmp, *base;
	int out_len, total_buf_size, total_out_len;
	int ft = 1;

	read_buf = malloc(CHUNK_SIZE);
	if (!read_buf) {
		syslog(LOG_ERR, "Failed to alloc memory");
		return NULL;
	}


	EVP_CipherInit(&ctx, EVP_aes_256_cbc(), key, ivec, 0);
	blocksize = EVP_CIPHER_CTX_block_size(&ctx);
	total_buf_size = CHUNK_SIZE + blocksize;
	cipher_buf = malloc(total_buf_size);
	if (!cipher_buf) {
		syslog(LOG_ERR, "Failed to alloc memory");
		free(read_buf);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}

	cp = malloc(total_buf_size);
	if (!cp) {
		syslog(LOG_ERR, "Failed to alloc memory");
		free(cipher_buf);
		free(read_buf);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}

	out_len = total_out_len = 0;
	while (1) {
		int numRead = fread(read_buf, sizeof(unsigned char), CHUNK_SIZE, f);
		if (numRead < 0) {
			syslog(LOG_ERR, "Failed to read from db");
			free(cp);
			free(read_buf);
			free(cipher_buf);
			EVP_CIPHER_CTX_cleanup(&ctx);
			return NULL;
		}

		if (!numRead && ft)
			break;
	
		ft = 0;
		if (!EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead)) {
			syslog(LOG_ERR, "Failed to decrypt db");
			free(cp);
			free(read_buf);
			free(cipher_buf);
			EVP_CIPHER_CTX_cleanup(&ctx);
			return NULL;
		}

		total_buf_size += out_len;

		tmp = realloc(cp, total_buf_size);
		if (!tmp) {
			syslog(LOG_ERR, "Failed to realloc memory");
			free(cp);
			free(read_buf);
			free(cipher_buf);
			EVP_CIPHER_CTX_cleanup(&ctx);
			return NULL;
		}		

		cp = tmp;
		memcpy(cp + total_out_len, cipher_buf, out_len);
		total_out_len += out_len;

		if (numRead < CHUNK_SIZE)
			break;

	}

	if (!ft && !EVP_CipherFinal(&ctx, cipher_buf, &out_len)) {
		syslog(LOG_ERR, "Failed to decrypt db");
		free(cp);
		free(read_buf);
		free(cipher_buf);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;

	}

	free(read_buf);
	free(cipher_buf);
	EVP_CIPHER_CTX_cleanup(&ctx);

	total_out_len += out_len;
	*size = total_out_len;
	
	return cp;
}





