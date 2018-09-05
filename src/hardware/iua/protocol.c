/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2018 Sylvain Munaut <tnt@246tNt.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include "protocol.h"

#include <string.h>

static void
send_samples(const struct sr_dev_inst *sdi, uint64_t samples_to_send)
{
        struct sr_datafeed_packet packet;
        struct sr_datafeed_logic logic;
        struct dev_context *devc;

        devc = sdi->priv;

        packet.type = SR_DF_LOGIC;
        packet.payload = &logic;
        logic.length = samples_to_send;
        logic.unitsize = 1;
        logic.data = devc->dat_buf;
        sr_session_send(sdi, &packet);
}

static int
parse_data(const struct sr_dev_inst *sdi, uint8_t *sbuf, int slen)
{
	struct dev_context *devc;
	int sidx=0, didx=0;
	uint8_t cd = 0xff;	// Current data
	int  cr = 0;		// Current repeat
	int exp;

	devc = sdi->priv;

	/* Processing loop */
	while (1)
	{
		/* Load a data */
		if (cd == 0xff) {
			if ((sidx == slen) ||
			    (((sbuf[sidx] & 0xfc) == 0xfc) && ((slen-sidx) < 3)))
				break;

			cd = sbuf[sidx] & 0x03;
			cr = sbuf[sidx] >> 2;

			if (cr == 63) {
				cr = sbuf[sidx+1] | (sbuf[sidx+2] << 8);
				sidx+=3;
			} else
				sidx++;

			cr++;
		}

		/* Expand */
		exp = IUA_DAT_BUFSIZE - didx;
		if (exp > cr)
			exp = cr;

		memset(devc->dat_buf + didx, cd, exp);
		didx += exp;

		/* Need new ? */
		cr -= exp;
		if (!cr)
			cd = 0xff;

		/* Send off the decompressed samples if buffer is full */
		if (didx == IUA_DAT_BUFSIZE) {
			send_samples(sdi, didx);
			didx = 0;
		}
	}

	/* Send any samples left */
	if (didx)
		send_samples(sdi, didx);

	return sidx;
}

SR_PRIV int iua_receive_data(int fd, int revents, void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct sr_serial_dev_inst *serial;
	struct dev_context *devc;
	int len, plen;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	if (revents != G_IO_IN)
		/* Timeout */
		return FALSE;

	serial = sdi->conn;

	/* Read data in buffer */
	len = serial_read_nonblocking(serial, devc->ser_buf + devc->ser_buflen, IUA_SER_BUFSIZE - devc->ser_buflen);
	if (len == 0)
		return TRUE;
	if (len < 0) {
		sr_err("Serial port read error: %d.", len);
		return FALSE;
	}
	devc->ser_buflen += len;

	/* Parse the data */
	plen = parse_data(sdi, devc->ser_buf, devc->ser_buflen);
	if (plen < 0)
		return FALSE;

	/* Save any un-processed part of the buffer */
	if (devc->ser_buflen != plen)
		memmove(devc->ser_buf, devc->ser_buf+plen, devc->ser_buflen-plen);
	devc->ser_buflen -= plen;

	return TRUE;
}
