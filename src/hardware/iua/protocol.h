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

#ifndef LIBSIGROK_HARDWARE_IUA_PROTOCOL_H
#define LIBSIGROK_HARDWARE_IUA_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "iua"

#define SERIAL_WRITE_TIMEOUT_MS 10

#define IUA_SER_BUFSIZE 1024
#define IUA_DAT_BUFSIZE 4 * 1024 * 1024

struct dev_context {
	/* Settings */
	uint64_t cur_samplerate;

	/* Serial data buffer */
	uint8_t ser_buf[IUA_SER_BUFSIZE];
	int ser_buflen;

	/* Sample data buffer */
	uint8_t dat_buf[IUA_DAT_BUFSIZE];
};

SR_PRIV int iua_receive_data(int fd, int revents, void *cb_data);

#endif
