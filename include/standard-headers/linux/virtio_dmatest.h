/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2022 Linaro Ltd.
 */
#ifndef _LINUX_VIRTIO_DMATEST_H
#define _LINUX_VIRTIO_DMATEST_H

#include "standard-headers/linux/types.h"

struct virtio_dmatest_config {
	uint16_t		num_queues;
};

/* Fill output buffer with pattern */
#define VIRTIO_DMATEST_J_MEMSET		1
/* Return hash of bytes in input buffer */
#define VIRTIO_DMATEST_J_HASH		2

/* Job successful */
#define VIRTIO_DMATEST_S_OK             1
/* Job failed */
#define VIRTIO_DMATEST_S_IO             2
/* Invalid parameters */
#define VIRTIO_DMATEST_S_INVAL          3

/* Common fields */
struct virtio_dmatest_job {
	/* Device readable */
	uint8_t		type;
	uint8_t		reserved1[7 + 8 * 8];

	/* Device writable */
	uint8_t		status;
	uint8_t		reserved2[7 + 8];
};

/*
 * Similar to a call of memset(output_start, (char)input_value,
 *                             output_end - output_start + 1)
 */
struct virtio_dmatest_memset {
	/* Device readable */
	uint8_t		type;		/* VIRTIO_DMATEST_J_MEMSET */
	uint8_t		reserved1[7];

	uint64_t		addr_start;
	uint64_t		addr_end;
	uint64_t		input_value;

	uint8_t		reserved2[5 * 8];

	/* Device writable */
	uint8_t		status;
	uint8_t		reserved3[7 + 8];
};

/*
 * Compute a hash of the buffer, byte by byte, return a 64-bit value.
 * The djb2 algorithm by Dan Bernstein:
 *
 *   uint64_t hash = 5381;
 *
 *   for (i = 0; i < len; i++)
 *	hash = ((hash << 5) + hash) + buf[i]; // hash * 33 + c
 */
#define VIRTIO_DMATEST_HASH_SEED	5381

struct virtio_dmatest_hash {
	/* Device readable */
	uint8_t		type;		/* VIRTIO_DMATEST_J_HASH */
	uint8_t		reserved1[7];

	uint64_t		addr_start;
	uint64_t		addr_end;

	uint8_t		reserved2[6 * 8];

	/* Device writable */
	uint8_t		status;
	uint8_t		reserved3[7];
	uint64_t		hash;
};
#endif
