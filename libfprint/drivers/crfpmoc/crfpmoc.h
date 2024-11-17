/*
 * ChromeOS Fingerprint driver for libfprint
 *
 * Copyright (C) 2024 Abhinav Baid <abhinavbaid@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <config.h>
#include <stdint.h>
#include <sys/ioctl.h>

#ifndef HAVE_UDEV
#error "crfpmoc requires udev"
#endif

#include "fpi-device.h"
#include "fpi-ssm.h"

G_DECLARE_FINAL_TYPE (FpiDeviceCrfpMoc, fpi_device_crfpmoc, FPI, DEVICE_CRFPMOC, FpDevice)


#define CRFPMOC_DRIVER_FULLNAME "ChromeOS Fingerprint Match-on-Chip"

#define CRFPMOC_NR_ENROLL_STAGES 5

/* crfpmoc_ec_command return value for non-success result from EC */
#define CRFPMOC_EECRESULT 1000

/* Resend last response (not supported on LPC). */
#define CRFPMOC_EC_CMD_RESEND_RESPONSE 0x00DB
/* Configure the Fingerprint MCU behavior */
#define CRFPMOC_EC_CMD_FP_MODE 0x0402
#define CRFPMOC_EC_CMD_FP_INFO 0x0403
#define CRFPMOC_EC_CMD_FP_STATS 0x0407
#define CRFPMOC_EC_CMD_FP_SEED 0x0408

/* Finger enrollment session on-going */
#define CRFPMOC_FP_MODE_ENROLL_SESSION (1U << 4)
/* Enroll the current finger image */
#define CRFPMOC_FP_MODE_ENROLL_IMAGE (1U << 5)
/* Try to match the current finger image */
#define CRFPMOC_FP_MODE_MATCH (1U << 6)
/* Reset and re-initialize the sensor. */
#define CRFPMOC_FP_MODE_RESET_SENSOR (1U << 7)
/* special value: don't change anything just read back current mode */
#define CRFPMOC_FP_MODE_DONT_CHANGE (1U << 31)

#define CRFPMOC_FPSTATS_MATCHING_INV (1U << 1)



/* New Fingerprint sensor event, the event data is fp_events bitmap. */
#define CRFPMOC_EC_MKBP_EVENT_FINGERPRINT 5

/* Version of the format of the encrypted templates. */
#define CRFPMOC_FP_TEMPLATE_FORMAT_VERSION 4

/* Constants for encryption parameters */
#define CRFPMOC_FP_CONTEXT_NONCE_BYTES 12
#define CRFPMOC_FP_CONTEXT_USERID_WORDS (32 / sizeof(guint32))
#define CRFPMOC_FP_CONTEXT_TAG_BYTES 16
#define CRFPMOC_FP_CONTEXT_ENCRYPTION_SALT_BYTES 16
#define CRFPMOC_FP_CONTEXT_TPM_BYTES 32

#define CRFPMOC_EC_CMD_FP_FRAME 0x0404

/* constants defining the 'offset' field which also contains the frame index */
#define CRFPMOC_FP_FRAME_INDEX_SHIFT 28
/* Frame buffer where the captured image is stored */
#define CRFPMOC_FP_FRAME_INDEX_RAW_IMAGE 0
/* First frame buffer holding a template */
#define CRFPMOC_FP_FRAME_INDEX_TEMPLATE 1
#define CRFPMOC_FP_FRAME_GET_BUFFER_INDEX(offset) ((offset) >> FP_FRAME_INDEX_SHIFT)
#define CRFPMOC_FP_FRAME_OFFSET_MASK 0x0FFFFFFF


struct crfpmoc_ec_params_fp_frame {
	/*
	 * The offset contains the template index or FP_FRAME_INDEX_RAW_IMAGE
	 * in the high nibble, and the real offset within the frame in
	 * FP_FRAME_OFFSET_MASK.
	 */
	guint32 offset;
	guint32 size;
} __attribute__((packed));

#define CRFPMOC_EC_CMD_GET_PROTOCOL_INFO 0x000B
struct crfpmoc_ec_response_get_protocol_info {
	/* Fields which exist if at least protocol version 3 supported */
	guint32 protocol_versions;
	guint16 max_request_packet_size;
	guint16 max_response_packet_size;
	guint32 flags;
} __attribute__((packed));

struct crfpmoc_ec_host_response {
	guint8 struct_version;
	guint8 checksum;
	guint16 result;
	guint16 data_len;
	guint16 reserved;
} __attribute__((packed));



struct crfpmoc_ec_params_fp_mode
{
  guint32 mode; /* as defined by CRFPMOC_FP_MODE_ constants */
} __attribute__((packed));

struct crfpmoc_ec_response_fp_mode
{
  guint32 mode; /* as defined by CRFPMOC_FP_MODE_ constants */
} __attribute__((packed));

struct crfpmoc_ec_response_fp_stats
{
  guint32 capture_time_us;
  guint32 matching_time_us;
  guint32 overall_time_us;
  struct
  {
    guint32 lo;
    guint32 hi;
  } overall_t0;
  guint8 timestamps_invalid;
  gint8  template_matched;
} __attribute__((packed));

struct crfpmoc_ec_params_fp_seed {
	/*
	 * Version of the structure format (N=3).
	 */
	guint16 struct_version;
	/* Reserved bytes, set to 0. */
	guint16 reserved;
	/* Seed from the TPM. */
	guint8 seed[CRFPMOC_FP_CONTEXT_TPM_BYTES];
} __attribute__((packed));


struct crfpmoc_ec_response_fp_info
{
  /* Sensor identification */
  guint32 vendor_id;
  guint32 product_id;
  guint32 model_id;
  guint32 version;
  /* Image frame characteristics */
  guint32 frame_size;
  guint32 pixel_format;
  guint16 width;
  guint16 height;
  guint16 bpp;
  guint16 errors;
  /* Template/finger current information */
  guint32 template_size; /* max template size in bytes */
  guint16 template_max; /* maximum number of fingers/templates */
  guint16 template_valid; /* number of valid fingers/templates */
  guint32 template_dirty; /* bitmap of templates with MCU side changes */
  guint32 template_version; /* version of the template format */
} __attribute__((packed));

/* Note: used in crfpmoc_ec_response_get_next_data_v1 */
struct crfpmoc_ec_response_motion_sense_fifo_info
{
  /* Size of the fifo */
  guint16 size;
  /* Amount of space used in the fifo */
  guint16 count;
  /* Timestamp recorded in us.
   * aka accurate timestamp when host event was triggered.
   */
  guint32 timestamp;
  /* Total amount of vector lost */
  guint16 total_lost;
  /* Lost events since the last fifo_info, per sensors */
  guint16 lost[0];
};

union __attribute__((packed)) crfpmoc_ec_response_get_next_data_v1
{
  guint8 key_matrix[16];

  /* Unaligned */
  guint32 host_event;
  guint64 host_event64;

  struct
  {
    /* For aligning the fifo_info */
    guint8                                            reserved[3];
    struct crfpmoc_ec_response_motion_sense_fifo_info info;
  } sensor_fifo;

  guint32 buttons;

  guint32 switches;

  guint32 fp_events;

  guint32 sysrq;

  guint32 cec_events;

  guint8  cec_message[16];
};

struct crfpmoc_ec_response_get_next_event_v1
{
  guint8                                     event_type;
  /* Followed by event data if any */
  union crfpmoc_ec_response_get_next_data_v1 data;
} __attribute__((packed));

/*
 * @version: Command version number (often 0)
 * @command: Command to send (CRFPMOC_EC_CMD_...)
 * @outsize: Outgoing length in bytes
 * @insize: Max number of bytes to accept from EC
 * @result: EC's response to the command (separate from communication failure)
 * @data: Where to put the incoming data from EC and outgoing data to EC
 */
struct crfpmoc_cros_ec_command_v2
{
  guint32 version;
  guint32 command;
  guint32 outsize;
  guint32 insize;
  guint32 result;
  guint8  data[0];
};

#define CRFPMOC_CROS_EC_DEV_IOC_V2 0xEC
#define CRFPMOC_CROS_EC_DEV_IOCXCMD_V2 \
        _IOWR (CRFPMOC_CROS_EC_DEV_IOC_V2, 0, struct crfpmoc_cros_ec_command_v2)
#define CRFPMOC_CROS_EC_DEV_IOCEVENTMASK_V2 _IO (CRFPMOC_CROS_EC_DEV_IOC_V2, 2)

/*
 * Host command response codes (16-bit).
 */
enum crfpmoc_ec_status {
  EC_RES_SUCCESS = 0,
  EC_RES_INVALID_COMMAND = 1,
  EC_RES_ERROR = 2,
  EC_RES_INVALID_PARAM = 3,
  EC_RES_ACCESS_DENIED = 4,
  EC_RES_INVALID_RESPONSE = 5,
  EC_RES_INVALID_VERSION = 6,
  EC_RES_INVALID_CHECKSUM = 7,
  EC_RES_IN_PROGRESS = 8, /* Accepted, command in progress */
  EC_RES_UNAVAILABLE = 9, /* No response available */
  EC_RES_TIMEOUT = 10, /* We got a timeout */
  EC_RES_OVERFLOW = 11, /* Table / data overflow */
  EC_RES_INVALID_HEADER = 12, /* Header contains invalid data */
  EC_RES_REQUEST_TRUNCATED = 13, /* Didn't get the entire request */
  EC_RES_RESPONSE_TOO_BIG = 14, /* Response was too big to handle */
  EC_RES_BUS_ERROR = 15, /* Communications bus error */
  EC_RES_BUSY = 16, /* Up but too busy.  Should retry */
  EC_RES_INVALID_HEADER_VERSION = 17, /* Header version invalid */
  EC_RES_INVALID_HEADER_CRC = 18, /* Header CRC invalid */
  EC_RES_INVALID_DATA_CRC = 19, /* Data CRC invalid */
  EC_RES_DUP_UNAVAILABLE = 20, /* Can't resend response */

  EC_RES_COUNT,

  EC_RES_MAX = UINT16_MAX, /**< Force enum to be 16 bits */
} __attribute__((packed));

/* SSM task states and various status enums */

typedef enum {
  ENROLL_SENSOR_ENROLL,
  ENROLL_WAIT_FINGER,
  ENROLL_SENSOR_CHECK,
  ENROLL_COMMIT,
  ENROLL_STATES,
} EnrollStates;

typedef enum {
  VERIFY_SENSOR_MATCH,
  VERIFY_WAIT_FINGER,
  VERIFY_SENSOR_CHECK,
  VERIFY_CHECK,
  VERIFY_STATES,
} VerifyStates;

typedef enum {
  CLEAR_STORAGE_SENSOR_RESET,
  CLEAR_STORAGE_STATES,
} ClearStorageStates;
