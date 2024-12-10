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

#define FP_COMPONENT "crfpmoc"

#include <glib-unix.h>
#include <sys/fcntl.h>
#include <sys/poll.h>

#include "drivers_api.h"
#include "crfpmoc.h"

struct _FpiDeviceCrfpMoc
{
  FpDevice      parent;
  FpiSsm       *task_ssm;
  GCancellable *interrupt_cancellable;
  int           fd;
};

G_DEFINE_TYPE (FpiDeviceCrfpMoc, fpi_device_crfpmoc, FP_TYPE_DEVICE)

typedef struct crfpmoc_enroll_print
{
  FpPrint *print;
  int      stage;
} EnrollPrint;

static const FpIdEntry crfpmoc_id_table[] = {
  {.udev_types = FPI_DEVICE_UDEV_SUBTYPE_MISC, .misc_name = "cros_fp"},
  {.udev_types = 0}
};

static const gchar *const crfpmoc_meanings[] = {
  "SUCCESS",
  "INVALID_COMMAND",
  "ERROR",
  "INVALID_PARAM",
  "ACCESS_DENIED",
  "INVALID_RESPONSE",
  "INVALID_VERSION",
  "INVALID_CHECKSUM",
  "IN_PROGRESS",
  "UNAVAILABLE",
  "TIMEOUT",
  "OVERFLOW",
  "INVALID_HEADER",
  "REQUEST_TRUNCATED",
  "RESPONSE_TOO_BIG",
  "BUS_ERROR",
  "BUSY",
  "INVALID_HEADER_VERSION",
  "INVALID_HEADER_CRC",
  "INVALID_DATA_CRC",
  "DUP_UNAVAILABLE",
};

static const gchar *
crfpmoc_strresult (int i)
{
  if (i < 0 || i >= G_N_ELEMENTS (crfpmoc_meanings))
    return "<unknown>";
  return crfpmoc_meanings[i];
}

static char *
get_print_data_descriptor (FpPrint *print, gint8 template)
{
  const char *driver;
  const char *dev_id;

  driver = fp_print_get_driver (print);
  dev_id = fp_print_get_device_id (print);

  return g_strdup_printf ("%s/%s/%d", driver, dev_id, template);
}

static void
crfpmoc_set_print_data (FpPrint *print, gint8 template, guint8 *frame, size_t frame_size)

{

  fp_dbg ("Setting print data");

  g_autofree gchar *descr = NULL;
  GVariant *print_id_var = NULL;
  GVariant *fpi_data = NULL;
  GVariant *frame_var = NULL;

  fpi_print_set_type (print, FPI_PRINT_RAW);
  // fpi_print_set_device_stored (print, TRUE);

  descr = get_print_data_descriptor (print, template);

  print_id_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, descr, strlen (descr), sizeof (guchar));




  if (frame == NULL || frame_size == 0)
  {
    frame_var = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, sizeof(guint8)); // Empty array
    
  } else {
      frame_var = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, frame,frame_size, sizeof(guint8));
  }

  


  fpi_data = g_variant_new("(@ay@ay)", print_id_var, frame_var);
  g_object_set (print, "fpi-data", fpi_data, NULL);

}



static void 
crfpmoc_get_print_data(FpPrint *print, guint8 **frame, size_t *frame_size) {
    g_autoptr(GVariant) fpi_data = NULL;
    g_autoptr(GVariant) frame_var = NULL;
    const guint8 *frame_data = NULL;
    gsize frame_data_size = 0;

    if (frame) {
        *frame = NULL;
    }
    if (frame_size) {
        *frame_size = 0;
    }

    g_object_get(print, "fpi-data", &fpi_data, NULL);

    if (!fpi_data) {
        g_warning("No fpi-data found in the print object.");
        return;
    }

    g_variant_get(fpi_data, "(@ay@ay)", NULL, &frame_var);

    if (frame_var) {
        frame_data = g_variant_get_fixed_array(frame_var, &frame_data_size, sizeof(guint8));
        if (frame_data && frame_data_size > 0) {
            if (frame) {
                *frame = g_memdup2(frame_data, frame_data_size);
            }
            if (frame_size) {
                *frame_size = frame_data_size;
            }
        }
    }
}



static FpPrint *
crfpmoc_create_empty_frame_print (FpDevice *self, FpPrint *in_print)
{
  g_return_val_if_fail(in_print != NULL, NULL);

  FpPrint *out_print = fp_print_new(self); // Create a new FpPrint object
  if (!out_print)
    return NULL;

  g_autofree gchar *descr = NULL;
  GVariant *print_id_var = NULL;
  GVariant *fpi_data = NULL;
  GVariant *frame_var = NULL;

  // Get the print data descriptor from the input print object
  descr = get_print_data_descriptor(in_print, 0); // Assuming template is 0 for simplicity
  if (!descr)
  {
    g_object_unref(out_print);
    return NULL;
  }

  // Create a GVariant for the print ID
  print_id_var = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, descr, strlen(descr), sizeof(guchar));
  if (!print_id_var)
  {
    g_object_unref(out_print);
    return NULL;
  }

  // Create an empty array for the frame
  frame_var = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, sizeof(guint8));
  if (!frame_var)
  {
    g_object_unref(out_print);
    return NULL;
  }

  // Combine the print ID and empty frame into a GVariant
  fpi_data = g_variant_new("(@ay@ay)", print_id_var, frame_var);
  if (!fpi_data)
  {
    g_object_unref(out_print);
    return NULL;
  }

  // Set the properties of the new print object
  fpi_print_set_type(out_print, FPI_PRINT_RAW);
  g_object_set(out_print, "fpi-data", fpi_data, NULL);

  return out_print;
}



// required since the downloaded frame data is encrypted and 2 downloads are not the same
// so a compare function, that ignores frame_var is required and only compares on the print_id_var
static gboolean
crfpmoc_print_equal (FpPrint *self, FpPrint *other, FpDevice *device)
{
  gboolean is_equal = FALSE;

  FpPrint *print1 = crfpmoc_create_empty_frame_print(device, self);
  FpPrint *print2 = crfpmoc_create_empty_frame_print(device, other);

  is_equal = fp_print_equal(print1, print2);

  g_object_unref(print1);
  g_object_unref(print2);

  return is_equal;

}


static gboolean
crfpmoc_ec_command (FpiDeviceCrfpMoc *self,
                    int               command,
                    int               version,
                    const void       *outdata,
                    int               outsize,
                    void             *indata,
                    int               insize,
                    GError          **error)
{
  g_autofree struct crfpmoc_cros_ec_command_v2 *s_cmd = NULL;
  int r;

  g_assert (outsize == 0 || outdata != NULL);
  g_assert (insize == 0 || indata != NULL);

  s_cmd = g_malloc0 (sizeof (struct crfpmoc_cros_ec_command_v2) + MAX (outsize, insize));
  g_assert (s_cmd != NULL);

  s_cmd->command = command;
  s_cmd->version = version;
  s_cmd->result = 0xff;
  s_cmd->outsize = outsize;
  s_cmd->insize = insize;
  if (outdata != NULL)
    memcpy (s_cmd->data, outdata, outsize);

  r = ioctl (self->fd, CRFPMOC_CROS_EC_DEV_IOCXCMD_V2, s_cmd);
  if (r < 0)
    {
      fp_warn ("ioctl %d, errno %d (%s), EC result %d (%s)", r, errno, strerror (errno), s_cmd->result, crfpmoc_strresult (s_cmd->result));
    }
  else
    {
      memcpy (indata, s_cmd->data, MIN (r, insize));
      if (s_cmd->result != EC_RES_SUCCESS)
        {
          fp_warn ("EC result %d (%s)", s_cmd->result, crfpmoc_strresult (s_cmd->result));
          r = -CRFPMOC_EECRESULT - s_cmd->result;
        }
    }

  if (r < 0)
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "%s", crfpmoc_strresult (s_cmd->result)));
      return FALSE;
    }

  // sleep 0.1 seconds to prevent the device from being overwhelmed
  usleep(100000);

  return TRUE;
}

static gboolean
crfpmoc_read_bytes (gint fd, GIOCondition condition, gpointer user_data)
{
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (user_data);
  int rv;
  struct crfpmoc_ec_response_get_next_event_v1 buffer = { 0 };

  if (fd != self->fd)
    return FALSE;

  rv = read (fd, &buffer, sizeof (buffer));

  if (rv == 0)
    {
      fp_warn ("Timeout waiting for MKBP event");
      fpi_ssm_mark_failed (self->task_ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return FALSE;
    }
  else if (rv < 0)
    {
      fp_warn ("Error polling for MKBP event");
      fpi_ssm_mark_failed (self->task_ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return FALSE;
    }

  fp_dbg ("MKBP event %d data", buffer.event_type);
  fpi_ssm_next_state (self->task_ssm);
  return FALSE;
}

static void
crfpmoc_ec_pollevent (FpiDeviceCrfpMoc *self, unsigned long mask)
{
  int rv;

  rv = ioctl (self->fd, CRFPMOC_CROS_EC_DEV_IOCEVENTMASK_V2, mask);
  if (rv < 0)
    {
      fpi_ssm_next_state (self->task_ssm);
      return;
    }

  g_unix_fd_add (self->fd, G_IO_IN, crfpmoc_read_bytes, self);
}

static gboolean
crfpmoc_cmd_fp_mode (FpiDeviceCrfpMoc *self, guint32 inmode, guint32 *outmode, GError **error)
{
  struct crfpmoc_ec_params_fp_mode p;
  struct crfpmoc_ec_response_fp_mode r;
  gboolean rv;

  p.mode = inmode;
  rv = crfpmoc_ec_command (self, CRFPMOC_EC_CMD_FP_MODE, 0, &p, sizeof (p), &r, sizeof (r), error);
  if (!rv)
    return rv;

  fp_dbg ("FP mode: (0x%x)", r.mode);
  if (outmode != NULL)
    *outmode = r.mode;

  return TRUE;
}

static gboolean
crfpmoc_cmd_fp_seed (FpiDeviceCrfpMoc *self,const char* seed, GError **error)
{
  struct crfpmoc_ec_params_fp_seed p;
  gboolean rv;

  fp_dbg ("Setting seed '%s'", seed);

  if(strlen(seed) != CRFPMOC_FP_CONTEXT_TPM_BYTES)
  {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Seed length should be %d", CRFPMOC_FP_CONTEXT_TPM_BYTES);
      return FALSE;
  }


  p.struct_version = CRFPMOC_FP_TEMPLATE_FORMAT_VERSION;
  memset(p.seed, 0, CRFPMOC_FP_CONTEXT_TPM_BYTES);
  memcpy(p.seed, seed, CRFPMOC_FP_CONTEXT_TPM_BYTES);

  rv = crfpmoc_ec_command (self, CRFPMOC_EC_CMD_FP_SEED, 0, &p, sizeof (p), NULL, 0, error);

  if (!rv)
    return rv;

  return TRUE;
}

static gboolean
crfpmoc_cmd_fp_info (FpiDeviceCrfpMoc *self, guint16 *enrolled_templates, GError **error)
{
  struct crfpmoc_ec_response_fp_info r;
  gboolean rv;

  rv = crfpmoc_ec_command (self, CRFPMOC_EC_CMD_FP_INFO, 1, NULL, 0, &r, sizeof (r), error);
  if (!rv)
    return rv;

  fp_dbg ("Fingerprint sensor: vendor %x product %x model %x version %x", r.vendor_id, r.product_id, r.model_id, r.version);
  fp_dbg ("Image: size %dx%d %d bpp", r.width, r.height, r.bpp);
  fp_dbg ("Templates: version %d size %d count %d/%d dirty bitmap %x", r.template_version, r.template_size, r.template_valid, r.template_max, r.template_dirty);

  *enrolled_templates = r.template_valid;
  return TRUE;
}

static gboolean
crfpmoc_cmd_fp_stats (FpiDeviceCrfpMoc *self, gint8 *template, GError **error)
{
  struct crfpmoc_ec_response_fp_stats r;
  gboolean rv;

  rv = crfpmoc_ec_command (self, CRFPMOC_EC_CMD_FP_STATS, 0, NULL, 0, &r, sizeof (r), error);
  if (!rv)
    return rv;

  if (r.timestamps_invalid & CRFPMOC_FPSTATS_MATCHING_INV)
    {
      fp_dbg ("Last matching time: Invalid");
      *template = -1;
    }
  else
    {
      fp_dbg ("Last matching time: %d us (finger: %d)", r.matching_time_us, r.template_matched);
      *template = r.template_matched;
    }

  return TRUE;
}

static gboolean
crfpmoc_cmd_fp_enc_status (FpiDeviceCrfpMoc *self, guint32 *status, GError **error)
{
	struct crfpmoc_ec_response_fp_encryption_status resp = { 0 };
  gboolean rv;

  rv = crfpmoc_ec_command (self, CRFPMOC_EC_CMD_FP_ENC_STATUS, 0, NULL, 0, &resp, sizeof (resp), error);
  if (!rv)
    return rv;

  fp_dbg("FPMCU encryption status: %d", resp.status);
	fp_dbg("Valid flags: %d", resp.valid_flags);

  if(resp.status == CRFPMOC_FP_ENC_STATUS_SEED_SET) {
    fp_dbg("Seed is set");
  }

  if(status == NULL)
    return FALSE;

  *status = resp.status;

  return TRUE;
}

static gboolean
crfmoc_cmd_fp_enshure_seed (FpiDeviceCrfpMoc *self, const char* seed, GError **error)
{
  guint32 status;
  gboolean rv;

  fp_dbg("Checking if seed is set");
  rv = crfpmoc_cmd_fp_enc_status (self, &status, error);
  if (!rv)
    return rv;


  fp_dbg("FPMCU encryption status: %d", status);

  // I don't know why the encryption status is 5 after using verify. Since it should be 1. It also returns to 1 after using enroll
  // I am going to assume that 5 means that the seed is set, since setting the seed twice locks the device
  if(status == 0)
  {
    fp_dbg("Seed is not set, setting seed");
    rv = crfpmoc_cmd_fp_seed (self, seed, error);
    if (!rv)
      return rv;
  }

  return TRUE;
}



static gboolean
crfpmoc_ec_max_insize(FpiDeviceCrfpMoc *self, guint32 *max_insize, GError **error)
{
  struct crfpmoc_ec_response_get_protocol_info protocol_info;
  gboolean rv;

  rv = crfpmoc_ec_command(self, CRFPMOC_EC_CMD_GET_PROTOCOL_INFO, 0, NULL, 0, &protocol_info, sizeof(protocol_info), error);
  if (!rv)
    return rv;

  *max_insize = protocol_info.max_response_packet_size - sizeof(struct crfpmoc_ec_host_response);

  return TRUE;
}

static gboolean
crfpmoc_ec_max_outsize(FpiDeviceCrfpMoc *self, guint32 *max_outsize, GError **error)
{
  struct crfpmoc_ec_response_get_protocol_info protocol_info;
  gboolean rv;

  rv = crfpmoc_ec_command(self, CRFPMOC_EC_CMD_GET_PROTOCOL_INFO, 0, NULL, 0, &protocol_info, sizeof(protocol_info), error);
  if (!rv)
    return rv;

  *max_outsize = protocol_info.max_request_packet_size - sizeof(struct crfpmoc_ec_host_request);

  return TRUE;
}

static gboolean
crfpmoc_fp_download_frame (FpiDeviceCrfpMoc *self,
                           struct crfpmoc_ec_response_fp_info *info,
                           gint index,
                           guint8 **out_buffer,
                           GError **error)
{
  struct crfpmoc_ec_params_fp_frame p;
  gsize stride, size;
  guint8 *buffer = NULL, *ptr;
  gboolean rv;
  gint cmdver = 1;
  gsize rsize = sizeof(*info);
  const gint max_attempts = 3;
  gint num_attempts;
  guint32 ec_max_insize;
  gint template_idx = index + CRFPMOC_FP_FRAME_INDEX_TEMPLATE;

  *out_buffer = NULL;

  rv = crfpmoc_ec_max_insize(self, &ec_max_insize, error);
  if (!rv) {
    return FALSE;
  }
  usleep(10000);

  rv = crfpmoc_ec_command(self, CRFPMOC_EC_CMD_FP_INFO, cmdver, NULL, 0, info, rsize, error);
  if (!rv) {
    return FALSE;
  }

  size = info->template_size;

  buffer = g_malloc0(size);
  if (!buffer) {
    g_set_error(error,
                G_IO_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to allocate memory for the image buffer.");
    return FALSE;
  }

  ptr = buffer;
  p.offset = template_idx << CRFPMOC_FP_FRAME_INDEX_SHIFT;
  while (size > 0) {
    stride = MIN(ec_max_insize, size);
    p.size = stride;
    num_attempts = 0;

    while (num_attempts < max_attempts) {
      num_attempts++;
      rv = crfpmoc_ec_command(self, CRFPMOC_EC_CMD_FP_FRAME, 0, &p, sizeof(p), ptr, stride, error);
      if (rv) {
        break; 
      }
      if (g_error_matches(*error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED)) {
        fp_dbg("Access denied, stopping retrying");
        break;
      }
      usleep(1000);
    }

    if (!rv) {
      g_free(buffer);
      return FALSE;
    }

    p.offset += stride;
    size -= stride;
    ptr += stride;
  }

  *out_buffer = buffer;
  return TRUE;
}

static gboolean
crfpmoc_fp_upload_template (FpiDeviceCrfpMoc *self,
                            const guint8     *template_data,
                            gsize             template_size,
                            GError          **error)
{
    struct crfpmoc_ec_params_fp_template *p = NULL;
    guint32 offset = 0;
    guint32 tlen;
    gboolean rv = FALSE;
    guint32 ec_max_outsize = 0;
    guint32 max_chunk =  0;
    gsize struct_size;

    rv = crfpmoc_ec_max_outsize(self, &ec_max_outsize, error);
    if (!rv) {
        g_prefix_error(error, "Failed to get max outsize: ");
        return FALSE;
    }
    
    max_chunk = ec_max_outsize - offsetof(struct crfpmoc_ec_params_fp_template, data) - 4;


    while (template_size > 0) {
        tlen = MIN(max_chunk, template_size);

        struct_size = offsetof(struct crfpmoc_ec_params_fp_template, data) + tlen;
        p = g_malloc0(struct_size);

        if (!p) {
            g_set_error(error,
                        G_IO_ERROR,
                        G_DBUS_ERROR_NO_MEMORY,
                        "Failed to allocate memory for template upload.");
            return FALSE;
        }

        p->offset = offset;
        p->size = tlen;

        template_size -= tlen;

        if (!template_size) {
            p->size |= CRFPMOC_FP_TEMPLATE_COMMIT; 
        }


        memcpy(p->data, template_data + offset, tlen);

        rv = crfpmoc_ec_command(self,
                                CRFPMOC_EC_CMD_FP_TEMPLATE,
                                0,
                                p,
                                offsetof(struct crfpmoc_ec_params_fp_template, data) + tlen,
                                NULL,
                                0,
                                error);

        g_free(p);
        p = NULL;

        if (!rv) {
            g_prefix_error(error, "Failed to upload template chunk at offset %u: ", offset);
            return FALSE;
        }

        offset += tlen;
    }

    return TRUE;
}


static void
crfpmoc_cmd_wait_event_fingerprint (FpiDeviceCrfpMoc *self)
{
  long event_type = CRFPMOC_EC_MKBP_EVENT_FINGERPRINT;

  crfpmoc_ec_pollevent (self, 1 << event_type);
}

static void
crfpmoc_task_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  fp_dbg ("Task SSM done");
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);

  g_assert (!self->task_ssm || self->task_ssm == ssm);
  self->task_ssm = NULL;

  if (error)
    fpi_device_action_error (device, error);
}

static void
crfpmoc_open (FpDevice *device)
{
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);
  const char *file = fpi_device_get_udev_data (FP_DEVICE (device), FPI_DEVICE_UDEV_SUBTYPE_MISC);
  GError *err = NULL;
  gboolean r;

  fp_dbg ("Opening device %s", file);

  self->interrupt_cancellable = g_cancellable_new ();

  int fd = open (file, O_RDWR);


  if (fd < 0)
    {
      g_set_error (&err, G_IO_ERROR, g_io_error_from_errno (errno), "unable to open misc device");
      fpi_device_open_complete (device, err);
      return;
    }

  self->fd = fd;

  r = crfmoc_cmd_fp_enshure_seed (self, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &err);
  if (!r)
    {
     g_clear_error (&err);
     g_set_error (&err, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to ensure seed");
      fpi_device_open_complete (device, err);
    }



  fpi_device_open_complete (device, NULL);
}




static void
crfpmoc_cancel (FpDevice *device)
{
  fp_dbg ("Cancel");
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);

  if (self->task_ssm != NULL)
    fpi_ssm_mark_failed (self->task_ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled"));

  crfpmoc_cmd_fp_mode (self, 0, NULL, NULL);

  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();
}

static void
crfpmoc_suspend (FpDevice *device)
{
  fp_dbg ("Suspend");

  crfpmoc_cancel (device);
  g_cancellable_cancel (fpi_device_get_cancellable (device));
  fpi_device_suspend_complete (device, NULL);
}

static void
crfpmoc_close (FpDevice *device)
{
  fp_dbg ("Closing device");
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);

  crfpmoc_cancel (device);
  g_clear_object (&self->interrupt_cancellable);

  if (self->fd >= 0)
    {
      close (self->fd);
      self->fd = -1;
    }
  fpi_device_close_complete (device, NULL);
}

static void
crfpmoc_enroll_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);
  EnrollPrint *enroll_print = fpi_ssm_get_data (ssm);
  g_autofree gchar *user_id = NULL;
  g_autofree gchar *device_print_id = NULL;
  gboolean r;
  guint32 mode;
  guint16 enrolled_templates = 0;
  GError *error;

  GError *serror = NULL;
  struct crfpmoc_ec_response_fp_info info;
  guint8 *frame = NULL;
  gboolean res;


  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_SENSOR_ENROLL:
      r = crfpmoc_cmd_fp_mode (self, CRFPMOC_FP_MODE_ENROLL_IMAGE | CRFPMOC_FP_MODE_ENROLL_SESSION, &mode, &error);
      if (!r)
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_next_state (ssm);
       
      break;

    case ENROLL_WAIT_FINGER:
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
      crfpmoc_cmd_wait_event_fingerprint (self);
      break;

    case ENROLL_SENSOR_CHECK:
      r = crfpmoc_cmd_fp_mode (self, CRFPMOC_FP_MODE_DONT_CHANGE, &mode, &error);
      if (!r)
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      else
        {
          if (mode & CRFPMOC_FP_MODE_ENROLL_SESSION)
            {
              if (mode & CRFPMOC_FP_MODE_ENROLL_IMAGE)
                {
                  fpi_ssm_jump_to_state (ssm, ENROLL_WAIT_FINGER);
                }
              else
                {
                  fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

                  enroll_print->stage++;
                  fp_info ("Partial capture successful (%d/%d).", enroll_print->stage, CRFPMOC_NR_ENROLL_STAGES);
                  fpi_device_enroll_progress (device, enroll_print->stage, enroll_print->print, NULL);

                  fpi_ssm_jump_to_state (ssm, ENROLL_SENSOR_ENROLL);
                }
            }
          else if (mode == 0)
            {
              fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

              fpi_ssm_next_state (ssm);
            }
          else
            {
              fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

              fpi_device_enroll_progress (device, enroll_print->stage, NULL, fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL, "FP mode: (0x%x)", mode));

              fpi_ssm_jump_to_state (ssm, ENROLL_SENSOR_ENROLL);
            }
        }
      break;

    case ENROLL_COMMIT:
      crfpmoc_cmd_fp_info (self, &enrolled_templates, &error);
      fp_dbg ("Number of enrolled templates is: %d", enrolled_templates);


      user_id = fpi_print_generate_user_id (enroll_print->print);
      fp_dbg ("New fingerprint ID: %s", user_id);



      g_object_set (enroll_print->print, "description", user_id, NULL);



      res = crfpmoc_fp_download_frame(self, &info,  enrolled_templates - 1, &frame ,&serror);

      if (!res) {
        g_warning("Failed to download frame: %s", serror->message);
        g_clear_error(&serror);
        crfpmoc_set_print_data (enroll_print->print, enrolled_templates - 1, NULL, 0);

      } else {
        crfpmoc_set_print_data (enroll_print->print, enrolled_templates - 1, frame, info.template_size);
      }

      g_free(frame);


      

      fp_info ("Enrollment was successful!");

      fpi_device_enroll_complete (device, g_object_ref (enroll_print->print), NULL);

      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
crfpmoc_enroll (FpDevice *device)
{
  fp_dbg ("Enroll");
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);
  EnrollPrint *enroll_print = g_new0 (EnrollPrint, 1);

  fpi_device_get_enroll_data (device, &enroll_print->print);
  enroll_print->stage = 0;

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (device, crfpmoc_enroll_run_state, ENROLL_STATES);
  fpi_ssm_set_data (self->task_ssm, g_steal_pointer (&enroll_print), g_free);
  fpi_ssm_start (self->task_ssm, crfpmoc_task_ssm_done);
}

static void
crfpmoc_verify_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);
  FpPrint *print = NULL;
  FpPrint *verify_print = NULL;
  GPtrArray *prints;
  gboolean found = FALSE;
  guint index;
  gboolean r;
  guint32 mode;
  gint8 template = -1;
  GError *error;


  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIFY_SENSOR_MATCH:

      r = crfpmoc_cmd_fp_mode (self, CRFPMOC_FP_MODE_RESET_SENSOR, &mode, &error);

      if(!r)
      {
        fpi_ssm_mark_failed (ssm, error);
      }
      else
      {
        fpi_ssm_next_state (ssm);
      }


      gboolean is_identify = fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY;
      if(is_identify)
      {
        fpi_device_get_identify_data (device, &prints);
        if (prints->len != 0)
        {
          FpPrint *test = g_ptr_array_index (prints, 0);
          guint8 *frame;
          size_t frame_size;
          crfpmoc_get_print_data(test, &frame, &frame_size);
          
          crfpmoc_fp_upload_template(self, frame, frame_size, &error);
          g_free(frame);
        }
      }
      else
      {
        fpi_device_get_verify_data (device, &verify_print);
        guint8 *frame;
        size_t frame_size;
        crfpmoc_get_print_data(verify_print, &frame, &frame_size);
        crfpmoc_fp_upload_template(self, frame, frame_size, &error);
        g_free(frame);
      }

      r = crfpmoc_cmd_fp_mode (self, CRFPMOC_FP_MODE_MATCH, &mode, &error);
      if (!r)
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_next_state (ssm);
      break;
      
    case VERIFY_WAIT_FINGER:
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
      crfpmoc_cmd_wait_event_fingerprint (self);
      break;

    case VERIFY_SENSOR_CHECK:
      r = crfpmoc_cmd_fp_mode (self, CRFPMOC_FP_MODE_DONT_CHANGE, &mode, &error);
      if (!r)
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      else
        {
          if (mode & CRFPMOC_FP_MODE_MATCH)
            {
              fpi_ssm_jump_to_state (ssm, VERIFY_WAIT_FINGER);
            }
          else if (mode == 0)
            {
              fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

              fpi_ssm_next_state (ssm);
            }
          else
            {
              fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

              fpi_ssm_mark_failed (ssm, fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL, "FP mode: (0x%x)", mode));
            }
        }
      break;

    case VERIFY_CHECK:
      r = crfpmoc_cmd_fp_stats (self, &template, &error);
      if (!r)
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      else
        {
          is_identify = fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY;
          if (template == -1)
            {
              fp_info ("Print was not identified by the device");

              if (is_identify)
                fpi_device_identify_report (device, NULL, NULL, NULL);
              else
                fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
            }
          else
            {
              print = fp_print_new (device);

              crfpmoc_set_print_data (print, template, NULL, 0);

              fp_info ("Identify successful for template %d", template);

              if (is_identify)
                {
                  fpi_device_identify_report (device, g_ptr_array_index (prints, index), print, NULL);
                }
              else
                {  
                  fpi_device_verify_report (device, FPI_MATCH_SUCCESS, print, NULL);
                }
            }
          if (is_identify)
            fpi_device_identify_complete (device, NULL);
          else
            fpi_device_verify_complete (device, NULL);
          fpi_ssm_mark_completed (ssm);
        }
      break;
    }
}

static void
crfpmoc_identify_verify (FpDevice *device)
{
  fp_dbg ("Identify or Verify");
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (device, crfpmoc_verify_run_state, VERIFY_STATES);
  fpi_ssm_start (self->task_ssm, crfpmoc_task_ssm_done);
}

static void
crfpmoc_clear_storage_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);
  gboolean r;
  guint32 mode;
  GError *error;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLEAR_STORAGE_SENSOR_RESET:
      r = crfpmoc_cmd_fp_mode (self, CRFPMOC_FP_MODE_RESET_SENSOR, &mode, &error);
      if (!r)
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      else
        {
          fpi_device_clear_storage_complete (device, NULL);
          fpi_ssm_mark_completed (ssm);
        }
      break;
    }
}

static void
crfpmoc_clear_storage (FpDevice *device)
{
  fp_dbg ("Clear storage");
  FpiDeviceCrfpMoc *self = FPI_DEVICE_CRFPMOC (device);

  g_assert (self->task_ssm == NULL);
  self->task_ssm = fpi_ssm_new (device, crfpmoc_clear_storage_run_state, CLEAR_STORAGE_STATES);
  fpi_ssm_start (self->task_ssm, crfpmoc_task_ssm_done);
}

static void
fpi_device_crfpmoc_init (FpiDeviceCrfpMoc *self)
{
  G_DEBUG_HERE ();
  self->fd = -1;
}

static void
fpi_device_crfpmoc_class_init (FpiDeviceCrfpMocClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = CRFPMOC_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_UDEV;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = crfpmoc_id_table;
  dev_class->nr_enroll_stages = CRFPMOC_NR_ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->open = crfpmoc_open;
  dev_class->cancel = crfpmoc_cancel;
  dev_class->suspend = crfpmoc_suspend;
  dev_class->close = crfpmoc_close;
  dev_class->enroll = crfpmoc_enroll;
  dev_class->identify = crfpmoc_identify_verify;
  dev_class->verify = crfpmoc_identify_verify;
  dev_class->clear_storage = crfpmoc_clear_storage;

  fpi_device_class_auto_initialize_features (dev_class);
}
