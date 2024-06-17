/*
 * Example storage clearing program, which deletes all the
 * fingers which have been previously enrolled to disk.
 * Copyright (C) 2020 Marco Trevisan <marco.trevisan@canonical.com>
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

#define FP_COMPONENT "example-clear-storage"

#include <stdio.h>
#include <libfprint/fprint.h>
#include <glib-unix.h>

#include "storage.h"
#include "utilities.h"

typedef struct _ClearStorageData
{
  GMainLoop    *loop;
  GCancellable *cancellable;
  unsigned int  sigint_handler;
  int           ret_value;
} ClearStorageData;

static void
clear_storage_data_free (ClearStorageData *clear_storage_data)
{
  g_clear_handle_id (&clear_storage_data->sigint_handler, g_source_remove);
  g_clear_object (&clear_storage_data->cancellable);
  g_main_loop_unref (clear_storage_data->loop);
  g_free (clear_storage_data);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ClearStorageData, clear_storage_data_free)

static void
on_device_closed (FpDevice *dev, GAsyncResult *res, void *user_data)
{
  ClearStorageData *clear_storage_data = user_data;

  g_autoptr(GError) error = NULL;

  fp_device_close_finish (dev, res, &error);

  if (error)
    g_warning ("Failed closing device %s", error->message);

  g_main_loop_quit (clear_storage_data->loop);
}

static void
clear_storage_quit (FpDevice         *dev,
                    ClearStorageData *clear_storage_data)
{
  if (!fp_device_is_open (dev))
    {
      g_main_loop_quit (clear_storage_data->loop);
      return;
    }

  fp_device_close (dev, NULL, (GAsyncReadyCallback) on_device_closed, clear_storage_data);
}

static void
on_clear_storage_completed (FpDevice *dev, GAsyncResult *res, void *user_data)
{
  ClearStorageData *clear_storage_data = user_data;

  g_autoptr(GError) error = NULL;

  if (!fp_device_clear_storage_finish (dev, res, &error))
    {
      g_warning ("Failed to clear storage: %s", error->message);
      clear_storage_data->ret_value = EXIT_FAILURE;
    }
  else
    {
      gboolean r = clear_saved_prints (&error);
      if (!r)
        {
          g_warning ("Clear saved prints from local storage failed, code %d", r);
          clear_storage_data->ret_value = EXIT_FAILURE;
        }
      else
        {
          g_print ("Clear storage successful!\n");
          clear_storage_data->ret_value = EXIT_SUCCESS;
        }
    }

  clear_storage_quit (dev, clear_storage_data);
}

static void
start_clear_storage (FpDevice *dev, ClearStorageData *clear_storage_data)
{
  char buffer[20];

  g_print ("Clear device storage? [Y/n]? ");
  if (fgets (buffer, sizeof (buffer), stdin) &&
      (buffer[0] == 'Y' || buffer[0] == 'y' || buffer[0] == '\n'))
    {
      fp_device_clear_storage (dev, clear_storage_data->cancellable, (GAsyncReadyCallback) on_clear_storage_completed, clear_storage_data);
      return;
    }

  clear_storage_quit (dev, clear_storage_data);
}

static void
on_device_opened (FpDevice *dev, GAsyncResult *res, void *user_data)
{
  ClearStorageData *clear_storage_data = user_data;

  g_autoptr(GError) error = NULL;

  if (!fp_device_open_finish (dev, res, &error))
    {
      g_warning ("Failed to open device: %s", error->message);
      clear_storage_quit (dev, clear_storage_data);
      return;
    }

  g_print ("Opened device. ");

  start_clear_storage (dev, clear_storage_data);
}

static gboolean
sigint_cb (void *user_data)
{
  ClearStorageData *clear_storage_data = user_data;

  g_cancellable_cancel (clear_storage_data->cancellable);

  return G_SOURCE_CONTINUE;
}

int
main (void)
{
  g_autoptr(FpContext) ctx = NULL;
  g_autoptr(ClearStorageData) clear_storage_data = NULL;
  GPtrArray *devices;
  FpDevice *dev;

  setenv ("G_MESSAGES_DEBUG", "all", 0);
  setenv ("LIBUSB_DEBUG", "3", 0);

  ctx = fp_context_new ();

  devices = fp_context_get_devices (ctx);
  if (!devices)
    {
      g_warning ("Impossible to get devices");
      return EXIT_FAILURE;
    }

  dev = discover_device (devices);
  if (!dev)
    {
      g_warning ("No devices detected.");
      return EXIT_FAILURE;
    }

  clear_storage_data = g_new0 (ClearStorageData, 1);
  clear_storage_data->ret_value = EXIT_FAILURE;
  clear_storage_data->loop = g_main_loop_new (NULL, FALSE);
  clear_storage_data->cancellable = g_cancellable_new ();
  clear_storage_data->sigint_handler = g_unix_signal_add_full (G_PRIORITY_HIGH,
                                                               SIGINT,
                                                               sigint_cb,
                                                               clear_storage_data,
                                                               NULL);
  fp_device_open (dev, clear_storage_data->cancellable,
                  (GAsyncReadyCallback) on_device_opened,
                  clear_storage_data);

  g_main_loop_run (clear_storage_data->loop);

  return clear_storage_data->ret_value;
}
