/*
 * ChromeOS Fingerprint driver storage utils for libfprint
 *
 * Copyright (C) 2019 Benjamin Berg <bberg@redhat.com>
 * Copyright (C) 2019-2020 Marco Trevisan <marco.trevisan@canonical.com>
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

#include "crfpmoc_storage.h"

#define STORAGE_FILE "crfpmoc.variant"

static char *
get_print_data_descriptor (FpPrint *print, FpDevice *dev, gint8 finger)
{
  const char *driver;
  const char *dev_id;

  if (print)
    {
      driver = fp_print_get_driver (print);
      dev_id = fp_print_get_device_id (print);
    }
  else
    {
      driver = fp_device_get_driver (dev);
      dev_id = fp_device_get_device_id (dev);
    }

  return g_strdup_printf ("%s/%s/%d", driver, dev_id, finger);
}

static GVariantDict *
load_data (void)
{
  GVariantDict *res;
  GVariant *var;
  gchar *contents = NULL;
  gsize length = 0;

  if (!g_file_get_contents (STORAGE_FILE, &contents, &length, NULL))
    {
      g_warning ("Error loading storage, assuming it is empty");
      return g_variant_dict_new (NULL);
    }

  var = g_variant_new_from_data (G_VARIANT_TYPE_VARDICT, contents, length, FALSE, g_free, contents);

  res = g_variant_dict_new (var);
  g_variant_unref (var);
  return res;
}

static int
save_data (GVariant *data)
{
  const gchar *contents = NULL;
  gsize length;

  length = g_variant_get_size (data);
  contents = (gchar *) g_variant_get_data (data);

  if (!g_file_set_contents (STORAGE_FILE, contents, length, NULL))
    {
      g_warning ("Error saving storage!");
      return -1;
    }

  g_variant_ref_sink (data);
  g_variant_unref (data);

  return 0;
}

static FpPrint *
load_print_from_data (GVariant *data)
{
  const guchar *stored_data = NULL;
  gsize stored_len;
  FpPrint *print;

  g_autoptr(GError) error = NULL;
  stored_data = (const guchar *) g_variant_get_fixed_array (data, &stored_len, 1);
  print = fp_print_deserialize (stored_data, stored_len, &error);
  if (error)
    g_warning ("Error deserializing data: %s", error->message);
  return print;
}

int
print_data_save (FpPrint *print, gint8 finger)
{
  g_debug ("Saving finger: %d", finger);
  GVariant *print_id_var = NULL;
  GVariant *fpi_data = NULL;

  g_autofree gchar *descr = get_print_data_descriptor (print, NULL, finger);
  print_id_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                            descr,
                                            strlen (descr),
                                            sizeof (guchar));
  fpi_data = g_variant_new ("(@ay)", print_id_var);
  g_object_set (print, "fpi-data", fpi_data, NULL);

  g_autoptr(GError) error = NULL;
  g_autoptr(GVariantDict) dict = NULL;
  g_autofree guchar *data = NULL;
  GVariant *val;
  gsize size;
  int res;

  dict = load_data ();

  fp_print_serialize (print, &data, &size, &error);
  if (error)
    {
      g_warning ("Error serializing data: %s", error->message);
      return -1;
    }
  val = g_variant_new_fixed_array (G_VARIANT_TYPE ("y"), data, size, 1);
  g_variant_dict_insert_value (dict, descr, val);

  res = save_data (g_variant_dict_end (dict));

  return res;
}

FpPrint *
print_data_load (FpDevice *dev, gint8 finger)
{
  g_autofree gchar *descr = get_print_data_descriptor (NULL, dev, finger);

  g_autoptr(GVariant) val = NULL;
  g_autoptr(GVariantDict) dict = NULL;

  dict = load_data ();
  val = g_variant_dict_lookup_value (dict, descr, G_VARIANT_TYPE ("ay"));

  if (val)
    return load_print_from_data (val);

  return NULL;
}

GPtrArray *
gallery_data_load (FpDevice *dev)
{
  g_autoptr(GVariantDict) dict = NULL;
  g_autoptr(GVariant) dict_variant = NULL;
  g_autofree char *dev_prefix = NULL;
  GPtrArray *gallery;
  const char *driver;
  const char *dev_id;
  GVariantIter iter;
  GVariant *value;
  gchar *key;

  gallery = g_ptr_array_new_with_free_func (g_object_unref);
  dict = load_data ();
  dict_variant = g_variant_dict_end (dict);
  driver = fp_device_get_driver (dev);
  dev_id = fp_device_get_device_id (dev);
  dev_prefix = g_strdup_printf ("%s/%s/", driver, dev_id);

  g_variant_iter_init (&iter, dict_variant);
  while (g_variant_iter_loop (&iter, "{sv}", &key, &value))
    {
      FpPrint *print;
      const guchar *stored_data;
      g_autoptr(GError) error = NULL;
      gsize stored_len;

      if (!g_str_has_prefix (key, dev_prefix))
        continue;

      stored_data = (const guchar *) g_variant_get_fixed_array (value, &stored_len, 1);
      print = fp_print_deserialize (stored_data, stored_len, &error);

      if (error)
        {
          g_warning ("Error deserializing data: %s", error->message);
          continue;
        }

      g_ptr_array_add (gallery, print);
    }

  return gallery;
}
