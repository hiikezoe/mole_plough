/*
 * Copyright (C) 2013 Hiroyuki Ikezoe
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
 *
 */

#include "mole_plough_plugin.h"

static void *security_bprm_set_creds = NULL;
static void *cap_bprm_set_creds = NULL;
static void *original_bprm_set_creds = NULL;
static void **security_ops_bprm_set_creds = NULL;

static mole_plough_plugin_neccessary_symbol neccessary_symbols[] = {
  { "security_bprm_set_creds", &security_bprm_set_creds, MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE },
  { "cap_bprm_set_creds",      &cap_bprm_set_creds,      MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE },
  { NULL,                      NULL,                     0}
};

static void *
get_security_ops_bprm_set_creds(void *address)
{
  int *value;
  int i;

  value = (int*)address;
  for (i = 0; i < 0x10; i++) {
    if ((value[i] & 0xffff0000) == 0xe8bd0000) {
      int offset = value[i - 1] & 0xfff;
      unsigned int *security_ops;
      security_ops = (unsigned int*)value[i + 1];
      return (void*)(*security_ops + offset);
    }
  }
}

static int
disable_security_bprm_set_creds(void*(*address_converted)(void *address, void *base), void *base_address)
{
  if (!security_bprm_set_creds || !cap_bprm_set_creds) {
    return 0;
  }

  security_ops_bprm_set_creds = get_security_ops_bprm_set_creds(security_bprm_set_creds);
  if (security_ops_bprm_set_creds && *security_ops_bprm_set_creds != cap_bprm_set_creds) {
    original_bprm_set_creds = *security_ops_bprm_set_creds;
    *security_ops_bprm_set_creds = cap_bprm_set_creds;
  }

  return 0;
}

#ifdef MOLE_PLUGIN_STATIC_LINK
static
#endif
mole_plough_plugin MOLE_PLOUGH_PLUGIN = {
  .neccessary_symbols = neccessary_symbols,
  .disable_exec_security_check = disable_security_bprm_set_creds,
};

#ifdef MOLE_PLUGIN_STATIC_LINK
MOLE_PLOUGH_PLUGIN_DEFINE_GETTER(lsm);
#endif
