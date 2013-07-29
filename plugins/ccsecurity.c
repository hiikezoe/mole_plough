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

static void *search_binary_handler = NULL;
static void *ccsecurity_ops = NULL;
static unsigned long int *__ccs_search_binary_handlers = NULL;

static mole_plough_plugin_neccessary_symbol neccessary_symbols[] = {
  { "search_binary_handler",        &search_binary_handler,        MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE },
  { "ccsecurity_ops",               &ccsecurity_ops,               MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE },
  { "__ccs_search_binary_handler",  &__ccs_search_binary_handlers, MOLE_PLOUGH_PLUGIN_SYMBOL_MULTIPLE },
  { NULL,                           NULL,                          0 },
};

static void *
get_ccs_search_binary_handler(unsigned long int *address, unsigned long int *ccs_search_binary_handlers)
{
  int i = 0;
  int j = 0;

  while (__ccs_search_binary_handlers[i]) {
    int j;
    for (j = 0; j < 0x100; j++) {
      if (address[j] == __ccs_search_binary_handlers[i]) {
        return address + j;
      }
    }
    i++;
  }
  return NULL;
}

static int
disable_ccs_search_binary_handler(void*(*address_converter)(void *target, void *base), void *base_address)
{
  if (ccsecurity_ops && search_binary_handler && __ccs_search_binary_handlers) {
    int **ccs_search_binary_handler;
    void *converted_ccsecurity_ops;
    converted_ccsecurity_ops = address_converter(ccsecurity_ops, base_address);
    ccs_search_binary_handler = get_ccs_search_binary_handler(converted_ccsecurity_ops, __ccs_search_binary_handlers);
    if (ccs_search_binary_handler && *ccs_search_binary_handler != search_binary_handler) {
      *ccs_search_binary_handler = search_binary_handler;
    }
  }
  return 0;
}

#ifdef MOLE_PLOUGH_PLUGIN_STATIC_LINK
static
#endif
mole_plough_plugin MOLE_PLOUGH_PLUGIN = {
  .neccessary_symbols = neccessary_symbols,
  .disable_exec_security_check = disable_ccs_search_binary_handler,
};

#ifdef MOLE_PLOUGH_PLUGIN_STATIC_LINK
MOLE_PLOUGH_PLUGIN_DEFINE_GETTER(ccsecurity);
#endif
