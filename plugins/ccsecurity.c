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

#include <stdint.h>
#include "mole_plugin.h"

static void *search_binary_handler = NULL;
static void *ccsecurity_ops = NULL;
static unsigned long int *__ccs_search_binary_handlers = NULL;

static neccessary_symbol neccessary_symbols[] = {
  { "search_binary_handler",        &search_binary_handler,        SINGLE },
  { "ccsecurity_ops",               &ccsecurity_ops,               SINGLE },
  { "__ccs_search_binary_handler",  &__ccs_search_binary_handlers, MULTIPLE },
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
disable_ccs_search_binary_handler(void)
{
  if (ccsecurity_ops && search_binary_handler && __ccs_search_binary_handlers) {
    int **ccs_search_binary_handler;
    ccs_search_binary_handler = get_ccs_search_binary_handler(ccsecurity_ops, __ccs_search_binary_handlers);
    if (ccs_search_binary_handler && *ccs_search_binary_handler != search_binary_handler) {
      *ccs_search_binary_handler = search_binary_handler;
    }
  }
  return 0;
}

mole_plugin MOLE_PLUGIN = {
  neccessary_symbols,
  disable_ccs_search_binary_handler,
  NULL,
};

