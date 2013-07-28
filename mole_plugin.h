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

#ifndef MOLE_PLUGIN_H
#define MOLE_PLUGIN_H

#include <stdbool.h>

#define MOLE_PLUGIN MOLE_PLUGIN

typedef enum {
  SINGLE,
  MULTIPLE
} multiplicity;

typedef struct _neccessary_symbol {
  const char *name;
  void *address;
  multiplicity multiplicity;
} neccessary_symbol;

typedef struct _mole_plugin {
  neccessary_symbol *neccessary_symbols;
  int (*pre_commit_creds)(void);
  int (*post_commit_creds)(void);
  void *reserved[20];
} mole_plugin;

#endif /* MOLE_PLUGIN_H */
