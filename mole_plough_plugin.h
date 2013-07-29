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

#ifndef MOLE_PLOUGH_PLUGIN_H
#define MOLE_PLOUGH_PLUGIN_H

#include <stddef.h>

#define MOLE_PLOUGH_PLUGIN MOLE_PLOUGH_PLUGIN

typedef enum {
  MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE,
  MOLE_PLOUGH_PLUGIN_SYMBOL_MULTIPLE
} mole_plough_plugin_symbol_multiplicity;

typedef struct _mole_plough_plugin_neccessary_symbol {
  const char *name;
  void *address;
  mole_plough_plugin_symbol_multiplicity multiplicity;
} mole_plough_plugin_neccessary_symbol;

typedef struct _mole_plough_plugin {
  mole_plough_plugin_neccessary_symbol *neccessary_symbols;
  int (*disable_exec_security_check)(void*(*address_converter)(void *target, void *base), void *base_address);
  void *reserved[20];
} mole_plough_plugin;

typedef mole_plough_plugin* mole_plough_plugins;

mole_plough_plugins *mole_plough_plugin_load_all_plugins(const char *program_path);
void mole_plough_plugin_resolve_symbols(mole_plough_plugins *handler);
int mole_plough_plugin_disable_exec_security_check(mole_plough_plugins *handler,
                                                   void*(*address_converter)(void *target, void *base),
                                                   void *base_address);

#ifdef MOLE_PLOUGH_PLUGIN_STATIC_LINK
typedef struct _mole_plough_static_plugin {
  const char *name;
  void *getter;
} mole_plough_static_plugin;

mole_plough_plugins *mole_plough_static_plugin_register(void);

#define MOLE_PLOUGH_PLUGIN_DECLARE_GETTER(name) \
mole_plough_plugin * mole_plough_plugin_get_ ## name (void);

#define MOLE_PLOUGH_PLUGIN_DEFINE_GETTER(name) \
mole_plough_plugin *                                  \
mole_plough_plugin_get_ ## name (void)                \
{                                              \
  return &MOLE_PLOUGH_PLUGIN;                  \
}

MOLE_PLOUGH_PLUGIN_DECLARE_GETTER(ccsecurity)
MOLE_PLOUGH_PLUGIN_DECLARE_GETTER(lsm)
#endif

#endif /* MOLE_PLOUGH_PLUGIN_H */
