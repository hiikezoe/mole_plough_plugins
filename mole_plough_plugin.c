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

#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "mole_plough_plugin.h"
#include "kallsyms_in_memory.h"

#define PLUGIN_PREFIX "mole-"
#define PLUGIN_SUFFIX ".so"

static bool
is_plugin_file(const char *file_name)
{
  size_t file_name_length;
  size_t prefix_length;
  size_t suffix_length;

  file_name_length = strlen(file_name);
  prefix_length = strlen(PLUGIN_PREFIX);
  suffix_length = strlen(PLUGIN_SUFFIX);

  if (file_name_length < prefix_length + suffix_length) {
    return false;
  }

  return !strncmp(file_name, PLUGIN_PREFIX, prefix_length) &&
         !strncmp(file_name + file_name_length - suffix_length,
                  PLUGIN_SUFFIX, suffix_length);
}

static mole_plough_plugin *
load_plugin(const char *file_name)
{
  mole_plough_plugin *plugin;
  void *handle;

  handle = dlopen(file_name, RTLD_LAZY);
  if (!handle) {
    dlerror();
    return NULL;
  }

  plugin = dlsym(handle, "MOLE_PLOUGH_PLUGIN");
  if (!plugin) {
    dlclose(handle);
    return NULL;
  }

  return plugin;
}

static char *
get_plugin_path(const char *program_path)
{
  char current_directory[PATH_MAX];
  char path[PATH_MAX];
  char *last_slash;
  char *program_directory;

  last_slash = strrchr(program_path, '/');
  getcwd(current_directory, sizeof(current_directory));

  program_directory = strndup(program_path, last_slash - program_path);

  snprintf(path, sizeof(path), "%s%s", current_directory, program_directory);

  free(program_directory);

  return strdup(path);
}

static mole_plough_plugins *
load_all_plugins_in_directory(const char *dir_name)
{
  mole_plough_plugins *plugins;
  struct dirent *entry;
  DIR *dir;
  int count = 0;

  dir = opendir(dir_name);
  if (!dir) {
    return NULL;
  }

  entry = readdir(dir);
  while (entry) {
    if (is_plugin_file(entry->d_name)) {
      count++;
    }
    entry = readdir(dir);
  }
  rewinddir(dir);

  plugins = calloc(sizeof(mole_plough_plugins), count + 1);

  count = 0;
  entry = readdir(dir);
  while (entry) {
    if (is_plugin_file(entry->d_name)) {
      mole_plough_plugin *plugin;
      char file_path[PATH_MAX];
      snprintf(file_path, sizeof(file_path), "%s/%s", dir_name, entry->d_name);
      plugin = load_plugin(file_path);
      if (plugin) {
        plugins[count] = load_plugin(file_path);
        count++;
      }
    }
    entry = readdir(dir);
  }

  closedir(dir);

  return plugins;
}

mole_plough_plugins *
mole_plough_plugin_load_all_plugins(const char *program_path)
{
  char *plugin_path;
  mole_plough_plugins *handler;

  plugin_path = get_plugin_path(program_path);

  handler = load_all_plugins_in_directory(plugin_path);

  free(plugin_path);

  return handler;
}

void
mole_plough_plugin_resolve_symbols(kallsyms *kallsyms, mole_plough_plugins *handler)
{
  int i = 0;

  if (!handler) {
    return;
  }

  while (handler[i]) {
    mole_plough_plugin_neccessary_symbol *symbol;
    symbol = handler[i]->neccessary_symbols;
    while (symbol && symbol->name) {
      if (symbol->multiplicity == MOLE_PLOUGH_PLUGIN_SYMBOL_MULTIPLE) {
        (*((void**)symbol->address)) =
          (void*)kallsyms_in_memory_lookup_names(kallsyms, symbol->name);
      } else {
        (*((void**)symbol->address)) =
          (void*)kallsyms_in_memory_lookup_name(kallsyms, symbol->name);
      }
      symbol++;
    }
    i++;
  }
}

int
mole_plough_plugin_disable_exec_security_check(mole_plough_plugins *handler,
                                               void*(*address_converter)(void *target, void *base),
                                               void *base_address)
{
  int i = 0;

  if (!handler) {
    return 0;
  }

  while (handler[i]) {
    if (handler[i]->disable_exec_security_check) {
      handler[i]->disable_exec_security_check(address_converter, base_address);
    }
    i++;
  }

  return 0;
}

#ifdef MOLE_PLOUGH_PLUGIN_STATIC_LINK
#define DEFINE_MOLE_PLUGIN(name) \
  { #name, mole_plough_plugin_get_ ## name }

mole_plough_static_plugin static_plugins[] = {
  DEFINE_MOLE_PLUGIN(ccsecurity),
  DEFINE_MOLE_PLUGIN(lsm),
};

static int n_static_plugins = sizeof(static_plugins) / sizeof(static_plugins[0]);

mole_plough_plugins *
mole_plough_static_plugin_register(void)
{
  int i;
  mole_plough_plugins *plugins;

  plugins = calloc(sizeof(mole_plough_plugin*), n_static_plugins + 1);
  for (i = 0; i < n_static_plugins; i++) {
    mole_plough_plugin *(*mole_static_plugin_get)(void);
    mole_static_plugin_get = static_plugins[i].getter;
    plugins[i] = mole_static_plugin_get();
  }
  return plugins;
}
#endif
