LOCAL_PATH := $(call my-dir)

MOLE_PLOUGH_STATIC_PLUGINS_SOURCES :=

include $(CLEAR_VARS)

LOCAL_SRC_FILES := ccsecurity.c
LOCAL_MODULE := mole-plough-ccsecurity
LOCAL_MODULE_FILENAME := $(LOCAL_MODULE)
LOCAL_MODULE_TAGS := optional
LOCAL_LDFLAGS := -export-dynamic
MOLE_PLOUGH_STATIC_PLUGINS_SOURCES += $(LOCAL_SRC_FILES)

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := lsm.c
LOCAL_MODULE := mole-plough-lsm
LOCAL_MODULE_FILENAME := $(LOCAL_MODULE)
LOCAL_MODULE_TAGS := optional
LOCAL_LDFLAGS := -export-dynamic
MOLE_PLOUGH_STATIC_PLUGINS_SOURCES += $(LOCAL_SRC_FILES)

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := mole_plough_plugin.c
LOCAL_MODULE := mole_plough_plugin
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -DMOLE_PLOUGH_PLUGIN_STATIC_LINK
LOCAL_STATIC_LIBRARIES += libkallsyms
MOLE_PLOUGH_STATIC_PLUGINS_SOURCES += $(LOCAL_SRC_FILES)

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(MOLE_PLOUGH_STATIC_PLUGINS_SOURCES)
LOCAL_MODULE := mole_plough_plugins
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -DMOLE_PLOUGH_PLUGIN_STATIC_LINK

include $(BUILD_STATIC_LIBRARY)

