LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := mole_plough.c
LOCAL_MODULE := mole-plough
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libcutils libc
LOCAL_STATIC_LIBRARIES += libperf_event_exploit
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libkallsyms
LOCAL_STATIC_LIBRARIES += libmole_plough_plugin
TOP_SRCDIR := $(abspath $(LOCAL_PATH))
TARGET_C_INCLUDES +=            \
  $(TOP_SRCDIR)/device_database \
  $(TOP_SRCDIR)/kallsyms

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
