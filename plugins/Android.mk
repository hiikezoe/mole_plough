LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := ccsecurity.c
LOCAL_MODULE := mole-ccsecurity
LOCAL_MODULE_FILENAME := mole-ccsecurity
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -export-dynamic
LOCAL_LDFLAGS := -export-dynamic

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := lsm.c
LOCAL_MODULE := mole-lsm
LOCAL_MODULE_FILENAME := mole-lsm
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -export-dynamic
LOCAL_LDFLAGS := -export-dynamic

include $(BUILD_SHARED_LIBRARY)
