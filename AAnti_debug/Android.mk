LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := anti_debug 
LOCAL_SRC_FILES := anti_debug.c

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

#LOCAL_FORCE_STATIC_EXECUTABLE := true

#include $(BUILD_EXECUTABLE)
include $(BUILD_SHARED_LIBRARY)