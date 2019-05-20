LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := HookUtil 
LOCAL_SRC_FILES := HookUtil.c 

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

#LOCAL_FORCE_STATIC_EXECUTABLE := true

#include $(BUILD_EXECUTABLE)
include $(BUILD_SHARED_LIBRARY)