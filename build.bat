set BuildTool=%AD_NDK%\build\ndk-build
set __APP_ABI=armeabi-v7a

call %BuildTool% NDK_PROJECT_PATH=./inject      SYSROOT=%AD_NDK%\sysroot   APP_BUILD_SCRIPT=inject/Android.mk      APP_ABI=%__APP_ABI%
call %BuildTool% NDK_PROJECT_PATH=./HookUtil    SYSROOT=%AD_NDK%\sysroot   APP_BUILD_SCRIPT=HookUtil/Android.mk    APP_ABI=%__APP_ABI%
call %BuildTool% NDK_PROJECT_PATH=./AAnti_debug SYSROOT=%AD_NDK%\sysroot   APP_BUILD_SCRIPT=AAnti_debug/Android.mk APP_ABI=%__APP_ABI%

copy .\inject\libs\%__APP_ABI%\inject                .\anti_debug\
copy .\HookUtil\libs\%__APP_ABI%\libHookUtil.so      .\anti_debug\
copy .\AAnti_debug\libs\%__APP_ABI%\libanti_debug.so .\anti_debug\

del /F /S /Q inject\libs
del /F /S /Q HookUtil\libs
del /F /S/ Q AAnti_debug\libs
pause