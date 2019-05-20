#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <jni.h>
#include <sys/system_properties.h>
#include <sys/inotify.h>
#include <dirent.h>


#define LOG_TAG "Hook"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#ifdef win32
#endif


typedef FILE* (*proto_fopen)(const char * path,const char * mode);
typedef int (*proto_sys_get)(const char *name, char *value);
typedef int (*proto_open)(const char * path, int flags, mode_t mode);
typedef int (*proto_openat)(const char *path, int flags, mode_t mode);
typedef int (*proto_inotify_add_watch)(int, const char *, __u32);
typedef DIR* (*proto_opendir)(const char * name);

proto_fopen old_fopen = NULL;
proto_sys_get old_sys_get = NULL;
proto_open old_open = NULL;
proto_openat old_openat = NULL;
proto_inotify_add_watch old_inotify_add_watch = NULL;
proto_opendir old_opendir = NULL;


//uint32_t new_libc_addr = 0;
char new_libc_maps[16] = {0};
uint32_t libc_addr = 0; //当前so文件的内存地址
//uint32_t offset_sysget = 0;

//hookfuc("libc.so", "fopen", "new_fopen);

const char str_buildfile[] = "/data/local/tmp/anti_debug/new_build";
const char str_statusfile[] = "/data/local/tmp/anti_debug/new_status";
const char str_wchanfile[] = "/data/local/tmp/anti_debug/new_wchan";
const char str_cmdlinefile[] = "/data/local/tmp/anti_debug/new_cmdline";
const char str_tcpfile[] = "/data/local/tmp/anti_debug/new_tcp";
const char str_mapsfile[] = "/data/local/tmp/anti_debug/new_maps";
const char str_HookUtilSO[] = "/data/local/tmp/anti_debug/libHookUtil.so";
const char str_anti_debugSO[] = "/data/local/tmp/anti_debug/libanti_debug.so";


int new_sys_get(const char *name, char *value)
{
    LOGD("new_sys_get() name=%s\n", name);
    return old_sys_get(name, value);
    /*    
    int i =  old_sys_get(name, value);
    if (old_sys_get == -1)
        LOGD("error\n");
    LOGD("real value = %s", value);
    int BUFFERSIZE = 1024;
	char build_path[100] = {0};
	char buffer[BUFFERSIZE];
	FILE *fpr = fopen(str_buildfile, "r");

	if (fpr == NULL)
	{
		LOGD("[new_sys_get] path '%s' failed", str_buildfile);
	}
	else
	{
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
	//		LOGD("buffer_sysget = %s", buffer);
			if (strstr(buffer, name) != NULL) {

				char *p;

				p = strtok(buffer, "=");
				if (p)
//					LOGD("%s\n", p);

				p = strtok(NULL, "=");
				if (p)
				{
//					LOGD("%s\n", p);
					strcpy(value, p);
				}
				fclose(fpr);
			}
			break;
		}
	}

	LOGD("sysget value = %s", value);
    return i;
    */
}

int new_inotify_add_watch(int fd, const char *path, __u32 mask)
{
	if(strstr(path, "/proc") != NULL && strstr(path, "/mem") != NULL){
	  LOGD("inotify path = %s", path);
	  return old_inotify_add_watch(fd, path, 0x00000200);

	}else if(strstr(path, "/proc") != NULL && strstr(path, "/pagemap") != NULL){
	  LOGD("inotify path = %s", path);
	  return old_inotify_add_watch(fd, path, 0x00000200);
	}
	  LOGD("inotify path = %s", path);
	  return old_inotify_add_watch(fd, path, mask);
}

FILE* newFopen(const char * path,const char * mode)
{
	int BUFFERSIZE = 1024;
	char buffer[BUFFERSIZE];
	char re_path[100] = {0};
	LOGD("fopen path = %s", path);

	if(strstr(path, "/proc") != NULL && strstr(path, "/stat") != NULL){
		sprintf(re_path, "%s", str_statusfile);
		FILE *fpr, *fpw;

		fpr = old_fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[fopen] path [%s]failed", path);
			return NULL;
		}

		fpw = old_fopen(re_path, "w");
//		LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[fopen] re-path [%s]failed", re_path);
			return NULL;
		}
		if(strstr(path, "/status") != NULL) // /proc/pid/status
		{
			while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
			{
//				LOGD("buffer_status = %s", buffer);
				if (strstr(buffer, "State") != NULL)
				{
					fputs("State:\tS (sleeping)\n", fpw);
					continue;
				}
				if (strstr(buffer, "TracerPid") != NULL)
				{
					fputs("TracerPid:\t0\n", fpw);
					continue;
				}
				else
				{
					fputs(buffer, fpw);
				}
			}
		}else
		{ // /proc/pid/stat
			int i = 0;
			int j = 0;
			if (fgets(buffer, BUFFERSIZE, fpr)) {
				for(i=0; i<BUFFERSIZE; i++)
				{
					LOGD("buffer_stat = %c", buffer[i]);
					if(isspace(buffer[i]))
					{
						j++;
						LOGD("FIND SPACE. j = %d", j);
					}
					if(j == 2)
						break;
				}
				LOGD("buffer[i+1] = %c", buffer[i+1]);
				if(buffer[i+1] != 't')
				{
					buffer[i+1] = 'S';
				}
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_fopen(re_path, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/wchan") != NULL){ // /proc/pid/wchan
			sprintf(re_path, "%s", str_wchanfile);
			FILE *fpr, *fpw;

			fpr = old_fopen(path, "r");


			if (fpr == NULL)
			{
				LOGD("[fopen] path [%s]failed", path);
				return NULL;
			}
			fpw = old_fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
			if (fpw == NULL)
			{
				LOGD("[fopen] re-path [%s]failed", re_path);
				return NULL;
			}
			while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
			{
				LOGD("buffer_wchan = %s", buffer);
				fputs("sys_epoll_wait", fpw);
			}

			fclose(fpr);
			fclose(fpw);
			return old_fopen(re_path, mode);
		}

	if(strstr(path, "/proc") != NULL && strstr(path, "/cmdline") != NULL){ // /proc/pid/cmdline
		sprintf(re_path, "%s", str_cmdlinefile);
		FILE *fpr, *fpw;

		fpr = old_fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[fopen] path [%s]failed", path);
			return NULL;
		}
		fpw = old_fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[fopen] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
//			LOGD("buffer_cmdline = %s", buffer);
			if (strstr(buffer, "android_server") != NULL)
			{
				fputs("com.android.phone", fpw);

			}
			else
			{
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_fopen(re_path, mode);
	}

	if(strstr(path, "/proc/net/tcp") != NULL){ // /proc/net/tcp
		sprintf(re_path, "%s", str_tcpfile);
		FILE *fpr, *fpw;

		fpr = old_fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[fopen] path [%s]failed", path);
			return NULL;
		}
		fpw = old_fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[fopen] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			if (strstr(buffer, "5D8A") != NULL)
			{
				LOGD("buffer_tcp = %s", buffer);
				fputs("com.android.phone", fpw);

			}
			else
			{
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_fopen(re_path, mode);
	}

    
	FILE * result = old_fopen(path, mode);
    if(result == NULL)
        LOGD("[fopen] file path = %s [failed]", path);
    return result;

}

int newOpen(const char * path, int flags, mode_t mode)
{
	int BUFFERSIZE = 1024;
	char re_path[100] = {0};
	char buffer[BUFFERSIZE];
	LOGD("open path = %s", path);

	if(strstr(path, "/proc") != NULL && strstr(path, "/stat") != NULL){
		sprintf(re_path, "%s", str_statusfile);
		FILE *fpr, *fpw;

		fpr = fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[open] path [%s]failed", path);
			return NULL;
		}

		fpw = fopen(re_path, "w");
//		LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[open] re-path [%s]failed", re_path);
			return NULL;
		}
		if(strstr(path, "/status") != NULL) // /proc/*/status
		{
			while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
			{
//				LOGD("buffer_status = %s", buffer);
				if (strstr(buffer, "State") != NULL)
				{
					fputs("State:\tS (sleeping)\n", fpw);
					continue;
				}
				if (strstr(buffer, "TracerPid") != NULL)
				{
					fputs("TracerPid:\t0\n", fpw);
					continue;
				}
				else
				{
					fputs(buffer, fpw);
				}
			}
		}else
		{ // /proc/pid/stat
			int i = 0;
			int j = 0;
			if (fgets(buffer, BUFFERSIZE, fpr)) {
				for(i=0; i<BUFFERSIZE; i++)
				{
					LOGD("buffer_stat = %c", buffer[i]);
					if(isspace(buffer[i]))
					{
						j++;
						LOGD("FIND SPACE. j = %d", j);
					}
					if(j == 2)
						break;
				}
				LOGD("buffer[i+1] = %c", buffer[i+1]);
				if(buffer[i+1] != 't')
				{
					buffer[i+1] = 'S';
				}
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_open(re_path, flags, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/cmdline") != NULL){ // /proc/*/cmdline
		sprintf(re_path, "%s", str_cmdlinefile);
		FILE *fpr, *fpw;

		fpr = fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[open] path [%s]failed", path);
			return NULL;
		}
		fpw = fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[open] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			LOGD("buffer_cmdline = %s", buffer);
			if (strstr(buffer, "android_server") != NULL)
			{
				fputs("com.android.phone", fpw);

			}
			else
			{
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_open(re_path, flags, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/wchan") != NULL){ // /proc/*/wchan
		sprintf(re_path, "%s", str_wchanfile);
		FILE *fpr, *fpw;

		fpr = fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[open] path [%s]failed", path);
			return NULL;
		}
		fpw = fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[open] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			LOGD("buffer_wchan = %s", buffer);
			fputs("sys_epoll_wait", fpw);
		}

		fclose(fpr);
		fclose(fpw);
		return old_open(re_path, flags, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/maps") != NULL){ // /proc/pid/maps
		LOGD("start hook maps");

//		new_libc_addr = new_sys_get - offset_sysget;
		sprintf(new_libc_maps, "%lx", libc_addr);
		new_libc_maps[8] = '-';
		sprintf(new_libc_maps + 9, "%x", libc_addr + 0x46000);
		LOGD("new_libc_maps = %s\n", new_libc_maps);
		sprintf(re_path, "%s", str_mapsfile);


		FILE *fpr, *fpw;
		int i = 0;

		fpr = fopen(path, "r");
		if (fpr == NULL)
		{
			LOGD("[open] path [%s]failed", path);
			return NULL;
		}

		fpw = fopen(re_path, "w");
		if (fpw == NULL)
		{
			LOGD("[open] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			if (strstr(buffer, "libc.so") != NULL)
			{
//				LOGD("buffer_maps = %s", buffer);
				for(i = 0; i < 17 ; i++)
				{
					buffer[i] = new_libc_maps[i];
				}
				fputs(buffer, fpw);

			}
			else
			{
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_open(re_path, flags, mode);
	}

	FILE * result = old_open(path, flags, mode);
    if(result == NULL)
        LOGD("[open] file path = %s [failed]", path);
    return result;
}

int newOpenat(const char * path, int flags, mode_t mode)
{
	int BUFFERSIZE = 1024;
	char re_path[100] = {0};
	char buffer[BUFFERSIZE];
	LOGD("open path = %s", path);

	if(strstr(path, "/proc") != NULL && strstr(path, "/stat") != NULL){
		sprintf(re_path, "%s", str_statusfile);
		FILE *fpr, *fpw;

		fpr = fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[openat] path [%s]failed", path);
			return NULL;
		}

		fpw = fopen(re_path, "w");
//		LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[openat] re-path [%s]failed", re_path);
			return NULL;
		}
		if(strstr(path, "/status") != NULL) // /proc/*/status
		{
			while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
			{
//				LOGD("buffer_status = %s", buffer);
				if (strstr(buffer, "State") != NULL)
				{
					fputs("State:\tS (sleeping)\n", fpw);
					continue;
				}
				if (strstr(buffer, "TracerPid") != NULL)
				{
					fputs("TracerPid:\t0\n", fpw);
					continue;
				}
				else
				{
					fputs(buffer, fpw);
				}
			}
		}else
		{ // /proc/pid/stat
			int i = 0;
			int j = 0;
			if (fgets(buffer, BUFFERSIZE, fpr)) {
				for(i=0; i<BUFFERSIZE; i++)
				{
					LOGD("buffer_stat = %c", buffer[i]);
					if(isspace(buffer[i]))
					{
						j++;
						LOGD("FIND SPACE. j = %d", j);
					}
					if(j == 2)
						break;
				}
				LOGD("buffer[i+1] = %c", buffer[i+1]);
				if(buffer[i+1] != 't')
				{
					buffer[i+1] = 'S';
				}
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_openat(re_path, flags, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/cmdline") != NULL){ // /proc/*/cmdline
		sprintf(re_path, "%s", str_cmdlinefile);
		FILE *fpr, *fpw;

		fpr = fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[openat] path [%s]failed", path);
			return NULL;
		}
		fpw = fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[openat] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			LOGD("buffer_cmdline = %s", buffer);
			if (strstr(buffer, "android_server") != NULL)
			{
				fputs("com.android.phone", fpw);

			}
			else
			{
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_openat(re_path, flags, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/wchan") != NULL){ // /proc/*/wchan
		sprintf(re_path, "%s", str_wchanfile);
		FILE *fpr, *fpw;

		fpr = fopen(path, "r");


		if (fpr == NULL)
		{
			LOGD("[openat] path [%s]failed", path);
			return NULL;
		}
		fpw = fopen(re_path, "w");
//			LOGD("fopen re_path = %s", re_path);
		if (fpw == NULL)
		{
			LOGD("[openat] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			LOGD("buffer_wchan = %s", buffer);
			fputs("sys_epoll_wait", fpw);
		}

		fclose(fpr);
		fclose(fpw);
		return old_openat(re_path, flags, mode);
	}

	if(strstr(path, "/proc") != NULL && strstr(path, "/maps") != NULL){ // /proc/pid/maps
		LOGD("start hook maps");

//		new_libc_addr = new_sys_get - offset_sysget;
		sprintf(new_libc_maps, "%lx", libc_addr);
		new_libc_maps[8] = '-';
		sprintf(new_libc_maps + 9, "%x", libc_addr + 0x46000);
		LOGD("new_libc_maps = %s\n", new_libc_maps);
		sprintf(re_path, "%s", str_mapsfile);


		FILE *fpr, *fpw;
		int i = 0;

		fpr = fopen(path, "r");
		if (fpr == NULL)
		{
			LOGD("[openat] path [%s]failed", path);
			return NULL;
		}

		fpw = fopen(re_path, "w");
		if (fpw == NULL)
		{
			LOGD("[openat] re-path [%s]failed", re_path);
			return NULL;
		}
		while (fgets(buffer, BUFFERSIZE, fpr) != NULL)
		{
			if (strstr(buffer, "libc.so") != NULL)
			{
//				LOGD("buffer_maps = %s", buffer);
				for(i = 0; i < 17 ; i++)
				{
					buffer[i] = new_libc_maps[i];
				}
				fputs(buffer, fpw);

			}
			else
			{
				fputs(buffer, fpw);
			}
		}

		fclose(fpr);
		fclose(fpw);
		return old_openat(re_path, flags, mode);
	}

	FILE * result = old_openat(path, flags, mode);
    if(result == NULL)
        LOGD("[openat] file path = %s [failed]", path);
    return result;
}

DIR* newopendir(const char * name)
{
    if(strstr(name, "/system/bin") != NULL |
        strstr(name, "/system/xbin") != NULL)
        {
            return old_opendir("/system/app");
        }
    else{
        return old_opendir(name);
    }
}

int hook_entry(char *a){
    LOGD("Start to hook.\n");
	void *handle = NULL;
	handle = (void*)dlopen(str_HookUtilSO, RTLD_NOW);

	if(handle == NULL)
	{
        const char* err = dlerror();
		LOGD("dlopen libHookUtil file error. %s", err);
        
		return 0;
	}
    //原函数
    old_fopen = fopen;
    old_open = open;
    old_openat = openat;
    old_inotify_add_watch = inotify_add_watch;
    old_sys_get = __system_property_get;
    old_opendir = opendir;

	int (*hook_export) (char *soPath, void* newFunc, void* oldFunc);
	void* (*get_module_base)(pid_t pid, const char* module_name);
	hook_export = dlsym(handle, "hook_export");
	get_module_base = dlsym(handle, "get_module_base");

	hook_export("/system/lib/libc.so", (void*)newOpen, (void*)old_open);
    hook_export("/system/lib/libc.so", (void*)newOpenat, (void*)old_openat);
	hook_export("/system/lib/libc.so", (void*)newFopen, (void*)old_fopen);
	hook_export("/system/lib/libc.so", (void*)new_inotify_add_watch, (void*)old_inotify_add_watch);
    hook_export("/system/lib/libc.so", (void*)newopendir, (void*)old_opendir);
	hook_export("/system/lib/libc.so", (void*)new_sys_get, (void*)old_sys_get);
//	offset_sysget = (uint32_t)old_sys_get - (uint32_t)libc_addr;
	dlclose(handle);
    return 1;
}
