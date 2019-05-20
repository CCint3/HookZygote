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

#define LOG_TAG "Hook"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

void* get_module_base(pid_t pid, const char* module_name) //取模块基地址
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}

int hook_export(char *soPath, void* newFunc, void* oldFunc)
{
	void * so_base_addr = get_module_base(getpid(), soPath);
    LOGD("[+] so_base_addr = %p\n", so_base_addr);
    LOGD("[+] oldFunc address = %p\n", oldFunc);
    LOGD("[+] newFunc address = %p\n", newFunc);

    int fd;
    fd = open(soPath, O_RDONLY);
    if (-1 == fd) {
        LOGD("[-] open %s failed!\n", soPath);
        return -1;
    }
    LOGD("[+] open %s success!\n", soPath);
    Elf32_Ehdr ehdr;
    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    unsigned long shdr_addr = ehdr.e_shoff; // 节区头部表偏移
    int shnum = ehdr.e_shnum;
    int shent_size = ehdr.e_shentsize; // 节区头部表格的表项大小
    unsigned long stridx = ehdr.e_shstrndx;

    Elf32_Shdr shdr;
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(fd, &shdr, shent_size);// 读取该表项的内容

    char * string_table = (char *)malloc(shdr.sh_size); // 节区名称字符串表节区的大小
    char * strtab_table; // 字符串表节区的大小
    lseek(fd, shdr.sh_offset, SEEK_SET);
    read(fd, string_table, shdr.sh_size); // 读取节区名称字符串表节区
    lseek(fd, shdr_addr, SEEK_SET); // 定位到节区头部表

    int i;
    int fopen_found = 0;
    int open_found = 0;
    int notiaddwatch_found = 0;
    int sysget_found = 0;
    uint32_t out_addr = 0;
    uint32_t sym_addr = 0;
    uint32_t out_size = 0;
    uint32_t sym_st_value = 0;
    uint32_t sym_size = sizeof(Elf32_Sym);
    Elf32_Sym* sym;
    char *sym_name;
    char *sym_name2;
//	LOGD("sym_size = %lx \n", sym_size);


    LOGD("[+] shnum = %d !\n", shnum);
	for (i = 0; i < shnum; i++) {
		read(fd, &shdr, shent_size);
		int name_idx = shdr.sh_name;
		sym_name = &(string_table[name_idx]);
		LOGD("name_idx = %lx, sym_name = %s\n", name_idx, sym_name);
		if (strcmp(sym_name, ".dynstr") == 0) {
			out_addr = so_base_addr + shdr.sh_addr;//dynstr section address
			out_size = shdr.sh_size;
			LOGD("dynstr_addr = %lx, dynstr_size = %lx\n", out_addr, out_size);
			strtab_table = (char *)malloc(out_size);
			lseek(fd, shdr.sh_addr, SEEK_SET); // 定位到字符串表
		    read(fd, strtab_table, out_size); // 读取字符串表节区
		    break;
		}
	 }

	lseek(fd, shdr_addr, SEEK_SET);
    for (i = 0; i < shnum; i++) {
        read(fd, &shdr, shent_size);
		int name_idx = shdr.sh_name;
		int name_idx_str = 0;
		sym_name = &(string_table[name_idx]);
		LOGD("name_idx = %lx, sym_name = %s\n", name_idx, sym_name);
		if (strcmp(sym_name, ".dynsym") == 0) {
			out_addr = so_base_addr + shdr.sh_addr;//dynsym section address
			out_size = shdr.sh_size;
			LOGD("out_addr = %lx, out_size = %lx\n", out_addr, out_size);

			for (i = 0; i < out_size; i+=sym_size) {

				out_addr = out_addr + sym_size;
				sym = (Elf32_Sym*)out_addr;
				sym_st_value = sym->st_value;
				name_idx_str = sym->st_name;
				sym_name2 = &(strtab_table[name_idx_str]);
//					LOGD("sym_st_value = %lx, sym_st_name = %d , sym_name2 = %s\n", sym_st_value, name_idx_str, sym_name2);
				sym_addr = sym_st_value + so_base_addr;
				if (sym_addr  == oldFunc)
				{
					LOGD("Found %s in section dynsym. st_value = %lx\n", sym_name2, sym_st_value);
					uint32_t page_size = getpagesize();
					uint32_t entry_page_start = (out_addr + 4) & (~(page_size - 1));
					mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
					*(uint32_t *)(out_addr + 4) = newFunc - (uint32_t)so_base_addr;
					break;
				}
				else if(sym_addr  == newFunc)
				{
					LOGD("This function has already hooked.");
					break;
				}
			}
			break;
		}
    }

    free(string_table);
    free(strtab_table);
    close(fd);
}
