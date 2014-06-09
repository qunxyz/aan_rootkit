obj-m += syscall.o

KERNEL_DIR = /lib/modules/$(shell uname -r)/build
OLD_KERNEL_DIR = /mnt/db/zhaw/aan/kernel/linux-3.10.4/ 
PWD = $(shell pwd)

all:
	 $(MAKE) -C $(OLD_KERNEL_DIR) M=$(PWD)

clean:
	 rm -rf *.o *.ko *.symvers *.mod.* *.order
