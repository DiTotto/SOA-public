ifndef KERNELDIR
	KERNELDIR  := /lib/modules/$(shell uname -r)/build
endif

obj-m += monitor.o

monitor-objs := utils/hash.o utils/func_aux.o ref.o

# Aggiungo CFLAGS per abilitare C99
ccflags-y := -std=gnu99

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	
mount:
	insmod monitor.ko the_file=$(realpath ./singlefile-FS/mount/the-file)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

unmount:
	rmmod monitor.ko