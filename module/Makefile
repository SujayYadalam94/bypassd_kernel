KERNELDIR := $(abspath $(CURDIR)/../linux-5.4)
PWD := $(shell pwd)

obj-m += main.o
ccflags-y += -g -DDEBUG
CC += -g -DDEBUG


default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
