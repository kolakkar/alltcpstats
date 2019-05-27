# IF KERNELRELEASE IS DEFINED I HAVE BEEN INVOKED FROM THE KERNEL SUBSYSTEM
# ELSE I WAS INVOKED MANUALLY
ifneq ($(KERNELRELEASE),)
	obj-m+=seqtcpmod.o
else
	KERNELDIR ?=/usr/src/kernels/$(shell uname -r)/build
	PWD	:= $(shell pwd)
all:
	make -C /usr/src/kernels/2.6.18-128.el5-x86_64/ M=$(PWD) modules

clean:
	make -C /usr/src/kernels/2.6.18-128.el5-x86_64/ M=$(PWD) clean
endif
