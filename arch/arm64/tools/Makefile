# SPDX-License-Identifier: GPL-2.0

gen := arch/$(ARCH)/include/generated
kapi := $(gen)/asm

include $(srctree)/arch/arm64/tools/Makefile.sysreg

targets += $(addprefix ../../../, $(kapi)/cpucap-defs.h)

PHONY += kapi

all: $(syscall64) kapi

kapi:   $(kapi)/cpucap-defs.h

quiet_cmd_gen_cpucaps = GEN     $@
      cmd_gen_cpucaps = mkdir -p $(dir $@); $(AWK) -f $(real-prereqs) > $@

$(kapi)/cpucap-defs.h: $(src)/gen-cpucaps.awk $(src)/cpucaps FORCE
	$(call if_changed,gen_cpucaps)
