// SPDX-License-Identifier: GPL-2.0

#define MAX_DESCRIPTION 1024
#define MAX_DA_NAME_LEN	32

struct monitor {
	char name[MAX_DA_NAME_LEN];
	char desc[MAX_DESCRIPTION];
	int enabled;
	int nested;
};

int should_stop(void);
