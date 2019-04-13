/*	$NetBSD$	*/
/*
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD$");

#include <sys/module.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
check_permission(void)
{

	if (modctl(MODCTL_EXISTS, 0) == 0)
		return 0;

	/* Allow module loading administratively forbidden */
	if (errno == EPERM)
		return 0;

	return errno;
}

int
get_module_info(const char *name, modstat_t *msdest)
{
	bool found;
	size_t len;
	int count;
	struct iovec iov;
	modstat_t *ms;
	int saved_errno;
	int rv;

	saved_errno = errno;
	errno = 0;

	rv = check_permission();
	if (rv)
		goto fini;

	for (len = 8192; ;) {
		iov.iov_base = malloc(len);
		if (iov.iov_base == NULL) {
			rv = errno;
			goto fini;
		}
		iov.iov_len = len;

		if (modctl(MODCTL_STAT, &iov) != 0) {
			rv = errno;
			free(iov.iov_base);
			goto fini;
		}
		if (len >= iov.iov_len)
			break;
		free(iov.iov_base);
		len = iov.iov_len;
	}

	found = false;
	count = *(int *)iov.iov_base;
	ms = (modstat_t *)((char *)iov.iov_base + sizeof(int));
	while (count > 0) {
		if (strcmp(ms->ms_name, name) == 0) {
			if (msdest != NULL)
				*msdest = *ms;
			found = true;
			break;
		}
		ms++;
		count--;
	}

	free(iov.iov_base);

	if (found)
		rv = 0;
	else
		rv = ENOENT;

fini:
	errno = saved_errno;

	return rv;
}
