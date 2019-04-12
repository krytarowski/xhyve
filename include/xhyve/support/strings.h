#pragma once

#if defined(__NetBSD__)
/*
 * Find First Set bit
 */
static inline int
ffsll(long long mask)
{
	int bit;

	if (mask == 0)
		return (0);
	for (bit = 1; !(mask & 1); bit++)
		mask = (unsigned long long)mask >> 1;
	return (bit);
}

/*
 * Find Last Set bit
 */
static inline int
flsl(long mask)
{
	int bit;

	if (mask == 0)
		return (0);
	for (bit = 1; mask != 1; bit++)
		mask = (unsigned long)mask >> 1;
	return (bit);
}

/*
 * Find Last Set bit
 */
static inline int
flsll(long long mask)
{
	int bit;

	if (mask == 0)
		return (0);
	for (bit = 1; mask != 1; bit++)
		mask = (unsigned long long)mask >> 1;
	return (bit);
}

/*
 * Find Last Set bit
 */
static inline int
fls(int mask)
{
	int bit;

	if (mask == 0)
		return (0);
	for (bit = 1; mask != 1; bit++)
		mask = (unsigned int)mask >> 1;
	return (bit);
}
#endif
