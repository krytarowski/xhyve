#pragma once

#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#define SBT_1S  ((sbintime_t)1 << 32)
#define SBT_1M  (SBT_1S * 60)
#define SBT_1MS (SBT_1S / 1000)
#define SBT_1US (SBT_1S / 1000000)
#define SBT_1NS (SBT_1S / 1000000000)
#define SBT_MAX 0x7fffffffffffffffLL

#define	FREQ2BT(freq, bt) \
{ \
  (bt)->sec = 0; \
  (bt)->frac = ((uint64_t)0x8000000000000000  / (freq)) << 1; \
}

#define BT2FREQ(bt) \
  (((uint64_t)0x8000000000000000 + ((bt)->frac >> 2)) / \
    ((bt)->frac >> 1))

#if !defined(__NetBSD__)
struct bintime {
  uint64_t sec;
  uint64_t frac;
};
#endif

typedef int64_t sbintime_t;

static inline sbintime_t bttosbt(const struct bintime bt) {
  return (sbintime_t) (((uint64_t)bt.sec << 32) + (bt.frac >> 32));
}

static inline void bintime_mul(struct bintime *bt, unsigned int x) {
  uint64_t p1, p2;
  
  p1 = (bt->frac & 0xffffffffull) * x;
  p2 = (bt->frac >> 32) * x + (p1 >> 32);
  bt->sec *= x;
  bt->sec += (p2 >> 32);
  bt->frac = (p2 << 32) | (p1 & 0xffffffffull);
}

#if !defined(__NetBSD__)
static inline void bintime_add(struct bintime *_bt, const struct bintime *_bt2)
{
  uint64_t _u;

  _u = _bt->frac;
  _bt->frac += _bt2->frac;
  if (_u > _bt->frac)
    _bt->sec++;
  _bt->sec += _bt2->sec;
}

static inline void bintime_sub(struct bintime *_bt, const struct bintime *_bt2)
{
  uint64_t _u;

  _u = _bt->frac;
  _bt->frac -= _bt2->frac;
  if (_u < _bt->frac)
    _bt->sec--;
  _bt->sec -= _bt2->sec;
}
#endif

#define bintime_cmp(a, b, cmp) \
  (((a)->sec == (b)->sec) ? \
    ((a)->frac cmp (b)->frac) : \
    ((a)->sec cmp (b)->sec))


void binuptime(struct bintime *bt);
void getmicrotime(struct timeval *tv);

static inline struct bintime
sbttobt(sbintime_t _sbt)
{
	struct bintime _bt;

	_bt.sec = (uint64_t)_sbt >> 32;
	_bt.frac = (uint64_t)_sbt << 32;
	return (_bt);
}

static inline int64_t
sbttons(sbintime_t _sbt)
{

	return ((1000000000 * _sbt) >> 32);
}

static inline struct timespec
sbttots(sbintime_t _sbt)
{
	struct timespec _ts;

	_ts.tv_sec = _sbt >> 32;
	_ts.tv_nsec = sbttons((uint32_t)_sbt);
	return (_ts);
}

static inline sbintime_t sbinuptime(void) {
  struct bintime _bt;
  
  binuptime(&_bt);
  return (bttosbt(_bt));
}

struct callout {
  pthread_cond_t wait;
  struct callout *prev;
  struct callout *next;
#if defined(__APPLE__)
  uint64_t timeout;
#elif defined(__NetBSD__)
  struct timespec timeout;
#endif
  void *argument;
  void (*callout)(void *);
  int flags;
  int queued;
};

#define C_ABSOLUTE 0x0200 /* event time is absolute */
#define CALLOUT_ACTIVE 0x0002 /* callout is currently active */
#define CALLOUT_PENDING 0x0004 /* callout is waiting for timeout */
#define CALLOUT_MPSAFE 0x0008 /* callout handler is mp safe */
#define CALLOUT_RETURNUNLOCKED 0x0010 /* handler returns with mtx unlocked */
#define CALLOUT_COMPLETED 0x0020 /* callout thread finished */
#define CALLOUT_WAITING 0x0040 /* thread waiting for callout to finish */
//#define CALLOUT_QUEUED 0x0080

void callout_system_init(void);
void callout_init(struct callout *c, int mpsafe);
int callout_reset_sbt(struct callout *c, sbintime_t sbt,
  sbintime_t precision, void (*ftn)(void *), void *arg,
  int flags);

int callout_stop_safe(struct callout *c, int drain);

#define callout_active(c) ((c)->flags & CALLOUT_ACTIVE)
#define callout_deactivate(c) ((c)->flags &= ~CALLOUT_ACTIVE)
#define callout_pending(c)  ((c)->flags & CALLOUT_PENDING)
#define callout_completed(c)  ((c)->flags & CALLOUT_COMPLETED)
#define callout_drain(c) callout_stop_safe(c, 1)
#define callout_stop(c) callout_stop_safe(c, 0)
