#if !defined(_opusaudio_h)
# define _opusaudio_h (1)

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/**@cond PRIVATE*/

/*Enable special features for gcc and gcc-compatible compilers.*/
# if !defined(OP_GNUC_PREREQ)
#  if defined(__GNUC__)&&defined(__GNUC_MINOR__)
#   define OP_GNUC_PREREQ(_maj,_min) \
 ((__GNUC__<<16)+__GNUC_MINOR__>=((_maj)<<16)+(_min))
#  else
#   define OP_GNUC_PREREQ(_maj,_min) 0
#  endif
# endif

# if OP_GNUC_PREREQ(4,0)
#  pragma GCC visibility push(default)
# endif

/*Warning attributes for libopusfile functions.*/
# if OP_GNUC_PREREQ(3,4)
#  define OP_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
# else
#  define OP_WARN_UNUSED_RESULT
# endif
# if OP_GNUC_PREREQ(3,4)
#  define OP_ARG_NONNULL(_x) __attribute__((__nonnull__(_x)))
# else
#  define OP_ARG_NONNULL(_x)
# endif

/**@endcond*/

int encode(char *, char *,char *);

int decode(char *, char *, char *);

int startRecording(const char *pathStr);

void stopRecording(void);

long getTotalPcmDuration(void);

int getFinished(void);

int getSize(void);

long getPcmOffset(void);

void readOpusFile(uint8_t *buffer, int capacity);

int writeFrame(uint8_t *framePcmBytes, unsigned int frameByteCount);

int seekOpusFile(float position);

int openOpusFile(const char *path);

void closeOpusFile(void);

int isOpusFile(const char *path);


#define MAX_CMD_NUM 32
#define MAX_CMD_BUFFER 1024

int strToArgv(char *str, char *arg[]);

#endif
