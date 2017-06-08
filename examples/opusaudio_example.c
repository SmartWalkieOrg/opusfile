/********************************************************************
 *                                                                  *
 * THIS FILE IS PART OF THE libopusfile SOFTWARE CODEC SOURCE CODE. *
 * USE, DISTRIBUTION AND REPRODUCTION OF THIS LIBRARY SOURCE IS     *
 * GOVERNED BY A BSD-STYLE SOURCE LICENSE INCLUDED WITH THIS SOURCE *
 * IN 'COPYING'. PLEASE READ THESE TERMS BEFORE DISTRIBUTING.       *
 *                                                                  *
 * THE libopusfile SOURCE CODE IS (C) COPYRIGHT 1994-2012           *
 * by the Xiph.Org Foundation and contributors http://www.xiph.org/ *
 *                                                                  *
 ********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*For fileno()*/
#if !defined(_POSIX_SOURCE)
# define _POSIX_SOURCE 1
#endif
#include <errno.h>
#include <string.h>
#include <opus/opus.h>
#include <opusaudio.h>
#if defined(_WIN32)
# include "win32utf8.h"
# undef fileno
# define fileno _fileno
#endif

#define FRAME_SIZE 960
#define SAMPLE_RATE 16000
#define CHANNELS 1
#define ENCODER_SIZE 133
#define MAX_BUFFER_SIZE 1920

int main(int _argc, const char **_argv) {
  const char *inFile;
  FILE *fin;
  unsigned char bytes[ENCODER_SIZE];
  unsigned char pcm_frame_2[MAX_BUFFER_SIZE];
  int result;
  int error;
  OpusDecoder *decoder;
  int res = 0;
  int i = 0;

#if defined(_WIN32)
  win32_utf8_setup(&_argc, &_argv);
#endif

  if(_argc != 3) {
    fprintf(stderr,"Usage: %s <input.opus> <output.opus>", _argv[0]);
    return EXIT_FAILURE;
  }

  inFile = _argv[1];
  fin = fopen(inFile, "rb");
  if (fin == NULL) {
     fprintf(stderr, "\nfailed to open input file: %s", strerror(errno));
     return EXIT_FAILURE;
  }

  result = startRecording(_argv[2]);
  if (result != 1) {
    fprintf(stderr, "\nresult: %s", opus_strerror(result));
    return EXIT_FAILURE;
  }

  decoder = opus_decoder_create(SAMPLE_RATE, CHANNELS, &error);
  if (error != 0) {
    fprintf(stderr, "\nerror: %s", opus_strerror(error));
    return EXIT_FAILURE;
  }

  while (!feof(fin)) {
    i++;
    fread(bytes, sizeof(unsigned char), ENCODER_SIZE, fin);
    res = opus_decode(decoder, bytes, ENCODER_SIZE, (short *)(pcm_frame_2), FRAME_SIZE, 0);
    if (res < 0) {
      fprintf(stderr, "\nres: %d decoder: %s", res, opus_strerror(res));
      return EXIT_FAILURE;
    }
    writeFrame(pcm_frame_2, MAX_BUFFER_SIZE);
  }

  opus_decoder_destroy(decoder);
  stopRecording();
  fclose(fin);

  fprintf(stdout, "number of converted frames: %d\n", i);

  return 0;
}
