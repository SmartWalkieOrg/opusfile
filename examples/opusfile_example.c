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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <opusfile.h>
#include <opus/opus.h>
#include <ogg/ogg.h>
#if defined(_WIN32)
# include "win32utf8.h"
# undef fileno
# define fileno _fileno
#endif

static void print_duration(FILE *_fp,ogg_int64_t _nsamples,int _frac){
  ogg_int64_t seconds;
  ogg_int64_t minutes;
  ogg_int64_t hours;
  ogg_int64_t days;
  ogg_int64_t weeks;
  _nsamples+=_frac?24:24000;
  seconds=_nsamples/48000;
  _nsamples-=seconds*48000;
  minutes=seconds/60;
  seconds-=minutes*60;
  hours=minutes/60;
  minutes-=hours*60;
  days=hours/24;
  hours-=days*24;
  weeks=days/7;
  days-=weeks*7;
  if(weeks)fprintf(_fp,"%liw",(long)weeks);
  if(weeks||days)fprintf(_fp,"%id",(int)days);
  if(weeks||days||hours){
    if(weeks||days)fprintf(_fp,"%02ih",(int)hours);
    else fprintf(_fp,"%ih",(int)hours);
  }
  if(weeks||days||hours||minutes){
    if(weeks||days||hours)fprintf(_fp,"%02im",(int)minutes);
    else fprintf(_fp,"%im",(int)minutes);
    fprintf(_fp,"%02i",(int)seconds);
  }
  else fprintf(_fp,"%i",(int)seconds);
  if(_frac)fprintf(_fp,".%03i",(int)(_nsamples/48));
  fprintf(_fp,"s");
}

static void print_size(FILE *_fp,opus_int64 _nbytes,int _metric,
 const char *_spacer){
  static const char SUFFIXES[7]={' ','k','M','G','T','P','E'};
  opus_int64 val;
  opus_int64 den;
  opus_int64 round;
  int        base;
  int        shift;
  base=_metric?1000:1024;
  round=0;
  den=1;
  for(shift=0;shift<6;shift++){
    if(_nbytes<den*base-round)break;
    den*=base;
    round=den>>1;
  }
  val=(_nbytes+round)/den;
  if(den>1&&val<10){
    if(den>=1000000000)val=(_nbytes+(round/100))/(den/100);
    else val=(_nbytes*100+round)/den;
    fprintf(_fp,"%li.%02i%s%c",(long)(val/100),(int)(val%100),
     _spacer,SUFFIXES[shift]);
  }
  else if(den>1&&val<100){
    if(den>=1000000000)val=(_nbytes+(round/10))/(den/10);
    else val=(_nbytes*10+round)/den;
    fprintf(_fp,"%li.%i%s%c",(long)(val/10),(int)(val%10),
     _spacer,SUFFIXES[shift]);
  }
  else fprintf(_fp,"%li%s%c",(long)val,_spacer,SUFFIXES[shift]);
}

static void put_le32(unsigned char *_dst,opus_uint32 _x){
  _dst[0]=(unsigned char)(_x&0xFF);
  _dst[1]=(unsigned char)(_x>>8&0xFF);
  _dst[2]=(unsigned char)(_x>>16&0xFF);
  _dst[3]=(unsigned char)(_x>>24&0xFF);
}

/*Make a header for a 48 kHz, stereo, signed, 16-bit little-endian PCM WAV.*/
static void make_wav_header(unsigned char _dst[44],ogg_int64_t _duration){
  /*The chunk sizes are set to 0x7FFFFFFF by default.
    Many, though not all, programs will interpret this to mean the duration is
     "undefined", and continue to read from the file so long as there is actual
     data.*/
  static const unsigned char WAV_HEADER_TEMPLATE[44]={
    'R','I','F','F',0xFF,0xFF,0xFF,0x7F,
    'W','A','V','E','f','m','t',' ',
    0x10,0x00,0x00,0x00,0x01,0x00,0x02,0x00,
    0x80,0xBB,0x00,0x00,0x00,0xEE,0x02,0x00,
    0x04,0x00,0x10,0x00,'d','a','t','a',
    0xFF,0xFF,0xFF,0x7F
  };
  memcpy(_dst,WAV_HEADER_TEMPLATE,sizeof(WAV_HEADER_TEMPLATE));
  if(_duration>0){
    if(_duration>0x1FFFFFF6){
      fprintf(stderr,"WARNING: WAV output would be larger than 2 GB.\n");
      fprintf(stderr,
       "Writing non-standard WAV header with invalid chunk sizes.\n");
    }
    else{
      opus_uint32 audio_size;
      audio_size=(opus_uint32)(_duration*4);
      put_le32(_dst+4,audio_size+36);
      put_le32(_dst+40,audio_size);
    }
  }
}

#ifndef max
#define max(x, y) ((x) > (y)) ? (x) : (y)
#endif
#ifndef min
#define min(x, y) ((x) < (y)) ? (x) : (y)
#endif

typedef struct {
    int version;
    int channels; /* Number of channels: 1..255 */
    int preskip;
    ogg_uint32_t input_sample_rate;
    int gain; /* in dB S7.8 should be zero whenever possible */
    int channel_mapping;
    /* The rest is only used if channel_mapping != 0 */
    int nb_streams;
    int nb_coupled;
    unsigned char stream_map[255];
} OpusHeader;

typedef struct {
    void *readdata;
    opus_int64 total_samples_per_channel;
    int rawmode;
    int channels;
    long rate;
    int gain;
    int samplesize;
    int endianness;
    char *infilename;
    int ignorelength;
    int skip;
    int extraout;
    char *comments;
    int comments_length;
    int copy_comments;
} oe_enc_opt;

typedef struct {
    unsigned char *data;
    int maxlen;
    int pos;
} Packet;

const opus_int32 bitrate = 16000;
const opus_int32 rate = 16000;
const opus_int32 frame_size = 960;
const int with_cvbr = 1;
const int max_ogg_delay = 0;
const int comment_padding = 512;

opus_int32 coding_rate = 16000;
ogg_int32_t _packetId;
OpusEncoder *_encoder = 0;
uint8_t *_packet = 0;
ogg_stream_state os;
FILE *_fileOs = 0;
oe_enc_opt inopt;
OpusHeader header;
opus_int32 min_bytes;
int max_frame_bytes;
ogg_packet op;
ogg_page og;
opus_int64 bytes_written;
opus_int64 pages_out;
opus_int64 total_samples;
ogg_int64_t enc_granulepos;
ogg_int64_t last_granulepos;
int size_segments;
int last_segments;

static int write_uint32(Packet *p, ogg_uint32_t val) {
    if (p->pos > p->maxlen - 4) {
        return 0;
    }
    p->data[p->pos  ] = (val    ) & 0xFF;
    p->data[p->pos+1] = (val>> 8) & 0xFF;
    p->data[p->pos+2] = (val>>16) & 0xFF;
    p->data[p->pos+3] = (val>>24) & 0xFF;
    p->pos += 4;
    return 1;
}

static int write_uint16(Packet *p, ogg_uint16_t val) {
    if (p->pos > p->maxlen-2) {
        return 0;
    }
    p->data[p->pos  ] = (val    ) & 0xFF;
    p->data[p->pos+1] = (val>> 8) & 0xFF;
    p->pos += 2;
    return 1;
}

static int write_chars(Packet *p, const unsigned char *str, int nb_chars)
{
    int i;
    if (p->pos>p->maxlen-nb_chars)
        return 0;
    for (i=0;i<nb_chars;i++)
        p->data[p->pos++] = str[i];
    return 1;
}

void cleanupRecorder() {
  if (_encoder) {
    opus_encoder_destroy(_encoder);
    _encoder = 0;
  }

  ogg_stream_clear(&os);

  if (_packet) {
    free(_packet);
    _packet = 0;
  }

  if (_fileOs) {
    fclose(_fileOs);
    _fileOs = 0;
  }

  _packetId = -1;
  bytes_written = 0;
  pages_out = 0;
  total_samples = 0;
  enc_granulepos = 0;
  size_segments = 0;
  last_segments = 0;
  last_granulepos = 0;
  memset(&os, 0, sizeof(ogg_stream_state));
  memset(&inopt, 0, sizeof(oe_enc_opt));
  memset(&header, 0, sizeof(OpusHeader));
  memset(&op, 0, sizeof(ogg_packet));
  memset(&og, 0, sizeof(ogg_page));

  fprintf(stderr, "Recording ends!!!\n");
}


int opus_header_to_packet_(const OpusHeader *h, unsigned char *packet, int len) {
    int i;
    Packet p;
    unsigned char ch;

    p.data = packet;
    p.maxlen = len;
    p.pos = 0;
    if (len < 19) {
        return 0;
    }
    if (!write_chars(&p, (const unsigned char *)"OpusHead", 8)) {
        return 0;
    }

    ch = 1;
    if (!write_chars(&p, &ch, 1)) {
        return 0;
    }

    ch = h->channels;
    if (!write_chars(&p, &ch, 1)) {
        return 0;
    }

    if (!write_uint16(&p, h->preskip)) {
        return 0;
    }

    if (!write_uint32(&p, h->input_sample_rate)) {
        return 0;
    }

    if (!write_uint16(&p, h->gain)) {
        return 0;
    }

    ch = h->channel_mapping;
    if (!write_chars(&p, &ch, 1)) {
        return 0;
    }

    if (h->channel_mapping != 0) {
        ch = h->nb_streams;
        if (!write_chars(&p, &ch, 1)) {
            return 0;
        }

        ch = h->nb_coupled;
        if (!write_chars(&p, &ch, 1)) {
            return 0;
        }

        /* Multi-stream support */
        for (i = 0; i < h->channels; i++) {
            if (!write_chars(&p, &h->stream_map[i], 1)) {
                return 0;
            }
        }
    }

    return p.pos;
}

#define writeint(buf, base, val) do { buf[base + 3] = ((val) >> 24) & 0xff; \
buf[base + 2]=((val) >> 16) & 0xff; \
buf[base + 1]=((val) >> 8) & 0xff; \
buf[base] = (val) & 0xff; \
} while(0)

static void comment_init(char **comments, int *length, const char *vendor_string) {
    /* The 'vendor' field should be the actual encoding library used */
    int vendor_length = strlen(vendor_string);
    int user_comment_list_length = 0;
    int len = 8 + 4 + vendor_length + 4;
    char *p = (char *)malloc(len);
    memcpy(p, "OpusTags", 8);
    writeint(p, 8, vendor_length);
    memcpy(p + 12, vendor_string, vendor_length);
    writeint(p, 12 + vendor_length, user_comment_list_length);
    *length = len;
    *comments = p;
}

static void comment_pad(char **comments, int* length, int amount) {
    if (amount > 0) {
        char *p = *comments;
        /* Make sure there is at least amount worth of padding free, and round up to the maximum that fits in the current ogg segments */
        int newlen = (*length + amount + 255) / 255 * 255 - 1;
        p = realloc(p, newlen);
        int i = 0;
        for (i = *length; i < newlen; i++) {
            p[i] = 0;
        }
        *comments = p;
        *length = newlen;
    }
}

static int writeOggPage(ogg_page *page, FILE *os) {
    int written = fwrite(page->header, sizeof(unsigned char), page->header_len, os);
    written += fwrite(page->body, sizeof(unsigned char), page->body_len, os);
    return written;
}

int initRecorder(const char *path) {
  cleanupRecorder();

  fprintf(stderr, "in Recorder, path: %s\n", path);
  if (!path) {
    return 0;
  }

  _fileOs = fopen(path, "wb");
  if (!_fileOs) {
    return 0;
  }

  inopt.rate = rate;
  inopt.gain = 0;
  inopt.endianness = 0;
  inopt.copy_comments = 0;
  inopt.rawmode = 1;
  inopt.ignorelength = 1;
  inopt.samplesize = 16;
  inopt.channels = 1;
  inopt.skip = 0;

  comment_init(&inopt.comments, &inopt.comments_length, opus_get_version_string());

  if (rate > 24000) {
    coding_rate = 48000;
  } else if (rate > 16000) {
    coding_rate = 24000;
  } else if (rate > 12000) {
    coding_rate = 16000;
  } else if (rate > 8000) {
    coding_rate = 12000;
  } else {
    coding_rate = 8000;
  }

  /*   frame_size=frame_size/(48000/coding_rate); */
  if (rate != coding_rate) {
    fprintf(stderr, "Invalid rate\n");
    return 0;
  }

  header.channels = 1;
  header.channel_mapping = 0;
  header.input_sample_rate = rate;
  header.gain = inopt.gain;
  header.nb_streams = 1;

  int result = OPUS_OK;
  _encoder = opus_encoder_create(coding_rate, 1, OPUS_APPLICATION_AUDIO, &result);
  if (result != OPUS_OK) {
    fprintf(stderr, "Error cannot create encoder: %s\n", opus_strerror(result));
    return 0;
  }

  min_bytes = max_frame_bytes = (1275 * 3 + 7) * header.nb_streams;
  _packet = malloc(max_frame_bytes);

  result = opus_encoder_ctl(_encoder, OPUS_SET_BITRATE(bitrate));
  if (result != OPUS_OK) {
    fprintf(stderr, "Error OPUS_SET_BITRATE returned: %s\n", opus_strerror(result));
    return 0;
  }

#ifdef OPUS_SET_LSB_DEPTH
  result = opus_encoder_ctl(_encoder, OPUS_SET_LSB_DEPTH(max(8, min(24, inopt.samplesize))));
  if (result != OPUS_OK) {
    fprintf(stderr, "Warning OPUS_SET_LSB_DEPTH returned: %s\n", opus_strerror(result));
  }
#endif

  opus_int32 lookahead;
  result = opus_encoder_ctl(_encoder, OPUS_GET_LOOKAHEAD(&lookahead));
  if (result != OPUS_OK) {
    fprintf(stderr, "Error OPUS_GET_LOOKAHEAD returned: %s\n", opus_strerror(result));
    return 0;
  }

  inopt.skip += lookahead;
  header.preskip = (int)(inopt.skip * (48000.0 / coding_rate));
  inopt.extraout = (int)(header.preskip * (rate / 48000.0));

  if (ogg_stream_init(&os, rand()) == -1) {
    fprintf(stderr, "Error: stream init failed");
    return 0;
  }

  unsigned char header_data[100];
  int packet_size = opus_header_to_packet_(&header, header_data, 100);
  op.packet = header_data;
  op.bytes = packet_size;
  op.b_o_s = 1;
  op.e_o_s = 0;
  op.granulepos = 0;
  op.packetno = 0;
  ogg_stream_packetin(&os, &op);

  while ((result = ogg_stream_flush(&os, &og))) {
    if (!result) {
      break;
    }

    int pageBytesWritten = writeOggPage(&og, _fileOs);
    if (pageBytesWritten != og.header_len + og.body_len) {
      fprintf(stderr, "Error: failed writing header to output stream");
      return 0;
    }
    bytes_written += pageBytesWritten;
    pages_out++;
  }

  comment_pad(&inopt.comments, &inopt.comments_length, comment_padding);
  op.packet = (unsigned char *)inopt.comments;
  op.bytes = inopt.comments_length;
  op.b_o_s = 0;
  op.e_o_s = 0;
  op.granulepos = 0;
  op.packetno = 1;
  ogg_stream_packetin(&os, &op);

  while ((result = ogg_stream_flush(&os, &og))) {
    if (result == 0) {
      break;
    }

    int writtenPageBytes = writeOggPage(&og, _fileOs);
    if (writtenPageBytes != og.header_len + og.body_len) {
      fprintf(stderr, "Error: failed writing header to output stream");
      return 0;
    }

    bytes_written += writtenPageBytes;
    pages_out++;
  }

  free(inopt.comments);

  return 1;
}

int writeFrame(uint8_t *framePcmBytes, unsigned int frameByteCount) {
    int cur_frame_size = frame_size;
    _packetId++;

    opus_int32 nb_samples = frameByteCount / 2;
    total_samples += nb_samples;
    if (nb_samples < frame_size) {
        op.e_o_s = 1;
    } else {
        op.e_o_s = 0;
    }

    int nbBytes = 0;

    if (nb_samples != 0) {
        uint8_t *paddedFrameBytes = framePcmBytes;
        int freePaddedFrameBytes = 0;

        if (nb_samples < cur_frame_size) {
            paddedFrameBytes = malloc(cur_frame_size * 2);
            freePaddedFrameBytes = 1;
            memcpy(paddedFrameBytes, framePcmBytes, frameByteCount);
            memset(paddedFrameBytes + nb_samples * 2, 0, cur_frame_size * 2 - nb_samples * 2);
        }

        nbBytes = opus_encode(_encoder, (opus_int16 *)paddedFrameBytes, cur_frame_size, _packet, max_frame_bytes / 10);
        if (freePaddedFrameBytes) {
            free(paddedFrameBytes);
            paddedFrameBytes = NULL;
        }

        if (nbBytes < 0) {
            fprintf(stderr, "Encoding failed: %s. Aborting.\n", opus_strerror(nbBytes));
            return 0;
        }

        enc_granulepos += cur_frame_size * 48000 / coding_rate;
        size_segments = (nbBytes + 255) / 255;
        min_bytes = min(nbBytes, min_bytes);
    }

    while ((((size_segments <= 255) && (last_segments + size_segments > 255)) || (enc_granulepos - last_granulepos > max_ogg_delay)) && ogg_stream_flush_fill(&os, &og, 255 * 255)) {
        if (ogg_page_packets(&og) != 0) {
            last_granulepos = ogg_page_granulepos(&og);
        }

        last_segments -= og.header[26];
        int writtenPageBytes = writeOggPage(&og, _fileOs);
        if (writtenPageBytes != og.header_len + og.body_len) {
            fprintf(stderr, "Error: failed writing data to output stream\n");
            return 0;
        }
        bytes_written += writtenPageBytes;

        pages_out++;
    }

    op.packet = (unsigned char *)_packet;
    op.bytes = nbBytes;
    op.b_o_s = 0;
    op.granulepos = enc_granulepos;
    if (op.e_o_s) {
        op.granulepos = ((total_samples * 48000 + rate - 1) / rate) + header.preskip;
    }
    op.packetno = 2 + _packetId;
    ogg_stream_packetin(&os, &op);
    last_segments += size_segments;

    while ((op.e_o_s || (enc_granulepos + (frame_size * 48000 / coding_rate) - last_granulepos > max_ogg_delay) || (last_segments >= 255)) ? ogg_stream_flush_fill(&os, &og, 255 * 255) : ogg_stream_pageout_fill(&os, &og, 255 * 255)) {
        if (ogg_page_packets(&og) != 0) {
            last_granulepos = ogg_page_granulepos(&og);
        }
        last_segments -= og.header[26];
        int writtenPageBytes = writeOggPage(&og, _fileOs);
        if (writtenPageBytes != og.header_len + og.body_len) {
            fprintf(stderr, "Error: failed writing data to output stream\n");
            return 0;
        }
        bytes_written += writtenPageBytes;
        pages_out++;
    }

    fprintf(stderr, "last byte_written is %lld\n", bytes_written);
    return 1;
}

#define FRAME_SIZE 960
#define SAMPLE_RATE 16000
#define CHANNELS 1
#define ENCODER_SIZE 133
#define MAX_BUFFER_SIZE 1920

int main(int _argc,const char **_argv){
  OggOpusFile  *of;
  ogg_int64_t   duration;
  unsigned char wav_header[44];
  int           ret;
  int           is_ssl;
  int           output_seekable;
#if defined(_WIN32)
  win32_utf8_setup(&_argc,&_argv);
#endif

  char *inFile;
  FILE *fin;
  char *outFile;
  FILE *fout;
  opus_int16 in[FRAME_SIZE*CHANNELS];
  opus_int16 out[FRAME_SIZE*CHANNELS];
  unsigned char cbits[ENCODER_SIZE];
  int nbBytes = 0;

  inFile = _argv[2];
  fin = fopen(inFile, "rb");
  if (fin==NULL)
  {
     fprintf(stderr, "failed to open input file: %s\n", strerror(errno));
     return EXIT_FAILURE;
  }
  unsigned char bytes[ENCODER_SIZE];
  unsigned char pcm_frame_2[MAX_BUFFER_SIZE];

  int result = initRecorder(_argv[1]);

  /*
  outFile = _argv[1];
  fout = fopen(outFile, "ab");
  */
  int error1;
  OpusDecoder *decoder = opus_decoder_create(16000, 1, &error1);
  fprintf(stderr, "OPUS_OK: %d error1: %d\n", OPUS_OK, error1);

  int res = 0;
  int i = 0;
  while (!feof(fin)) {
    i++;
    fread(bytes, sizeof(unsigned char), 133, fin);
    res = opus_decode(decoder, bytes, 133, pcm_frame_2, FRAME_SIZE, 0);
    if (res<0) {
      fprintf(stderr, "res: %d decoder: %s\n", res, opus_strerror(res));
      return EXIT_FAILURE;
    }
    fprintf(stderr, "i: %d res: %d\n", i, res);
    writeFrame(pcm_frame_2, 1920);
    /* fwrite(bytes, 1, res, fout); */
  }

  opus_decoder_destroy(decoder);

  cleanupRecorder();

  fclose(fin);
  /* fclose(fout); */


  if(_argc<2){
    fprintf(stderr,"Usage: %s <file.opus>\n",_argv[0]);
    return EXIT_FAILURE;
  }
  is_ssl=0;
  if(strcmp(_argv[1],"-")==0){
    OpusFileCallbacks cb={NULL,NULL,NULL,NULL};
    of=op_open_callbacks(op_fdopen(&cb,fileno(stdin),"rb"),&cb,NULL,0,&ret);
  }
  else{
    OpusServerInfo info;
    /*Try to treat the argument as a URL.*/
    of=op_open_url(_argv[1],&ret,OP_GET_SERVER_INFO(&info),NULL);
#if 0
    if(of==NULL){
      OpusFileCallbacks  cb={NULL,NULL,NULL,NULL};
      void              *fp;
      /*For debugging: force a file to not be seekable.*/
      fp=op_fopen(&cb,_argv[1],"rb");
      cb.seek=NULL;
      cb.tell=NULL;
      of=op_open_callbacks(fp,&cb,NULL,0,NULL);
    }
#else
    if(of==NULL)of=op_open_file(_argv[1],&ret);
#endif
    else{
      if(info.name!=NULL){
        fprintf(stderr,"Station name: %s\n",info.name);
      }
      if(info.description!=NULL){
        fprintf(stderr,"Station description: %s\n",info.description);
      }
      if(info.genre!=NULL){
        fprintf(stderr,"Station genre: %s\n",info.genre);
      }
      if(info.url!=NULL){
        fprintf(stderr,"Station homepage: %s\n",info.url);
      }
      if(info.bitrate_kbps>=0){
        fprintf(stderr,"Station bitrate: %u kbps\n",
         (unsigned)info.bitrate_kbps);
      }
      if(info.is_public>=0){
        fprintf(stderr,"%s\n",
         info.is_public?"Station is public.":"Station is private.");
      }
      if(info.server!=NULL){
        fprintf(stderr,"Server software: %s\n",info.server);
      }
      if(info.content_type!=NULL){
        fprintf(stderr,"Content-Type: %s\n",info.content_type);
      }
      is_ssl=info.is_ssl;
      opus_server_info_clear(&info);
    }
  }
  if(of==NULL){
    fprintf(stderr,"Failed to open file '%s': %i\n",_argv[1],ret);
    return EXIT_FAILURE;
  }
  duration=0;
  output_seekable=fseek(stdout,0,SEEK_CUR)!=-1;
  if(op_seekable(of)){
    opus_int64  size;
    fprintf(stderr,"Total number of links: %i\n",op_link_count(of));
    duration=op_pcm_total(of,-1);
    fprintf(stderr,"Total duration: ");
    print_duration(stderr,duration,3);
    fprintf(stderr," (%li samples @ 48 kHz)\n",(long)duration);
    size=op_raw_total(of,-1);
    fprintf(stderr,"Total size: ");
    print_size(stderr,size,0,"");
    fprintf(stderr,"\n");
  }
  else if(!output_seekable){
    fprintf(stderr,"WARNING: Neither input nor output are seekable.\n");
    fprintf(stderr,
     "Writing non-standard WAV header with invalid chunk sizes.\n");
  }
  make_wav_header(wav_header,duration);
  if(!fwrite(wav_header,sizeof(wav_header),1,stdout)){
    fprintf(stderr,"Error writing WAV header: %s\n",strerror(errno));
    ret=EXIT_FAILURE;
  }
  else{
    ogg_int64_t pcm_offset;
    ogg_int64_t pcm_print_offset;
    ogg_int64_t nsamples;
    opus_int32  bitrate;
    int         prev_li;
    prev_li=-1;
    nsamples=0;
    pcm_offset=op_pcm_tell(of);
    if(pcm_offset!=0){
      fprintf(stderr,"Non-zero starting PCM offset: %li\n",(long)pcm_offset);
    }
    pcm_print_offset=pcm_offset-48000;
    bitrate=0;
    for(;;){
      ogg_int64_t   next_pcm_offset;
      opus_int16    pcm[120*48*2];
      unsigned char out[120*48*2*2];
      int           li;
      int           si;
      /*Although we would generally prefer to use the float interface, WAV
         files with signed, 16-bit little-endian samples are far more
         universally supported, so that's what we output.*/
      ret=op_read_stereo(of,pcm,sizeof(pcm)/sizeof(*pcm));
      if(ret==OP_HOLE){
        fprintf(stderr,"\nHole detected! Corrupt file segment?\n");
        continue;
      }
      else if(ret<0){
        fprintf(stderr,"\nError decoding '%s': %i\n",_argv[1],ret);
        if(is_ssl)fprintf(stderr,"Possible truncation attack?\n");
        ret=EXIT_FAILURE;
        break;
      }
      li=op_current_link(of);
      if(li!=prev_li){
        const OpusHead *head;
        const OpusTags *tags;
        int             binary_suffix_len;
        int             ci;
        /*We found a new link.
          Print out some information.*/
        fprintf(stderr,"Decoding link %i:                          \n",li);
        head=op_head(of,li);
        fprintf(stderr,"  Channels: %i\n",head->channel_count);
        if(op_seekable(of)){
          ogg_int64_t duration;
          opus_int64  size;
          duration=op_pcm_total(of,li);
          fprintf(stderr,"  Duration: ");
          print_duration(stderr,duration,3);
          fprintf(stderr," (%li samples @ 48 kHz)\n",(long)duration);
          size=op_raw_total(of,li);
          fprintf(stderr,"  Size: ");
          print_size(stderr,size,0,"");
          fprintf(stderr,"\n");
        }
        if(head->input_sample_rate){
          fprintf(stderr,"  Original sampling rate: %lu Hz\n",
           (unsigned long)head->input_sample_rate);
        }
        tags=op_tags(of,li);
        fprintf(stderr,"  Encoded by: %s\n",tags->vendor);
        for(ci=0;ci<tags->comments;ci++){
          const char *comment;
          comment=tags->user_comments[ci];
          if(opus_tagncompare("METADATA_BLOCK_PICTURE",22,comment)==0){
            OpusPictureTag pic;
            int            err;
            err=opus_picture_tag_parse(&pic,comment);
            fprintf(stderr,"  %.23s",comment);
            if(err>=0){
              fprintf(stderr,"%u|%s|%s|%ux%ux%u",pic.type,pic.mime_type,
               pic.description,pic.width,pic.height,pic.depth);
              if(pic.colors!=0)fprintf(stderr,"/%u",pic.colors);
              if(pic.format==OP_PIC_FORMAT_URL){
                fprintf(stderr,"|%s\n",pic.data);
              }
              else{
                fprintf(stderr,"|<%u bytes of image data>\n",pic.data_length);
              }
              opus_picture_tag_clear(&pic);
            }
            else fprintf(stderr,"<error parsing picture tag>\n");
          }
          else fprintf(stderr,"  %s\n",tags->user_comments[ci]);
        }
        if(opus_tags_get_binary_suffix(tags,&binary_suffix_len)!=NULL){
          fprintf(stderr,"<%u bytes of unknown binary metadata>\n",
           binary_suffix_len);
        }
        fprintf(stderr,"\n");
        if(!op_seekable(of)){
          pcm_offset=op_pcm_tell(of)-ret;
          if(pcm_offset!=0){
            fprintf(stderr,"Non-zero starting PCM offset in link %i: %li\n",
             li,(long)pcm_offset);
          }
        }
      }
      if(li!=prev_li||pcm_offset>=pcm_print_offset+48000){
        opus_int32 next_bitrate;
        opus_int64 raw_offset;
        next_bitrate=op_bitrate_instant(of);
        if(next_bitrate>=0)bitrate=next_bitrate;
        raw_offset=op_raw_tell(of);
        fprintf(stderr,"\r ");
        print_size(stderr,raw_offset,0,"");
        fprintf(stderr,"  ");
        print_duration(stderr,pcm_offset,0);
        fprintf(stderr,"  (");
        print_size(stderr,bitrate,1," ");
        fprintf(stderr,"bps)                    \r");
        pcm_print_offset=pcm_offset;
        fflush(stderr);
      }
      next_pcm_offset=op_pcm_tell(of);
      if(pcm_offset+ret!=next_pcm_offset){
        fprintf(stderr,"\nPCM offset gap! %li+%i!=%li\n",
         (long)pcm_offset,ret,(long)next_pcm_offset);
      }
      pcm_offset=next_pcm_offset;
      if(ret<=0){
        ret=EXIT_SUCCESS;
        break;
      }
      /*Ensure the data is little-endian before writing it out.*/
      for(si=0;si<2*ret;si++){
        out[2*si+0]=(unsigned char)(pcm[si]&0xFF);
        out[2*si+1]=(unsigned char)(pcm[si]>>8&0xFF);
      }
      /*
      if(!fwrite(out,sizeof(*out)*4*ret,1,stdout)){
        fprintf(stderr,"\nError writing decoded audio data: %s\n",
         strerror(errno));
        ret=EXIT_FAILURE;
        break;
      }
      */
      nsamples+=ret;
      prev_li=li;
    }
    if(ret==EXIT_SUCCESS){
      fprintf(stderr,"\nDone: played ");
      print_duration(stderr,nsamples,3);
      fprintf(stderr," (%li samples @ 48 kHz).\n",(long)nsamples);
    }
    if(op_seekable(of)&&nsamples!=duration){
      fprintf(stderr,"\nWARNING: "
       "Number of output samples does not match declared file duration.\n");
      if(!output_seekable)fprintf(stderr,"Output WAV file will be corrupt.\n");
    }
    if(output_seekable&&nsamples!=duration){
      make_wav_header(wav_header,nsamples);
      if(fseek(stdout,0,SEEK_SET)||
       !fwrite(wav_header,sizeof(wav_header),1,stdout)){
        fprintf(stderr,"Error rewriting WAV header: %s\n",strerror(errno));
        ret=EXIT_FAILURE;
      }
    }
  }
  op_free(of);
  return ret;
}
