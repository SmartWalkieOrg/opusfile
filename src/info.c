#include "internal.h"
#include <limits.h>
#include <string.h>

static unsigned op_parse_uint16le(const unsigned char *_data){
  return _data[0]|_data[1]<<8;
}

static int op_parse_int16le(const unsigned char *_data){
  int ret;
  ret=_data[0]|_data[1]<<8;
  return (ret^0x8000)-0x8000;
}

static opus_uint32 op_parse_uint32le(const unsigned char *_data){
  return _data[0]|_data[1]<<8|_data[2]<<16|_data[3]<<24;
}

int opus_head_parse(OpusHead *_head,const unsigned char *_data,size_t _len){
  OpusHead head;
  if(_len<8)return OP_ENOTFORMAT;
  if(memcmp(_data,"OpusHead",8)!=0)return OP_ENOTFORMAT;
  if(_len<9)return OP_EBADHEADER;
  head.version=_data[8];
  if(head.version>15)return OP_EVERSION;
  if(_len<19)return OP_EBADHEADER;
  head.channel_count=_data[9];
  head.pre_skip=op_parse_uint16le(_data+10);
  head.input_sample_rate=op_parse_uint32le(_data+12);
  head.output_gain=op_parse_int16le(_data+16);
  head.mapping_family=_data[18];
  if(head.mapping_family==0){
    if(head.channel_count<1||head.channel_count>2)return OP_EBADHEADER;
    if(head.version<=1&&_len>19)return OP_EBADHEADER;
    head.stream_count=1;
    head.coupled_count=head.channel_count-1;
    if(_head!=NULL){
      _head->mapping[0]=0;
      _head->mapping[1]=1;
    }
  }
  else if(head.mapping_family==1){
    size_t size;
    int    ci;
    if(head.channel_count<1||head.channel_count>8)return OP_EBADHEADER;
    size=21+head.channel_count;
    if(_len<size||head.version<=1&&_len>size)return OP_EBADHEADER;
    head.stream_count=_data[19];
    if(head.stream_count<1)return OP_EBADHEADER;
    head.coupled_count=_data[20];
    if(head.coupled_count>head.stream_count)return OP_EBADHEADER;
    for(ci=0;ci<head.channel_count;ci++){
      if(_data[21+ci]>=head.stream_count+head.coupled_count
       &&_data[21+ci]!=255){
        return OP_EBADHEADER;
      }
    }
    if(_head!=NULL)memcpy(_head->mapping,_data+21,head.channel_count);
  }
  /*General purpose players should not attempt to play back content with
     channel mapping family 255.*/
  else if(head.mapping_family==255)return OP_EIMPL;
  /*No other channel mapping families are currently defined.*/
  else return OP_EBADHEADER;
  if(_head!=NULL)memcpy(_head,&head,head.mapping-(unsigned char *)&head);
  return 0;
}

void opus_tags_init(OpusTags *_tags){
  memset(_tags,0,sizeof(*_tags));
}

void opus_tags_clear(OpusTags *_tags){
  int i;
  for(i=_tags->comments;i-->0;)_ogg_free(_tags->user_comments[i]);
  _ogg_free(_tags->user_comments);
  _ogg_free(_tags->comment_lengths);
  _ogg_free(_tags->vendor);
}

/*The actual implementation of opus_tags_parse().
  Unlike the public API, this function requires _tags to already be
   initialized, modifies its contents before success is guaranteed, and assumes
   the caller will clear it on error.*/
int opus_tags_parse_impl(OpusTags *_tags,
 const unsigned char *_data,size_t _len){
  opus_uint32 count;
  size_t      size;
  size_t      len;
  int         ncomments;
  int         i;
  len=_len;
  if(len<8)return OP_ENOTFORMAT;
  if(memcmp(_data,"OpusTags",8)!=0)return OP_ENOTFORMAT;
  if(len<16)return OP_EBADHEADER;
  _data+=8;
  len-=8;
  count=op_parse_uint32le(_data);
  _data+=4;
  len-=4;
  if(count>len)return OP_EBADHEADER;
  if(_tags!=NULL){
    char *vendor;
    size=count+1;
    if(size<count)return OP_EFAULT;
    vendor=(char *)_ogg_malloc(size);
    if(vendor==NULL)return OP_EFAULT;
    memcpy(vendor,_data,count);
    vendor[count]='\0';
    _tags->vendor=vendor;
  }
  _data+=count;
  len-=count;
  if(len<4)return OP_EBADHEADER;
  count=op_parse_uint32le(_data);
  _data+=4;
  len-=4;
  /*Check to make sure there's minimally sufficient data left in the packet.*/
  if(count>len>>2)return OP_EBADHEADER;
  /*Check for overflow (the API limits this to an int).*/
  if(count>(opus_uint32)INT_MAX)return OP_EFAULT;
  if(_tags!=NULL){
    size=sizeof(*_tags->comment_lengths)*count;
    if(size/sizeof(*_tags->comment_lengths)!=count)return OP_EFAULT;
    _tags->comment_lengths=(int *)_ogg_malloc(size);
    size=sizeof(*_tags->user_comments)*count;
    if(size/sizeof(*_tags->user_comments)!=count)return OP_EFAULT;
    _tags->user_comments=(char **)_ogg_malloc(size);
    if(_tags->comment_lengths==NULL||_tags->user_comments==NULL){
      return OP_EFAULT;
    }
  }
  ncomments=(int)count;
  for(i=0;i<ncomments;i++){
    /*Check to make sure there's minimally sufficient data left in the packet.*/
    if((size_t)(ncomments-i)>len>>2)return OP_EBADHEADER;
    count=op_parse_uint32le(_data);
    _data+=4;
    len-=4;
    if(count>len)return OP_EBADHEADER;
    /*Check for overflow (the API limits this to an int).*/
    if(count>(opus_uint32)INT_MAX)return OP_EFAULT;
    if(_tags!=NULL){
      _tags->comment_lengths[i]=(int)count;
      size=count+1;
      if(size<count)return OP_EFAULT;
      _tags->user_comments[i]=(char *)_ogg_malloc(size);
      if(_tags->user_comments[i]==NULL)return OP_EFAULT;
      _tags->comments=i+1;
      memcpy(_tags->user_comments[i],_data,count);
      _tags->user_comments[i][count]='\0';
    }
    _data+=count;
    len-=count;
  }
  return 0;
}

int opus_tags_parse(OpusTags *_tags,const unsigned char *_data,size_t _len){
  if(_tags!=NULL){
    OpusTags tags;
    int      ret;
    opus_tags_init(&tags);
    ret=opus_tags_parse_impl(&tags,_data,_len);
    if(ret<0)opus_tags_clear(&tags);
    else *_tags=*&tags;
    return ret;
  }
  else return opus_tags_parse_impl(NULL,_data,_len);
}