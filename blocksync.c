
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <zlib.h>

#ifdef OPENSOLARIS
#include <md5.h>
#define MHASH MD5_CTX
#endif

#ifdef LINUX
#include <mhash.h>
#define O_LARGEFILE 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define debug(...) fprintf (stderr, __VA_ARGS__)

#define BLOCKSIZE 4096
#define LOOKUP_TABLE_SIGBITS 20
#define HASH_SIZE 8  // was: 16
#define SUBTABLE_ENTRIES 340  // results in ~4kB subtable size
#define HASH_REMAINDER_SIZE (HASH_SIZE - (LOOKUP_TABLE_SIGBITS/8))
#define PACKED __attribute__ ((packed));
#define TABLE_SIZE (1 << LOOKUP_TABLE_SIGBITS)

#define SUBTABLES_PER_MEMORY_BLOCK (1048500 / sizeof(struct SUBTABLE))
#define MEMORY_BLOCK_SIZE (SUBTABLES_PER_MEMORY_BLOCK * sizeof(struct SUBTABLE))

#define uint8 unsigned char
#define uint16 unsigned short 
#define uint32 unsigned int
#define uint64 unsigned long long 
#define uint128 __uint128_t

#define BLOCKSYNC_MSG_HELLO	0x01
#define BLOCKSYNC_MSG_REFBLOCK	0x02
#define BLOCKSYNC_MSG_REFRANGE	0x03 //todo
#define BLOCKSYNC_MSG_FILEOPEN	0x04
#define BLOCKSYNC_MSG_FULLBLOCK	0x05
#define BLOCKSYNC_MSG_PARTBLOCK	0x06
#define BLOCKSYNC_MSG_ZEROBLOCK	0x07
#define BLOCKSYNC_MSG_BLOCKDIFF 0x08
#define BLOCKSYNC_MSG_FILESHUT	0x09
#define BLOCKSYNC_MSG_FILENAME	0x0A
#define BLOCKSYNC_MSG_GOODBYE	0x0B
#define BLOCKSYNC_MSG_DELFILE	0x0C
#define BLOCKSYNC_MESSAGES	0x0D

static char *message_types[] = {
  "Unknown", "Hello", "RefBlock", "RefRange", "FileOpen", "FullBlock", "PartBlock", "ZeroBlock", "BlockDiff",
  "FileShut", "FileName", "GoodBye", "DelFile", NULL };

/* TODO ideas
 - once a new dstfile is processed, add it to the srclist
*/

/* stuff for lzma */
void *MyAlloc(size_t x) { return malloc(x); }
void MyFree(void *x) { free(x); }

struct FILERANGE {
  uint16 file_id;
  uint32 block_index;
} PACKED;

struct SUBTABLE_ENTRY {
  struct FILERANGE range;
  uint8  hash_remainder[HASH_REMAINDER_SIZE];
} PACKED;

struct SUBTABLE {
  struct SUBTABLE_ENTRY entries[SUBTABLE_ENTRIES];
  struct SUBTABLE	*next;
  uint16		num_entries;
} PACKED;

struct BLOCKSYNC_FILE {
  uint8 *path;
  time_t mtime;
  off_t size_bytes;
};

#define MAX_FILES (1 << (sizeof(uint16) * 8) - 1)
struct BLOCKSYNC_FILELIST {
  struct BLOCKSYNC_FILE files[MAX_FILES];
  uint8 *prepath;
  uint16 num_files;
};

static struct {
  uint64	num_entries;
  uint32	longest_chain;
  uint32 	touched_keys;
  uint32	total_subtables;
  void		*current_memory_block;
  int		current_block_allocated;
  struct BLOCKSYNC_FILELIST
                srclist, dstlist;
  uint64 	hash_cmps, hash_matches, block_cmps, block_matches;
  MHASH		current_md5calc;
  uint64 	msg_counts[BLOCKSYNC_MESSAGES];
  uint64 	msg_bytes[BLOCKSYNC_MESSAGES];
} data;

struct SUBTABLE **table;

static void *current_memory_block;
static int current_block_allocated;

void dump_msg_counters(void)
{
  int i;
  debug("COUNTS: ");
  for(i=0; i<BLOCKSYNC_MESSAGES; i++) {
    debug("%s:%lluK/%llu ", message_types[i], data.msg_bytes[i]>>10, data.msg_counts[i]);
  }
  debug("\n");
}

uint8 *md5_to_str(uint128 *md5sum)
{
  static uint8 buf[33], *p, i;
  p = (uint8 *)md5sum;
  for(i=0; i < 16; i++)
    snprintf(buf+(i<<1), 3, "%02X", p[i]);
  return(buf);
}

void fail(const char *errmsg) 
{
  perror(errmsg);
  exit(1);
}

char *get_full_path(struct BLOCKSYNC_FILELIST *list, uint16 file_id)
{
  static char newpath[PATH_MAX], *p1, *p2;
  p1 = list->prepath;
  p2 = list->files[file_id].path;
  if((strlen(p1) + strlen(p2) + 2) >= PATH_MAX) {
    fprintf(stderr, "%s/%s: ", p1, p2);
    fail("Path too long");
  }
  snprintf(newpath, PATH_MAX, "%s%s%s", p1, p1[0] ? "/" : "", p2);  
  return(newpath);
}

void emit_output(uint8 *buf, size_t len, uint8 *extrabuf, size_t extralen)
{
  if(len > 0) {
    //debug("EMIT %s (%lu)\n", message_types[buf[0] < BLOCKSYNC_MESSAGES ? buf[0] : 0], len + extralen);
    data.msg_counts[buf[0] < BLOCKSYNC_MESSAGES ? buf[0] : 0]++;
    data.msg_bytes[buf[0] < BLOCKSYNC_MESSAGES ? buf[0] : 0] += len + extralen;
    if(len!=write(STDOUT_FILENO, buf, len))
      fail("output_stream");
  }
  if(extralen > 0) {
    if(extralen!=write(STDOUT_FILENO, extrabuf, extralen))
      fail("output_stream");
  }
}

#define BLOCKSYNC_MAGIC_NUMBER 0x00FF127A914F8CB0uLL
struct MSG_HELLO {
  uint8 msg_type;
  uint64 magic_number;
  uint32 block_size_bytes;
} PACKED;

void msg_hello(void)
{
  struct MSG_HELLO *buf = malloc(sizeof(struct MSG_HELLO));
  buf->msg_type = BLOCKSYNC_MSG_HELLO;
  buf->magic_number = BLOCKSYNC_MAGIC_NUMBER;
  buf->block_size_bytes = BLOCKSIZE;
  emit_output((void *)buf, sizeof(*buf), NULL, 0);
}

void msg_goodbye(void)
{
  struct MSG_HELLO *buf = malloc(sizeof(struct MSG_HELLO));
  buf->msg_type = BLOCKSYNC_MSG_GOODBYE;
  buf->magic_number = BLOCKSYNC_MAGIC_NUMBER;
  emit_output((void *)buf, sizeof(*buf), NULL, 0);
}


struct MSG_REFBLOCK {
  uint8 msg_type;
  struct FILERANGE range;
  uint32 dst_block;
} PACKED;


void msg_refblock(struct FILERANGE *source, uint32 dst_block)
{
  struct MSG_REFBLOCK *buf = malloc(sizeof(struct MSG_REFBLOCK));
  buf->msg_type = BLOCKSYNC_MSG_REFBLOCK;
  memcpy(&buf->range, source, sizeof(*source));
  buf->dst_block = dst_block;
  emit_output((void *)buf, sizeof(*buf), NULL, 0);
}

struct MSG_FILENAME {
  uint8 msg_type;
  uint16 len;
} PACKED;

void msg_filename(uint8 *filename)
{
  struct MSG_FILENAME *buf = malloc(sizeof(struct MSG_FILENAME));
  buf->msg_type = BLOCKSYNC_MSG_FILENAME;
  buf->len = strlen(filename) + 1;
  emit_output((void *)buf, sizeof(*buf), (void *)filename, buf->len);
}

struct MSG_DELFILE {
  uint8 msg_type;
  uint16 len;
} PACKED;

void msg_delfile(uint8 *filename)
{
  struct MSG_DELFILE *buf = malloc(sizeof(struct MSG_DELFILE));
  buf->msg_type = BLOCKSYNC_MSG_DELFILE;
  buf->len = strlen(filename) + 1;
  emit_output((void *)buf, sizeof(*buf), (void *)filename, buf->len);
}


struct MSG_FILESHUT {
  uint8 msg_type;
  time_t mtime;
  uint128 md5sum;
} PACKED;

void msg_fileshut(time_t mtime, uint128 md5sum)
{
  struct MSG_FILESHUT *buf = malloc(sizeof(struct MSG_FILESHUT));
  buf->msg_type = BLOCKSYNC_MSG_FILESHUT;
  buf->mtime = mtime;
  buf->md5sum = md5sum;
  emit_output((void *)buf, sizeof(*buf), NULL, 0);
}

struct MSG_FILEOPEN {
  uint8 msg_type;
  uint16 file_id;
  off_t filesize;
} PACKED;

void msg_fileopen(uint16 file_id, off_t filesize)
{
  struct MSG_FILEOPEN *buf = malloc(sizeof(struct MSG_FILEOPEN));
  buf->msg_type = BLOCKSYNC_MSG_FILEOPEN;
  buf->file_id = file_id;
  buf->filesize = filesize;
  emit_output((void *)buf, sizeof(*buf), NULL, 0);
}

struct MSG_FULLBLOCK {
  uint8 msg_type;
  uint32 block_number;
} PACKED;

void msg_fullblock(uint32 block_number, uint8 *datablock)
{
  struct MSG_FULLBLOCK *buf = malloc(sizeof(struct MSG_FULLBLOCK));
  buf->msg_type = BLOCKSYNC_MSG_FULLBLOCK;
  buf->block_number = block_number;
  emit_output((void *)buf, sizeof(*buf), (void *)datablock, BLOCKSIZE);
}

struct MSG_BLOCKDIFF {
  uint8 msg_type;
  uint32 dst_block;
  uint16 len;
  struct FILERANGE src_range;
} PACKED;

void msg_blockdiff(uint32 dst_block, struct FILERANGE *src_range, uint8 *srcblock, uint8 *datablock)
{
  uint8 patch[BLOCKSIZE];
  struct MSG_BLOCKDIFF *buf = malloc(sizeof(struct MSG_BLOCKDIFF));
  buf->msg_type = BLOCKSYNC_MSG_BLOCKDIFF;
  buf->dst_block = dst_block;
  memcpy(&buf->src_range, src_range, sizeof(*src_range));
  
  if(!(buf->len = (uint16) bsdiff(srcblock, BLOCKSIZE, datablock, BLOCKSIZE, patch, BLOCKSIZE))) {
    msg_fullblock(dst_block, datablock);
    //fprintf(stderr, "Warning: bsdiff patch generation failed\n");
    return;
  }
  emit_output((void *)buf, sizeof(*buf), (void *)patch, buf->len);
}

// multiple FULLBLOCKs might be collapsed into a single PARTBLOCK
struct MSG_PARTBLOCK {
  uint8 msg_type;
  uint32 block_number;
  uint16 len;		
} PACKED;

void msg_partblock(uint32 block_number, uint8 *datablock, uint16 len)
{
  struct MSG_PARTBLOCK *buf = malloc(sizeof(struct MSG_PARTBLOCK));
  buf->msg_type = BLOCKSYNC_MSG_PARTBLOCK;
  buf->block_number = block_number;
  buf->len = len;
  emit_output((void *)buf, sizeof(*buf), (void *)datablock, len);
}

struct MSG_ZEROBLOCK {
  uint8 msg_type;
  uint32 block_number;
} PACKED;

void msg_zeroblock(uint32 block_number)
{
  struct MSG_ZEROBLOCK *buf = malloc(sizeof(struct MSG_ZEROBLOCK));
  buf->msg_type = BLOCKSYNC_MSG_ZEROBLOCK;
  buf->block_number = block_number;
  emit_output((void *)buf, sizeof(*buf), NULL, 0);
}


#ifdef LINUX
void md5_calc(void *output, void *input, size_t length) 
{
  MHASH hsh;
  hsh = mhash_init(MHASH_MD5);
  mhash(hsh, input, length);
  mhash_deinit(hsh, output);
}

void md5_file_begin(void)
{
  data.current_md5calc = mhash_init(MHASH_MD5);
}

void md5_file_add(void *buf, size_t len)
{
  mhash(data.current_md5calc, buf, len);
}

uint128 md5_file_end(void)
{
  uint128 retval;
  mhash_deinit(data.current_md5calc, (void *)&retval);
  debug("md5_file_end: hash=%s\n", md5_to_str(&retval));
  return(retval);
}
#endif

#ifdef OPENSOLARIS
void md5_file_begin(void)
{
  MD5Init(&data.current_md5calc);
}

void md5_file_add(void *buf, size_t len)
{
  MD5Update(&data.current_md5calc, buf, len);
}

uint128 md5_file_end(void)
{
  uint128 retval;
  MD5Final((uint8 *) &retval, &data.current_md5calc);
  debug("md5_file_end: hash=%s\n", md5_to_str(&retval));
  return(retval);
}

#endif

void hexdump(uint8 *str, uint8 *buf, int len)
{
  int i = 0;
  debug("Hexdump: %s (%d bytes)\n [0000] ", str, len);
  while(i < len) {
    debug("%02X", buf[i++]);
    if(i >= len)
      break;
    if((i % 16) == 0)
      debug(" ");
    if((i % 64) == 0)
      debug("\n [%04d] ", i);
  }
  debug("\n");
}


void read_block(void *buf, struct FILERANGE *range)
{
  int fd;
  char *path;
  path = get_full_path(&data.srclist, range->file_id);
  if((fd = open(path, O_RDONLY|O_LARGEFILE))<0)
    fail(path);
  if(BLOCKSIZE != pread(fd, buf, BLOCKSIZE, (off_t)range->block_index * BLOCKSIZE))
    fail(data.srclist.files[range->file_id].path);
  close(fd);
}

struct SUBTABLE *allocate_new_subtable(void)
{
  struct SUBTABLE *retval;
  if(!data.current_memory_block || data.current_block_allocated == SUBTABLES_PER_MEMORY_BLOCK) { 
    if(!(data.current_memory_block = malloc(MEMORY_BLOCK_SIZE)))
      abort();
    memset(data.current_memory_block, 0, MEMORY_BLOCK_SIZE);
    data.current_block_allocated = 0;
  }
  
  retval = (struct SUBTABLE *) (data.current_memory_block + (data.current_block_allocated++ * sizeof(struct SUBTABLE)));
  retval->num_entries = 0;
  retval->next = NULL;
  data.total_subtables++;
  return retval;
}




void md5_to_key_and_remainder(uint128 *md5hash, uint32 *key, uint8 *hash_remainder) 
{
  uint8 i;
  // Extract the key and remainder components of the hash
  *key = *md5hash & (TABLE_SIZE - 1);
  for(i = 0; i < HASH_REMAINDER_SIZE; i++) {
    hash_remainder[i] = (*md5hash >> (i << 3)) & 0xFF;
  }
}

uint16 find_in_subtable(struct SUBTABLE *subtable, uint8 *hash_remainder)
{
  uint16 i;
  for(i=0; i < subtable->num_entries; i++) {
    data.hash_cmps++;
    if(0==memcmp(hash_remainder, subtable->entries[i].hash_remainder, HASH_REMAINDER_SIZE)) {
      data.hash_matches++;
      break;
    }
  }
  return(i);
}

struct FILERANGE *find_in_table(uint8 *datablock) 
{
  uint128 md5hash;
  uint32 key;
  uint16 i=0;
  uint8 buf[BLOCKSIZE], hash_remainder[HASH_REMAINDER_SIZE];
  struct SUBTABLE *subtable;   
  struct FILERANGE *retval = NULL;

  md5_calc((uint8 *)&md5hash, datablock, BLOCKSIZE);
  md5_to_key_and_remainder(&md5hash, &key, hash_remainder);
//  debug("find_in_table: key=%u hash=%s\n", key, md5_to_str(&md5hash));
  
  subtable = table[key];
  do {
    if(!subtable)
      break;
    if((i = find_in_subtable(subtable, hash_remainder)) < subtable->num_entries) {
      data.block_cmps++;
      read_block((void *)buf, &subtable->entries[i].range);
      if(0==memcmp(buf, datablock, BLOCKSIZE)) {
        data.block_matches++;
        retval = &subtable->entries[i].range;
        break;
      }
    }
  } while(!retval && i == subtable->num_entries && (subtable = subtable->next));
  
  return(retval);
}

void add_to_table(uint8 *datablock, uint16 file_id, uint32 block_index)
{
  uint128 md5hash;
  uint32 key;
  uint16 i, chain_length=0;
  uint8 buf[BLOCKSIZE], hash_remainder[HASH_REMAINDER_SIZE];
  int cmpres;
  struct SUBTABLE *subtable;
  struct SUBTABLE_ENTRY *entry;
  
  md5_calc((uint8 *)&md5hash, datablock, BLOCKSIZE);
  md5_to_key_and_remainder(&md5hash, &key, hash_remainder);
  //debug("[%u/%u] key=%u hash=%08llX%08llX\n", file_id, block_index, key, (uint64) md5hash, (uint64) (md5hash >> 64));
  
  // Allocate a table if one is not there
  if(!table[key]) {
    table[key] = allocate_new_subtable();
    data.touched_keys++;
  }

  subtable = table[key];
  
  // Search for a match in the subtable, follow the linked list of subtables until a match is found or no more subtables
  do {
    chain_length++;
    for(i=0; i < subtable->num_entries; i++) {
      //debug("Comparing hashes... file_id=%u,%u block_index=%lu,%lu\n", file_id, subtable->entries[i].file_id, block_index, subtable->entries[i].block_index);

      data.hash_cmps++;
      cmpres = memcmp(hash_remainder, subtable->entries[i].hash_remainder, HASH_REMAINDER_SIZE);
      if(cmpres == 0) {
        data.hash_matches++;
        read_block((void *)buf, &subtable->entries[i].range);
        data.block_cmps++;
        if(0==memcmp(buf, datablock, BLOCKSIZE)) {
          //debug("Identical block! file_id=%u,%u block_index=%lu,%lu\n",
          //  file_id, subtable->entries[i].file_id,
          //  block_index, subtable->entries[i].block_index);
          data.block_matches++;
          return;
        }
        /*else {
          todo: Count this
          debug("Hash match but not identical... file_id=%u,%u block_index=%lu,%lu\n", file_id, subtable->entries[i].file_id, block_index, subtable->entries[i].block_index);
          if(file_id == 1 && subtable->entries[i].file_id == 0 && block_index == subtable->entries[i].block_index) {
            hexdump(data.files[file_id], datablock, BLOCKSIZE);
            hexdump(data.files[subtable->entries[i].file_id], buf, BLOCKSIZE);
            usleep(10000000);
          }
        }*/
      }
      else if(cmpres >= 0) {
        break;
      }
    }
  } while(i == subtable->num_entries && subtable->next && (subtable = subtable->next));
  
  // if subtable is full, allocate a new one
  if(subtable->num_entries == SUBTABLE_ENTRIES) {
    subtable->next = allocate_new_subtable();
    subtable = subtable->next;
    i = 0;
    chain_length++;
  }
  
  memmove(&subtable->entries[i+1], &subtable->entries[i], (subtable->num_entries - i) * sizeof(struct SUBTABLE_ENTRY));
  entry = &subtable->entries[i];
  entry->range.file_id = file_id;
  entry->range.block_index = block_index;
  memcpy(entry->hash_remainder, hash_remainder, HASH_REMAINDER_SIZE);
  
  subtable->num_entries++;
  data.num_entries++;
  if(data.longest_chain < chain_length)
    data.longest_chain = chain_length;
    
  
  
//  debug("hash: %08X%08X\n", *((uint64 *) md5hash),*((uint64 *) md5hash+8) );
  //debug("hash: %08llX%08llX (%d)\n", md5hash[0], md5hash[1], sizeof(md5hash));
  ///  debug("hash: %08llX%08llX (%d)\n", (uint64) md5hash, (uint64) (md5hash >> 64), key);
}

void show_table_stats(void)
{
  struct SUBTABLE *subtable;
  uint16 i, smallest_subtable=65535, biggest_subtable=0;
  uint32 key;
  uint64 total_records=0, num_subtables=0;
  
  for(key=0; key<TABLE_SIZE; key++) {
    subtable = table[key];
    while(subtable) {
      num_subtables++;
      total_records += subtable->num_entries;
      if(subtable->num_entries < smallest_subtable)
        smallest_subtable = subtable->num_entries;
      if(subtable->num_entries > biggest_subtable)
        biggest_subtable = subtable->num_entries;
      subtable = subtable->next;
    }
  }
  debug("Table Stats: total_records=%llu, num_subtables=%llu, smallest_subtable=%u, biggest_subtable=%u\n",
    total_records, num_subtables, smallest_subtable, biggest_subtable);
}

int block_is_nonzero(void *datablock)
{
  uint64 *p, *ep;
  int i=0;
  p = (uint64 *) datablock;
  ep = (uint64 *) (datablock + BLOCKSIZE);
  while(p != ep && *p == (uint64) 0uLL)
    p++;
  return(p != ep);
}

void recurse_subdir(struct BLOCKSYNC_FILELIST *filelist, const char *path)
{
  DIR *dir;
  struct dirent *dirent;
  struct stat statbuf;
  uint8 newpath[PATH_MAX];

  if(path[0]) {
    debug("recurse_subdir: Opening %s\n", path);
    dir = opendir(path);

  }
  else {
    dir = opendir(".");
  }
  if(!dir)
    fail("opendir");
      rewinddir(dir);
  while(dirent = readdir(dir)) {
    //debug("DEBUG direntry: '%s'\n", dirent->d_name);
    if((strlen(path) + strlen(dirent->d_name) + 2) >= PATH_MAX) {
      debug("Skipping file: Path too long: %s/%s\n", path, dirent->d_name);
      continue;
    }
    if(dirent->d_name[0] == '.') // skip hidden files and directories
      continue;
      
    snprintf(newpath, PATH_MAX, "%s%s%s", path, path[0] ? "/" : "", dirent->d_name);
    //debug("DEBUG stat: '%s'\n", newpath);
    if(stat(newpath, &statbuf))
      fail("stat");
    
    if(S_ISREG(statbuf.st_mode)) { // is a file, so add it to the file list
      if(filelist->num_files >= MAX_FILES) {
        debug("Warning: Reached limit of number of files (%u)\n", MAX_FILES);
        return;
      }
      filelist->files[filelist->num_files].path = strdup(newpath);
      filelist->files[filelist->num_files].mtime = statbuf.st_mtime;
      filelist->files[filelist->num_files].size_bytes = statbuf.st_size;
      filelist->num_files++;
      debug("recurse_subdir: Adding file: %s (%lu bytes)\n", newpath, statbuf.st_size);
    }
    else if(S_ISDIR(statbuf.st_mode)) {
      recurse_subdir(filelist, newpath);
    }
  }
  if(errno) 
    fail("readdir");
  closedir(dir);
  debug("Closing dir\n");
}

void recurse_subdir_with_wd(struct BLOCKSYNC_FILELIST *filelist)
{
  char cwd[PATH_MAX];
  if(!getcwd(cwd, PATH_MAX)) 
    fail("getcwd");
  if(0!=chdir(filelist->prepath)) 
    fail("chdir");
  recurse_subdir(filelist, "");
  if(0!=chdir(cwd)) 
    fail("chdir");
}

uint16 find_srclist_file(uint8 *filename)
{
  uint16 i=0;
  while(i < data.srclist.num_files) {
    if(strlen(filename)==strlen(data.srclist.files[i].path) && (0==strcmp(filename, data.srclist.files[i].path)))
      break;
    i++;
  }
  return(i < data.srclist.num_files ? i : MAX_FILES);
}

uint16 add_srclist_file(uint16 dst_file_id)
{
  if(data.srclist.num_files >= MAX_FILES) {
    fprintf(stderr, "Error: reached limit of number of files (%u)\n", MAX_FILES);
    exit(1);
  }

  memcpy(&data.srclist.files[data.srclist.num_files],
    &data.dstlist.files[dst_file_id],
    sizeof(struct BLOCKSYNC_FILE));
  
  return(data.srclist.num_files++);
}

main(int argc, char *argv[])
{
  uint8 buf[BLOCKSIZE], srcbuf[BLOCKSIZE], cwd[PATH_MAX];
  uint64 *p, *ep;
  uint32 blocknum, src_blocks, src_blocknum;
  uint16 file_id=0, src_file_id=0, dst_src_list_id=0;
  int fd, bytes_read, have_source, dest_is_zero;
  struct FILERANGE range, *matched_range;
  char *path;

  
  table = (void *)calloc(TABLE_SIZE, sizeof(struct SUBTABLE *));
  
  debug("%lu, %lu, %u, %lu, %lu\n", sizeof(uint16), sizeof(uint32), HASH_REMAINDER_SIZE, sizeof(struct SUBTABLE_ENTRY), sizeof(struct SUBTABLE));

  if(argc < 3) {
    fail("Usage: blocksync <common dir> <target dir>");
  }

  if(!getcwd(cwd, PATH_MAX)) 
    fail("getcwd");

  debug("Reading source dir '%s'\n", argv[1]);
  data.srclist.prepath = strdup(argv[1]);
  recurse_subdir_with_wd(&data.srclist);

  /*while(gets(fn) && data.num_files < 65535) {
    data.files[data.num_files++].path = strdup(fn);
  }*/

  for(file_id=0; file_id < data.srclist.num_files; file_id++) {
    path = get_full_path(&data.srclist, file_id);
    msg_filename(data.srclist.files[file_id].path);
    if((fd = open(path, O_RDONLY|O_LARGEFILE))<0) {
      perror(path);
      continue;
    }
    blocknum = 0;
        
    while((bytes_read=read(fd, buf, BLOCKSIZE))>0) {
      if(bytes_read < BLOCKSIZE)
        break;

      if(block_is_nonzero(buf))
        add_to_table(buf, file_id, blocknum);

      if((blocknum % 16384)==0) {
        debug("\rFile: %s (%u/%lu MB) ", data.srclist.files[file_id].path, blocknum >> 8, data.srclist.files[file_id].size_bytes >> 20);
      }
      
      blocknum++;
    }
    close(fd);
    debug("DATA: num_entries=%llu, longest_chain=%u, touched_keys=%u, total_subtables=%u\n",
      data.num_entries, data.longest_chain, data.touched_keys, data.total_subtables);
    show_table_stats();
  }

  debug("DATA: hash_cmps=%llu, hash_matches=%llu, block_cmps=%llu, block_matches=%llu\n",
    data.hash_cmps, data.hash_matches, data.block_cmps, data.block_matches);


  //exit(0);

  debug("Reading target dir '%s'\n", argv[2]);
  data.dstlist.prepath = strdup(argv[2]);
  recurse_subdir_with_wd(&data.dstlist);

  for(file_id=0; file_id < data.dstlist.num_files; file_id++) {
    path = get_full_path(&data.dstlist, file_id);
    debug("Processing target file: %s\n", path);
    if((fd = open(path, O_RDONLY|O_LARGEFILE))<0) {
      perror(path);
      continue;
    }
    
    md5_file_begin();
    blocknum = 0;
    
    // TODO: find the file_id of the same filename in the source list. skip identical check if it doesnt exist.
    if(MAX_FILES != (src_file_id=find_srclist_file(data.dstlist.files[file_id].path))) {
      have_source = 1;
      src_blocks = data.srclist.files[src_file_id].size_bytes/BLOCKSIZE;
      debug("Found a source file: %s\n", data.srclist.files[src_file_id].path);

      
    }
    else {
      have_source = 0;
      debug("No source file for %s\n", data.dstlist.files[file_id].path);
      
      src_file_id = add_srclist_file(file_id);
      msg_filename(data.srclist.files[src_file_id].path);
    }
    
    msg_fileopen(src_file_id, data.dstlist.files[file_id].size_bytes);
    debug("[%u/%u]: dest_is_zero=%d, have_source=%d, src_file_id=%u, src_blocks=%u\n",
      file_id, blocknum, dest_is_zero, have_source, src_file_id, src_blocks);
    usleep(1000000);    

    while((bytes_read=read(fd, buf, BLOCKSIZE))>0) {
      md5_file_add(buf, bytes_read);
      dest_is_zero = !block_is_nonzero(buf);

      if((blocknum % 16384)==0) {
        debug("\rFile: %s (%u/%lu MB) ", data.dstlist.files[file_id].path, blocknum >> 8, data.dstlist.files[file_id].size_bytes >> 20);
      }
      

      
      if(bytes_read < BLOCKSIZE) {
        msg_partblock(blocknum, buf, bytes_read);
      }
      else {
        if(have_source && blocknum < src_blocks) {
          range.file_id = src_file_id;
          range.block_index = blocknum;
          read_block((void *)srcbuf, &range);
        }
        else
          have_source = 0;
        
        if(have_source && 0==memcmp(buf, srcbuf, BLOCKSIZE))  // source & dest are identical
//          debug("blocks identical\n", file_id, blocknum);
          ;
        else if(have_source && !block_is_nonzero(srcbuf))  // source is zero but dest is not 
          msg_fullblock(blocknum, buf);
        else if(dest_is_zero)
          msg_zeroblock(blocknum);
        else if(matched_range = find_in_table(buf))
          msg_refblock(matched_range, blocknum);
        else if(have_source) // source exists, and is different to dest, and neither are zero, so send a binary diff.
          msg_blockdiff(blocknum, &range, srcbuf, buf);
        else { // no source or hashmatch exists, send whole block
          //add_to_table(buf, src_file_id, blocknum);  // we have no source file, so add this new block to the table
          msg_fullblock(blocknum, buf);
        }
      }

      blocknum++;

/*      if((totalsize % 1073741824)==0) {
        debug("\rFile: %s (%llu/%llu GB) ", fn, zerosize >> 30, totalsize >> 30);
      }
      */
    }
    msg_fileshut(data.dstlist.files[file_id].mtime, md5_file_end());
    
    close(fd);
    
    dump_msg_counters();
  }

  /* TODO: see if any source files dont exist in dest and send a delete message */

  msg_goodbye();
  if(0!=chdir(cwd)) 
    fail("chdir");
  
  debug("DATA: hash_cmps=%llu, hash_matches=%llu, block_cmps=%llu, block_matches=%llu\n",
    data.hash_cmps, data.hash_matches, data.block_cmps, data.block_matches);
    
  
}



/*
File: /fat/san/management/.zfs/snapshot/201003262000/bsdmigration/bsdmigration-flat.vmdk (1210/1429 GB) 


File: /fat/san/m00/oct_moonbuggymedia_mbmvps/oct_moonbuggymedia_mbmvps_1-flat.vmdk (1339/2196 GB) 
*/
