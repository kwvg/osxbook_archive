#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#define _GNU_SOURCE 1
#include <string.h>

#include <sys/stat.h> // for mkdir
#include <sys/mman.h> // for mmap

#undef ntohl
#undef ntohs



#define RED     "\033[0;31m"
#define M0      "\e[0;30m"
#define CYAN    "\e[0;36m"
#define M1      "\e[0;31m"
#define GREY    "\e[0;37m"
#define M8      "\e[0;38m"
#define M9      "\e[0;39m"
#define GREEN   "\e[0;32m"
#define YELLOW  "\e[0;33m"
#define BLUE    "\e[0;34m"
#define PINK    "\e[0;35m"
#define NORMAL  "\e[0;0m"

#ifdef LINUX
typedef unsigned long uint64_t;
typedef unsigned short uint16_t;
extern void *memmem (const void *__haystack, size_t __haystacklen,
                     const void *__needle, size_t __needlelen);


#endif
/**
 *  Apple iOS OTA/PBZX expander/unpacker/lister/searcher - by Jonathan Levin,
 *
 *  http://NewOSXBook.com/
 *
 *  Free for anyone (AISE) to use, modify, etc. I won't complain :-), but I'd appreciate a mention
 *
 * Changelog: 02/08/16 - Replaced alloca with malloc () (full OTAs with too many files would have popped stack..)
 *
 *            02/17/16 - Increased tolerance for corrupt OTA - can now seek to entry in a file
 *
 *            08/31/16 - Added search in OTA.
 *
 *            02/28/18 - It's been a while - and ota now does diff!
 *                       Also tidied up and made neater
 *
 *            12/03/18 - Added -S to search for string null terminated
 *
 *            The last OTA: (seriously, I'm done :-)
 *
 *        08/06/19 - Integrated @S1guza's symlink fix (Thanks, man!)
 *                       Added pbzx built-in so you don't have to use pbzx first
 *                       Added multiple file processing, compatible with shell expansion
 *                         Can now ota ...whatever... payload.0?? to iterate over all files!
 *                       Added -H to generate SHA-1 hashes for all ('*') or specific files in OTA
 *             (SHA-1 code taken from public domain, as was lzma)
 *
 *  To compile: now use attached makefile, since there are lzma dependencies
 *          Remember to add '-DLINUX' if on Linux
 *
 *
 */
typedef     unsigned int    uint32_t;
uint64_t pos = 0;


#ifndef NOSHA
#include "sha1.c"
#endif // NOSHA
#pragma pack(1)
struct entry
{

    unsigned int usually_0x210_or_0x110;
    unsigned short  usually_0x00_00; //_00_00;
    unsigned int  fileSize;
    unsigned short whatever;
    unsigned long long timestamp_likely;
    unsigned short _usually_0x20;
    unsigned short nameLen;
    unsigned short uid;
    unsigned short gid;
    unsigned short perms;
    char name[0];
// Followed by file contents
};

#pragma pack()

extern int ntohl(int);
extern short ntohs(short);
uint32_t
swap32(uint32_t arg)
{
    return (ntohl(arg));
}

int g_list = 0;
int g_verbose = 0;
char *g_extract = NULL;
char *g_search = NULL;
char *g_hash = NULL;
int g_nullTerm = 0;



// Since I now diff and use open->mmap(2) on several occasions, refactored
// into its own function
//
void *mmapFile(char *FileName, uint64_t *FileSize)
{
    int fd = open (FileName, O_RDONLY);
    if (fd < 0)
        {
            perror (FileName);
            exit(1);
        }
    // 02/17/2016 - mmap
    struct stat stbuf;
    int rc = fstat(fd, &stbuf);
    char *mmapped =  mmap(NULL, // void *addr,
                          stbuf.st_size,    // size_t len,
                          PROT_READ,        // int prot,
                          MAP_PRIVATE,                //  int flags,
                          fd,               // int fd,
                          0);               // off_t offset);
    if (mmapped == MAP_FAILED)
        {
            perror (FileName);
            exit(1);
        }
    if (FileSize) *FileSize = stbuf.st_size;
    close (fd);
    return (mmapped);
}


void hashFile (char *File, char *Name, uint32_t Size, short Perms, char *HashCriteria)
{
    if (!HashCriteria) return;
    if ((HashCriteria[0] != '*') && ! strstr(Name, HashCriteria)) return ;
#define HASH_SIZE   20
    uint8_t Message_Digest[SHA1HashSize];
    doSHA1((void*)File, Size, Message_Digest);
    int i = 0;
    printf("%s (%d bytes): ", Name, Size);
    for (i = 0; i < HASH_SIZE; i++)
        {
            printf("%02X", Message_Digest[i]);
        }
    printf("\n");
}

void
extractFile (char *File, char *Name, uint32_t Size, short Perms, char *ExtractCriteria)
{
    // MAYBE extract file (depending if matches Criteria, or "*").
    // You can modify this to include regexps, case sensitivity, what not.
    // presently, it's just strstr()
    if (!ExtractCriteria) return;
    if ((ExtractCriteria[0] != '*') && ! strstr(Name, ExtractCriteria)) return;
    uint16_t type = Perms & S_IFMT;
    Perms &= ~S_IFMT;
    if(type != S_IFREG && type != S_IFLNK)
        {
            fprintf(stderr, "Unknown file type: %o\n", type);
            // return;
        }
    // Ok. Extract . This is simple - just dump the file contents to its directory.
    // What we need to do here is parse the '/' and mkdir(2), etc.
    char *dirSep = strchr (Name, '/');
    while (dirSep)
        {
            *dirSep = '\0';
            mkdir(Name,0755);
            *dirSep = '/';
            dirSep+=1;
            dirSep = strchr (dirSep, '/');
        }
    if(type == S_IFLNK)
        {
            /* @s1guza's support for symlinks! */
            /* http://newosxbook.com/forum/viewtopic.php?f=3&t=19513 */
            char *target = strndup(File, Size);
            if(g_verbose)
                {
                    fprintf(stderr, "Symlinking %s to %s\n", Name, target);
                }
            symlink(target, Name);
            fchmodat(AT_FDCWD, Name, Perms, AT_SYMLINK_NOFOLLOW);
            free(target);
        }
    else
        {
            // at this point we're out of '/'s
            // go back to the last /, if any
            if (g_verbose)
                {
                    fprintf(stderr, "Dumping %d bytes to %s\n", Size, Name);
                }
            int fd = open (Name, O_WRONLY| O_CREAT);
            fchmod (fd, Perms);
            write (fd, File, Size);
            close (fd);
        }
} //  end extractFile

void showPos()
{
    fprintf(stderr, "POS is %lld\n", pos);
}

struct entry *getNextEnt (char *Mapping, uint64_t Size, uint64_t *Pos)
{
    // Return entry at Mapping[Pos],
    // and advance Pos to point to next one
    int pos = 0;
    struct entry *ent =(struct entry *) (Mapping + *Pos );
    if (*Pos > Size) return (NULL);
    *Pos += sizeof(struct entry);
    uint32_t entsize = swap32(ent->fileSize);
    uint32_t nameLen = ntohs(ent->nameLen);
    // Get Name (immediately after the entry)
    //char *name = malloc (nameLen+1);
    // strncpy(name, Mapping+ *Pos , nameLen);
    //name[nameLen] = '\0';
    //printf("NAME %p IS %s, Size: %d\n", Mapping, name, entsize);
    //free (name);
    *Pos += nameLen;
    *Pos += entsize;
    return (ent);
} // getNextEnt


int doDiff (char *File1, char *File2, int Exists)
{
    // There are two ways to do diff:
    // look at both files as archives, find diffs, then figure out diff'ing entry,
    // or look at file internal entries individually, then compare each of them
    // I chose the latter. This also (to some extent) survives file ordering
    // Note I'm still mmap(2)ing BOTH files. This contributes to speed, but does
    // have the impact of consuming lots o'RAM. That said, this is to be run on a
    // Linux/MacOS, and not on an i-Device, so we should be ok.
    uint64_t file1Size = 0;
    char *file1Mapping = mmapFile(File1, &file1Size);
    uint64_t file2Size = 0;
    char *file2Mapping = mmapFile(File2, &file2Size);
    uint64_t file1pos = 0;
    uint64_t file2pos = 0;
    struct entry *file1ent = getNextEnt (file1Mapping, file1Size, &file1pos);
    struct entry *file2ent  = getNextEnt (file2Mapping,file2Size, &file2pos);
    uint64_t lastFile1pos, lastFile2pos = 0;
    while (file1ent && file2ent)
        {
            lastFile1pos = file1pos;
            lastFile2pos = file2pos;
            file1ent = getNextEnt (file1Mapping, file1Size, &file1pos);
            file2ent = getNextEnt (file2Mapping,file2Size, &file2pos);
            char *ent1Name = file1ent->name;
            char *ent2Name = file2ent->name;
            // Because I'm lazy: skip last entry
            if (file1pos > file1Size - 1000000) break;
            int found = 1;
            char *n1 = strndup(file1ent->name, ntohs(file1ent->nameLen));
            if (strncmp(ent1Name, ent2Name, ntohs(file1ent->nameLen)))
                {
                    // Stupid names aren't NULL terminated (AAPL don't read my comments,
                    // apparently), so we have to copy both names in:
                    // But that's the least of our problems: We don't know if n1 has been removed
                    // from n2, or n2 is a new addition:
                    uint64_t seekpos = file2pos;
                    // seek n1 in file2:
                    found = 0;
                    int i = 0;
                    struct entry *seek2ent;
                    while (1)
                        {
                            seek2ent = getNextEnt (file2Mapping,file2Size, &seekpos);
                            if (!seek2ent)
                                {
                                    break;
                                } // {printf("EOF\n");break;}
                            if (memcmp(seek2ent->name,file1ent->name, ntohs(seek2ent->nameLen)) == 0)
                                {
                                    found++;
                                    break;
                                }
                            else
                                {
                                    /*
                                                            i++;
                                                            if (i < 200) {
                                                            char *n2 = strndup(seek2ent->name, ntohs(seek2ent->nameLen));

                                                            printf("check: %s(%d) != %s(%d) -- %d\n",n2, ntohs(seek2ent->nameLen),n1, strlen(n1),
                                                        memcmp(seek2ent->name,file1ent->name, ntohs(seek2ent->nameLen) ));
                                                            free(n2);

                                                            }
                                    */
                                }
                        } // end while
                    if (!found)
                        {
                            printf("%s: In file1 but not file2\n", n1);
                            // rewind file2pos so we hit the entry again..
                            file2pos = lastFile2pos;
                        }
                    else
                        {
                            // Found it - align (all the rest to this point were not in file1)
                            file2pos = seekpos;
                        }
                } // name mismatch
            if (found)
                {
                    // Identical entries - check for diffs unless we're only doing existence checks
                    // if the sizes diff, obviously:
                    if (!Exists)
                        {
                            if (file1pos - lastFile1pos != file2pos - lastFile2pos)
                                {
                                    fprintf(stdout,"%s (different sizes)\n", n1);
                                }
                            else
                                // if sizes are identical, maybe - but ignore timestamp!
                                if (memcmp (((unsigned char *)file1ent) + sizeof(struct entry),
                                            ((unsigned char *)file2ent) + sizeof(struct entry), file1pos - lastFile1pos - sizeof(struct entry)))
                                    {
                                        fprintf(stdout,"%s\n", n1);
                                    }
                        }
                    free (n1);
                }
        } // end file1pos
    return 0;
}

void processFile(char *fileName);

int
main(int argc,char **argv)
{
    char *filename ="p";
    int i = 0;
    if (argc < 2)
        {
            fprintf (stderr,"Usage: %s [-v] [-l] [...] _filename[s]_ \nWhere: -l: list files in update payload\n"
                     "Where: [...] is one of:\n"
                     "       -e _file: extract file from update payload (use \"*\" for all files)\n"
                     "       -s _string _file: Look for occurences of _string_ in file\n"
                     "       -S _string _file: Look for occurences of _string_, NULL terminated in file\n"
                     "       -H [_file]: get hash digest of specific file (use \"*\" for all files)\n"
                     "       [-n] -d _file1 _file2: Point out differences between OTA _file1 and _file2\n"
                     "                              -n to only diff names\n", argv[0]);
            exit(10);
        }
    int exists = 0;
    for (i = 1;
            (i < argc -1) && (argv[i][0] == '-');
            i++)
        {
            // This is super quick/dirty. You might want to rewrite with getopt, etc..
            if (strcmp(argv[i], "-n") == 0)
                {
                    exists++;
                }
            else if (strcmp (argv[i], "-d") == 0)
                {
                    // make sure we have argv[i+1] and argv[i+2]...
                    if (i != argc - 3)
                        {
                            fprintf(stderr,"-d needs exactly two arguments - two OTA files to compare\n");
                            exit(6);
                        }
                    // that the files exist...
                    if (access (argv[i+1], F_OK))
                        {
                            fprintf(stderr,"%s: not a file\n", argv[i+1]);
                            exit(11);
                        }
                    if (access (argv[i+2], F_OK))
                        {
                            fprintf(stderr,"%s: not a file\n", argv[i+2]);
                            exit(12);
                        }
                    // then do diff
                    return ( doDiff (argv[i+1],argv[i+2], exists));
                }
            else if (strcmp (argv[i], "-l") == 0)
                {
                    g_list++;
                }
            else if (strcmp (argv[i], "-v") == 0)
                {
                    g_verbose++;
                }
#ifndef NOSHA
            else if (strcmp(argv[i], "-H") == 0)
                {
                    if (i == argc -1)
                        {
                            fprintf(stderr, "-H: Option requires an argument (what to extract)\n");
                            exit(5);
                        }
                    g_hash = argv[i+1];
                    i++;
                }
#endif
            else if (strcmp (argv[i], "-e") == 0)
                {
                    if (i == argc -1)
                        {
                            fprintf(stderr, "-e: Option requires an argument (what to extract)\n");
                            exit(5);
                        }
                    g_extract = argv[i+1];
                    i++;
                }
            // Added 08/31/16:
            // and modified 12/01/2018
            else if ((strcmp (argv[i], "-s") == 0) || (strcmp (argv[i], "-S") == 0))
                {
                    if (i == argc - 2)
                        {
                            fprintf(stderr, "%s: Option requires an argument (search string)\n", argv[i]);
                            exit(5);
                        }
                    g_search = argv[i+1];
                    if (argv[i][1] == 'S') g_nullTerm++;
                    i++;
                }
            else
                {
                    fprintf(stderr,"Unknown option: %s\n", argv[i]);
                    return 1;
                }
        }
    // Another little fix if user forgot filename, rather than try to open
    if (argv[argc-1][0] == '-')
        {
            fprintf(stderr,"Must supply filename\n");
            exit(5);
        }
    // Loop over filenames:
    for (; i < argc; i++)
        {
            if (strstr(argv[i],".ecc")) continue;
            processFile(argv[i]);
        }
}

#define PBZX_MAGIC  "pbzx"


char *doPBZX (char *pbzxData, int Size, int *ExtractedSize)
{
#ifndef NO_PBZX
#define OUT_BUFSIZE     16*1024*1024 // Largest chunk I've seen is 8MB. This is double that.
    char *  decompressXZChunk(char *buf, int size, char *Into, int *IntoSize);
    uint64_t length = 0, flags = 0;
    char *returned = malloc(OUT_BUFSIZE);
    int returnedSize = OUT_BUFSIZE;
    int available = returnedSize;
    int pos = strlen(PBZX_MAGIC);
    flags = *((uint64_t *) pbzxData + pos);
    // read (fd, &flags, sizeof (uint64_t));
    pos += sizeof(uint64_t);
    flags = __builtin_bswap64(flags);
    // fprintf(stderr,"Flags: 0x%llx\n", flags);
    int i = 0;
    int off = 0;
    int warn = 0 ;
    int skipChunk = 0;
    int rc = 0;
    // 03/09/2016 - Fixed for single chunks (payload.0##) files, e.g. WatchOS
    //              and for multiple chunks. AAPL changed flags on me..
    //
    // New OTAs use 0x800000 for more chunks, not 0x01000000.
    // 08/06/2019 - dang it. it's not flags - it's uncomp chunk size.
    uint64_t totalSize = 0;
    uint64_t uncompLen = flags;
    while (pos < Size)
        {
            i++;
            //printf("FLAGS: %llx\n", flags);
            // rc= read (fd, &flags, sizeof (uint64_t)); // check retval..
            flags = *((uint64_t *) (pbzxData +pos));
            pos+= sizeof(uint64_t);
            flags = __builtin_bswap64(flags);
            //printf("FLAGS: %llx\n", flags);
            length = *((uint64_t *) (pbzxData +pos));
            //rc = read (fd, &length, sizeof (uint64_t));
            pos+= sizeof(uint64_t);
            length = __builtin_bswap64(length);
            skipChunk = 0; // (i < minChunk);
            if (getenv("JDEBUG") != NULL) fprintf(stderr,"Chunk #%d (uncomp: %lld, comp length: %lld bytes) %s\n",i, flags,length, skipChunk? "(skipped)":"");
            // Let's ignore the fact I'm allocating based on user input, etc..
            //char *buf = malloc (length);
            //int bytes = read (fd, buf, length);
            char *buf = pbzxData + pos;
            pos += length;
// flags = *((uint64_t *) (pbzxData +pos));
#if 0
            // 6/18/2017 - Fix for WatchOS 4.x OTA wherein the chunks are bigger than what can be read in one operation
            int bytes = length;
            int totalBytes = bytes;
            while (totalBytes < length)
                {
                    // could be partial read
                    bytes = read (fd, buf +totalBytes, length -totalBytes);
                    totalBytes +=bytes;
                }
#endif
            // We want the XZ header/footer if it's the payload, but prepare_payload doesn't have that,
            // so just warn.
            if (memcmp(buf, "\xfd""7zXZ", 6))
                {
                    warn++;
                    fprintf (stderr, "Warning: Can't find XZ header. Instead have 0x%x(?).. This is likely not XZ data.\n",
                             (* (uint32_t *) buf ));
                    // Treat as uncompressed
                    // UNCOMMENT THIS to handle uncomp XZ too..
                    // write (1, buf, length);
                }
            else // if we have the header, we had better have a footer, too
                {
                    if (strncmp(buf + length - 2, "YZ", 2))
                        {
                            warn++;
                            fprintf (stderr, "Warning: Can't find XZ footer at 0x%llx (instead have %x). This is bad.\n",
                                     (length -2),
                                     *((unsigned short *) (buf + length - 2)));
                        }
//  if (1 && !skipChunk)
                    {
                        // Uncompress chunk
                        int chunkExpandedSize = available;
                        char *ptrTo = returned + (returnedSize - available);
                        decompressXZChunk(buf, length, returned + (returnedSize - available),&chunkExpandedSize);
                        //  printf("DECOMPRESSING to %p - %p\n", ptrTo , ptrTo + chunkExpandedSize);
                        totalSize += chunkExpandedSize;
                        available -= chunkExpandedSize;
                        if (available < OUT_BUFSIZE)
                            {
                                returnedSize += 10 * OUT_BUFSIZE;
                                available +=  10 * OUT_BUFSIZE;
                                // Can't use realloc!
                                char *new = malloc(returnedSize);
                                if (getenv("JDEBUG") != NULL)printf("REALLOCING from %p to %p ,%x, AVAIL: %x\n", returned,  new, returnedSize, available);
                                if (new)
                                    {
                                        memcpy(new, returned, returnedSize - available);
                                        free(returned);
                                        returned = new;
                                    }
                                else
                                    {
                                        fprintf(stderr,"ERROR!\n");
                                        exit(1);
                                    }
                            }
                    }
                    warn = 0;
                    // free (buf);  // Not freeing anymore, @ryandesign :-)
                }
        }
    //printf("Total size: %d\n", totalSize);
    *ExtractedSize = totalSize;
    if (getenv("JDEBUG") != NULL)
        {
            int f = open ("/tmp/out1", O_WRONLY |O_CREAT);
            write (f, returned, totalSize);
            close(f);
        }
    return (returned);
#else
    fprintf(stderr,"Not compiled with PBZX support!\n");
    return (NULL);
#endif
} // pbzx

void processFile(char *FileName)
{
    int color = (getenv("JCOLOR")!= NULL);
    fprintf(stderr, "%sProcessing %s%s\n", color ? RED: "", FileName, color ? NORMAL :"");
    //unsigned char buf[4096];
    uint64_t fileSize;
    uint64_t mappedSize;
    char *actualMmapped = mmapFile(FileName, &mappedSize);
    fileSize = mappedSize;
    if (actualMmapped == MAP_FAILED)
        {
            perror (FileName);
            return ;
        }
    char *mmapped = actualMmapped;
    char *extracted = NULL;
    // File could be a PBZX :-)
    if (memcmp(mmapped, PBZX_MAGIC, strlen(PBZX_MAGIC)) ==0)
        {
            // DO PBZX first!
            int extractedSize = 0;
            extracted = doPBZX (mmapped, mappedSize, &extractedSize);
            mmapped = extracted;
            fileSize = extractedSize;
            //  printf("EXTRACTED: %p, size: 0x%llx\n",mmapped, fileSize);
        }
    int i = 0;
    struct entry *ent = alloca (sizeof(struct entry));
    pos = 0;
    while(pos + 3*sizeof(struct entry) < fileSize)
        {
            ent = (struct entry *) (mmapped + pos );
            pos += sizeof(struct entry);
            if ((ent->usually_0x210_or_0x110 != 0x210 && ent->usually_0x210_or_0x110 != 0x110 &&
                    ent->usually_0x210_or_0x110 != 0x310) ||
                    ent->usually_0x00_00)
                {
                    fprintf (stderr,"Corrupt entry (0x%x at pos %llu@0x%llx).. skipping\n", ent->usually_0x210_or_0x110,
                             pos, (uint64_t)(mmapped+pos));
                    int skipping = 1;
                    while (skipping)
                        {
                            ent = (struct entry *) (mmapped + pos ) ;
                            while (ent->usually_0x210_or_0x110 != 0x210 && ent->usually_0x210_or_0x110 != 0x110)
                                {
                                    // #@$#$%$# POS ISN'T ALIGNED!
                                    pos ++;
                                    ent = (struct entry *) (mmapped + pos ) ;
                                }
                            // read rest of entry
                            int nl = ntohs(ent->nameLen);
                            if (ent->usually_0x00_00 || !nl)
                                {
                                    //   fprintf(stderr,"False positive.. skipping %d\n",pos);
                                    pos+=1;
                                }
                            else
                                {
                                    skipping =0;
                                    pos += sizeof(struct entry);
                                }
                            if (pos > fileSize) return;
                        }
                }
            uint32_t    size = swap32(ent->fileSize);
// fprintf(stdout," Here - ENT at pos %d: %x and 0 marker is %x namelen: %d, fileSize: %d\n", pos, ent->usually_0x210_or_0x110, ent->usually_0x00_00, ntohs(ent->nameLen), size);
            uint32_t    nameLen = ntohs(ent->nameLen);
            // Get Name (immediately after the entry)
            //
            // 02/08/2016: Fixed this from alloca() - the Apple jumbo OTAs have so many files in them (THANKS GUYS!!)
            // that this would exceed the stack limits (could solve with ulimit -s, or also by using
            // a max buf size and reusing same buf, which would be a lot nicer)
            // Note to AAPL: Life would have been a lot nicer if the name would have been NULL terminated..
            // What's another byte per every file in a huge file such as this?
            // char *name = (char *) (mmapped+pos);
            char *name = alloca (nameLen+1);
            strncpy(name, mmapped+pos, nameLen);
            name[nameLen] = '\0';
            //printf("NAME IS %s\n", name);
            pos += ntohs(ent->nameLen);
            uint32_t    fileSize = swap32(ent->fileSize);
            uint16_t    perms = ntohs(ent->perms);
            if (g_list)
                {
                    if (g_verbose)
                        {
                            printf ("Entry @0x%d: UID: %d GID: %d Mode: %o Size: %d (0x%x) Namelen: %d Name: ", i,
                                    ntohs(ent->uid), ntohs(ent->gid),
                                    perms, size, size,
                                    ntohs(ent->nameLen));
                        }
                    printf ("%s\n", name);
                }
            // Get size (immediately after the name)
            if (fileSize)
                {
                    if (g_extract)
                        {
                            extractFile(mmapped +pos, name, fileSize, perms, g_extract);
                        }
                    // Added  08/05/19 -  Hash
                    if (g_hash)
                        {
                            hashFile (mmapped +pos, name, fileSize, perms, g_hash);
                        }
                    // Added 08/31/16 - And I swear I should have this from the start.
                    // So darn simple and sooooo useful!
                    if (g_search)
                        {
                            char *found = memmem (mmapped+pos, fileSize, g_search, strlen(g_search) + (g_nullTerm ? 1 : 0));
                            while (found != NULL)
                                {
                                    int relOffset = found - mmapped - pos;
                                    fprintf(stdout, "Found in Entry: %s, relative offset: 0x%x (Absolute: %lx)",
                                            name,
                                            relOffset,
                                            found - mmapped);
                                    // 12/01/18
                                    if (g_verbose)
                                        {
                                            fputc(':', stdout);
                                            fputc(' ', stdout);
                                            char *begin = found;
                                            int i = 0 ;
#define BACK_LIMIT -20
#define FRONT_LIMIT 20
                                            while(begin[i] && i > BACK_LIMIT)
                                                {
                                                    i--;
                                                }
                                            for (; begin +i < found; i++)
                                                {
                                                    if (isprint(begin[i])) putc (begin[i], stdout);
                                                    else putc ('.', stdout);
                                                }
                                            printf("%s%s%s",RED, g_search, NORMAL);
                                            for (i+= strlen(g_search); begin[i] &&( i < FRONT_LIMIT); i++)
                                                {
                                                    if (isprint(begin[i])) putc (begin[i], stdout);
                                                    else putc ('.', stdout);
                                                }
                                        }
                                    fprintf(stdout,"\n");
                                    // keep looking..
                                    found = memmem (found + 1, fileSize - relOffset, g_search, strlen(g_search) +( g_nullTerm ? 1: 0));
                                } // end while
                        } // end g_search
                    pos +=fileSize;
                }
        } // Back to loop
    if (extracted)
        {
            /*printf("FREEing %p\n", extracted);*/ free (extracted);
        }
    munmap(actualMmapped, mappedSize);
}



