#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/timeb.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "fat16.h"

#include <ctype.h>

#define FAT_NAME_LENGTH	11
#define FAT_EXT_OFFSET	8
#define FAT_EXT_LENGTH	3
#define ATTR_LONG_NAME 0x0f
#define FAT_DIR_ENTRY_SIZE 32
char *FAT_FILE_NAME = "fat16_test.img";

/* Read the sector 'secnum' from the image to the buffer */
void sector_read(FILE *fd, unsigned int secnum, void *buffer)
{
  fseek(fd, BYTES_PER_SECTOR * secnum, SEEK_SET);
  fread(buffer, BYTES_PER_SECTOR, 1, fd);
}

/** TODO:
 * ������·������/���ָ�ɶ���ַ�����������FAT�ļ�����ʽת���ַ���
 * ����: pathInput: char*, ������ļ�·����, ��/home/user/m.c
 * ���: pathDepth_ret, �ļ�������, �� 3
 * ����: ��FAT��ʽת������ļ����ַ���.
 * 
 * Hint1:����pathInputΪ��/dir1/dir2/file.txt��������ָ�ɡ�dir1������dir2������file.txt����
 *      ÿ���ַ���ת���ɳ���Ϊ11��FAT��ʽ���ļ������硰file.txt��ת���ɡ�FILE    TXT����
 *      ����ת������ַ������飬����*pathDepth_ret����Ϊ3, ת����ʽ���ĵ�����˵��.
 * Hint2:���ܻ���ֹ������ַ������룬�硰/.Trash-1000������Ҫ���нض��ַ���
 * Hint3:��Ҫ����.��..�����(. �� .. ������Ӧ��Ϊ /.��/..)
 **/
char **path_split(char *pathInput, int *pathDepth_ret)
{
    int i = 0, j = 0, k = 0;
    int pathDepth = 0, pathLenth = 0;
    pathLenth = strlen(pathInput);
    for (i = 0; i < pathLenth; i++){
        if(pathInput[i] == '/')
            pathDepth++;
    }     
    char **paths = malloc(pathDepth * sizeof(char *));
    for(i = 0;i < pathDepth;i++){
        paths[i] = malloc(11 * sizeof(char));
    }
    int isExtension = 0; //���ڼ�¼�Ƿ�Ϊ��չ��
	for (i = 0, j = 0; i < pathLenth; i++){
        if (pathInput[i] == '/'){
            strcpy(paths[j], "           ");
            k = 0;
            isExtension = 0;
            if (pathInput[i + 1] == '.' && pathInput[i + 2] == '.' && (pathInput[i + 3] == '/' || i + 3 >= pathLenth))
            {
                // "/../././../."
                paths[j][0] = '.';
                paths[j][1] = '.';
                i += 2;
            }
            else if (pathInput[i + 1] == '.' && (pathInput[i + 2] == '/' || i + 2 >= pathLenth))
            {
                paths[j][0] = '.';
                i += 1;
            }
            j++;
            continue;
        }
        if (pathInput[i] == '.')
        {
            k = 8;
            isExtension = 1;
            continue;
        }
        if ((k < 11 && isExtension == 1) || (k < 8 && isExtension == 0))
        {
            if(pathInput[i] >= 'a' && pathInput[i] <= 'z')
                paths[j - 1][k] = pathInput[i] - 'a' + 'A';
            else
                 paths[j - 1][k] = pathInput[i];
            k++;
        }
           
    }

    *pathDepth_ret = pathDepth;
    return paths;
}


/**
 * This function receieves a FAT file/directory name (DIR_Name) and decodes it
 * to its original user input name.
**/
BYTE *path_decode(BYTE *path)
{

  int i, j;
  BYTE *pathDecoded = malloc(MAX_SHORT_NAME_LEN * sizeof(BYTE));

  /* If the name consists of "." or "..", return them as the decoded path */
  if (path[0] == '.' && path[1] == '.' && path[2] == ' ')
  {
    pathDecoded[0] = '.';
    pathDecoded[1] = '.';
    pathDecoded[2] = '\0';
    return pathDecoded;
  }
  if (path[0] == '.' && path[1] == ' ')
  {
    pathDecoded[0] = '.';
    pathDecoded[1] = '\0';
    return pathDecoded;
  }

  /* Decoding from uppercase letters to lowercase letters, removing spaces,
   * inserting 'dots' in between them and verifying if they are legal */
  for (i = 0, j = 0; i < 11; i++)
  {
    if (path[i] != ' ')
    {
      if (i == 8)
        pathDecoded[j++] = '.';

      if (path[i] >= 'A' && path[i] <= 'Z')
        pathDecoded[j++] = path[i] - 'A' + 'a';
      else
        pathDecoded[j++] = path[i];
    }
  }
  pathDecoded[j] = '\0';
  return pathDecoded;
}

/**
 * Reads BPB, calculates the first sector of the root and data sections.
 * ============================================================================
 * Return
 * @fat16_ins: Structure that contains essential data about the File System (BPB,
 * first sector number of the Data Region, number of sectors in the root
 * directory and the first sector number of the Root Directory Region).
* =============================================================================
**/
FAT16 *pre_init_fat16(void)
{
  /* Opening the FAT16 image file */
  FILE *fd = fopen(FAT_FILE_NAME, "r+");

  if (fd == NULL)
  {
    fprintf(stderr, "Missing FAT16 image file!\n");
    exit(EXIT_FAILURE);
  }

  FAT16 *fat16_ins = malloc(sizeof(FAT16));

  fat16_ins->fd = fd;

  /** TODO: 
   * ��ʼ��fat16_ins�������Ա����
   * Hint: root directory�Ĵ�С��Bpb.BPB_RootEntCnt�йأ����������������
  **/
  /* ���뿪ʼ */
    BPB_BS Bpb;
	fread(&Bpb, sizeof(BPB_BS), 1, fd);
	fat16_ins->Bpb = Bpb;

	DWORD FirstRootDirSecNum = Bpb.BPB_RsvdSecCnt + (Bpb.BPB_NumFATS * Bpb.BPB_FATSz16);
	fat16_ins->FirstRootDirSecNum = FirstRootDirSecNum;

	DWORD RootDirSectors = (Bpb.BPB_RootEntCnt * 32)  / Bpb.BPB_BytsPerSec;
	DWORD FirstDataSector = Bpb.BPB_RsvdSecCnt + (Bpb.BPB_NumFATS * Bpb.BPB_FATSz16) + RootDirSectors;
	fat16_ins->FirstDataSector = FirstDataSector;

	

  /* ������� */

  return fat16_ins;
}


/** TODO:
 * ���شغ�ΪClusterN��Ӧ��FAT����
**/
WORD fat_entry_by_cluster(FAT16 *fat16_ins, WORD ClusterN)
{
  /* Buffer to store bytes from the image file and the FAT16 offset */ 
  BYTE sector_buffer[BYTES_PER_SECTOR];
  /* ���뿪ʼ */
  DWORD FATOffset = ClusterN * 2;
  DWORD ThisFATSecNum = fat16_ins->Bpb.BPB_RsvdSecCnt + (FATOffset / fat16_ins->Bpb.BPB_BytsPerSec);//������=����������+ƫ��/�����ֽ��� 
  DWORD ThisFATEntOffset = FATOffset % fat16_ins->Bpb.BPB_BytsPerSec; //������ƫ�� 
  sector_read(fat16_ins->fd, ThisFATSecNum, sector_buffer);
  WORD FAT16ClusEntryVal = *((WORD *)&sector_buffer[ThisFATEntOffset]);
  return FAT16ClusEntryVal;

  //return 0xffff;  //�����޸�

  /* ������� */
}

/**
 * Given a cluster N, this function reads its fisrst sector, 
 * then set the value of its FAT entry and the value of its first sector of cluster.
 * ============================================================================
**/
void first_sector_by_cluster(FAT16 *fat16_ins, WORD ClusterN, WORD *FatClusEntryVal, WORD *FirstSectorofCluster, BYTE *buffer)
{
  *FatClusEntryVal = fat_entry_by_cluster(fat16_ins, ClusterN);
  *FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;

  sector_read(fat16_ins->fd, *FirstSectorofCluster, buffer);
}


/**
 * Browse directory entries in root directory.
 * ==================================================================================
 * Return
 * 0, if we did find a file corresponding to the given path or 1 if we did not
**/

int find_root(FAT16 *fat16_ins, DIR_ENTRY *Root, const char *path)
{
  int i, j;
  int RootDirCnt = 1, is_eq;
  BYTE buffer[BYTES_PER_SECTOR];

  int pathDepth;
  char **paths = path_split((char *)path, &pathDepth);

  sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, buffer);

  /* We search for the path in the root directory first */
  for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
  {
    memcpy(Root, &buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);

    /* If the directory entry is free, all the next directory entries are also
     * free. So this file/directory could not be found */
    if (Root->DIR_Name[0] == 0x00)
    {
      return 1;
    }

    /* Comparing strings character by character */
    is_eq = strncmp(Root->DIR_Name, paths[0], 11) == 0 ? 1 : 0;

    /* If the path is only one file (ATTR_ARCHIVE) and it is located in the
     * root directory, stop searching */
    if (is_eq && Root->DIR_Attr == ATTR_ARCHIVE)
    {
      return 0;
    }

    /* If the path is only one directory (ATTR_DIRECTORY) and it is located in
     * the root directory, stop searching */
    if (is_eq && Root->DIR_Attr == ATTR_DIRECTORY && pathDepth == 1)
    {
      return 0;
    }

    /* If the first level of the path is a directory, continue searching
     * in the root's sub-directories */
    if (is_eq && Root->DIR_Attr == ATTR_DIRECTORY)
    {
      return find_subdir(fat16_ins, Root, paths, pathDepth, 1);
    }

    /* End of bytes for this sector (1 sector == 512 bytes == 16 DIR entries)
     * Read next sector */
    if (i % 16 == 0 && i != fat16_ins->Bpb.BPB_RootEntCnt)
    {
      sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, buffer);
      RootDirCnt++;
    }
  }

  /* We did not find anything */
  return 1;
}



/** TODO:
 * ����Ŀ¼��ʼ����path��Ӧ���ļ���Ŀ¼���ҵ�����0��û�ҵ�����1������Dir���Ϊ���ҵ��Ķ�ӦĿ¼��
 * 
 * Hint1: ��find_subdir��ڴ���DirӦ����Ҫ���ҵ���һ��Ŀ¼�ı����Ҫ�������еĴغţ���ȡ�⼶Ŀ¼��Ӧ����������
 * Hint2: Ŀ¼�Ĵ�С��δ֪�ģ����ܿ�Խ����������Խ����أ������ҵ�ĳ������0x00��ͷ�Ϳ���ֹͣ����
 * Hint3: ��Ҫ��������Ϊpaths[curDepth]���ļ���Ŀ¼��ͬ����Ҫ����pathDepth�ж��Ƿ��������find_subdir����
**/
int find_subdir(FAT16 *fat16_ins, DIR_ENTRY *Dir, char **paths, int pathDepth, int curDepth)
{
    int SecEntryCnt;
	int DirSecCnt = 0;  /* ����ͳ���Ѷ�ȡ�������� */
	BYTE buffer[BYTES_PER_SECTOR];
	WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;	
	ClusterN = Dir->DIR_FstClusLO;
	// read first sector
	first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);
    /* Searching for the given path in all directory entries of Dir */
    /* ���뿪ʼ */
    while (1) {
		// Subdir entry count unknown	
		while (1) {
			DirSecCnt++;
			for (SecEntryCnt = 0; SecEntryCnt < BYTES_PER_SECTOR / FAT_DIR_ENTRY_SIZE; SecEntryCnt++) {
				DIR_ENTRY DirEntry;
				memcpy(&DirEntry,
				       buffer + SecEntryCnt * FAT_DIR_ENTRY_SIZE,
				       FAT_DIR_ENTRY_SIZE);

				if (strncmp(DirEntry.DIR_Name, paths[curDepth], FAT_NAME_LENGTH) == 0) {
					*Dir = DirEntry;
					if (DirEntry.DIR_Attr == ATTR_DIRECTORY && curDepth < pathDepth-1)
						return find_subdir(fat16_ins, Dir, paths, pathDepth, curDepth + 1);//��һ��paths 
					else
						return 0;
				}
			}

			if (DirSecCnt < fat16_ins->Bpb.BPB_SecPerClus)
				sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, buffer);//��һ������ 
			else
				break;
		}

		if (FatClusEntryVal == 0x00) {
			break;
		} else {
			//��һ���� 
			ClusterN = FatClusEntryVal;
			first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal,
						&FirstSectorofCluster, buffer);
		}
	}

  /* ������� */

  /* We did not find the given path */
  return 1;
}

/* Function: plit the path, while keep their original format 
 * ==================================================================================
 * exp: "/dir1/dir2/text"  -> {"dir1","dir2","text"}
 * ==================================================================================
*/
char **org_path_split(char *pathInput){
  char *pathInput_;
  pathInput_ =(char *)malloc((strlen(pathInput)+1) * sizeof(char));
  memcpy(pathInput_, pathInput ,strlen(pathInput));
  int len = strlen(pathInput);
  printf("len: %d\n\n",len);
  pathInput_[len]='\0';
  printf("Paths_: %s\n\n",pathInput_);
  int i, j;
  int pathDepth = 0;
  for (i = 0; pathInput[i] != '\0'; i++)
  {
    if (pathInput_[i] == '/')
    {
      pathDepth++;
    }
  }
  char **orgPaths = (char **)malloc(pathDepth * sizeof(char *));
  const char token[] = "/";
  char *slice;

  /* Dividing the path into separated strings of file names */
  slice = strtok(pathInput_, token);
  for (i = 0; i < pathDepth; i++)
  {
    orgPaths[i] = slice;
    slice = strtok(NULL, token);
  }
  //printf("orgPaths_1: %s\n",orgPaths[0]);
  //printf("orgPaths_2: %s\n",orgPaths[1]);
  //printf("orgPaths_3: %s\n",orgPaths[2]);
  //printf("orgPaths_4: %s\n",orgPaths[3]);
  return orgPaths;
}


/* Function: Add an entry according to specified sector and offset
 * ==================================================================================
 * exp: sectorNum = 1000, offset = 1*BYTES_PER_DIR 
 * The 1000th sector content before create: | Dir Entry(used)   |  Dir Entry(free)  | ... |
 * The 1000th sector content after create:  | Dir Entry(used)   | Added Entry(used) | ... |
 * ==================================================================================
*/
/** TODO:
 * װ����Ŀ
 * ������Ӧ������ֵ
 * �Ѿ��������ļ�����ʾ�������������������
 **/  
int dir_entry_create(FAT16 *fat16_ins, int sectorNum, int offset, char *Name, BYTE attr, WORD firstClusterNum, DWORD fileSize)
{
	 printf("name: %s\n",Name);
	/* Create memory buffer to store entry info */
	BYTE *entry_info = malloc(BYTES_PER_DIR * sizeof(BYTE));
	/* Fill in file name */
	memcpy(entry_info, Name, 11);
	/* ���뿪ʼ */
	/* Fill in attr */
	entry_info[0xb] = attr;

	/* ������� */
	time_t timer_s;
	time(&timer_s);
	struct tm *time_ptr = localtime(&timer_s);
	int value;

	/* Unused */
	memset(entry_info + 12, 0, 10 * sizeof(BYTE));

	/* ���뿪ʼ */
	/* File update time */
	/* ʱ�䲿��һ��Ҫ�Ķ�ʵ���ĵ�!!! */
	unsigned temp;
	temp = (time_ptr->tm_sec >> 1) + (time_ptr->tm_min << 5) + (time_ptr->tm_hour << 11);
	entry_info[0x16] = temp;
	entry_info[0x17] = temp >> 8;
	/* File update date */
	/* First Cluster Number & File Size */
	temp = (time_ptr->tm_mday) + (time_ptr->tm_mon << 5) + ((time_ptr->tm_year - 80) << 9);
	entry_info[0x18] = temp;
	entry_info[0x19] = temp >> 8;
	/* ������� */
	/* Write the above entry to specified location */
	FILE *fd = fat16_ins->fd;
	BYTE *bufferm = malloc(BYTES_PER_DIR * sizeof(BYTE));
	fseek(fd, sectorNum * fat16_ins->Bpb.BPB_BytsPerSec + offset, SEEK_SET);
	int w_size = fwrite(entry_info, sizeof(BYTE), 32, fd);
	fflush(fd);
	free(entry_info);
	return 0;
}

/* Function: Get parent directory path of a specified file 
 * ==================================================================================
 * exp: path = "dir1/dir2/texts" orgPaths = { "dir1", "dir2", "tests" }
 * Return "dir1/dir2"
 * ==================================================================================
*/
char * get_prt_path(char *path, char **orgPaths,int pathDepth){
  char *prtPath;
  if(pathDepth == 1){
    prtPath = (char *)malloc(2*sizeof(char));
    prtPath[0] = '/';
    prtPath[1] = '\0';
  }
  else {
    int prtPathLen = strlen(path) - strlen(orgPaths[pathDepth-1])-1;
    prtPath = (char *)malloc((prtPathLen+1)*sizeof(char));
    strncpy(prtPath, path, prtPathLen);
    prtPath[prtPathLen] = '\0';
  }
  return prtPath;
}

//------------------------------------------------------------------------------

void *fat16_init(struct fuse_conn_info *conn)
{
  struct fuse_context *context;
  context = fuse_get_context();

  return context->private_data;
}

void fat16_destroy(void *data)
{
  free(data);
}

int fat16_getattr(const char *path, struct stat *stbuf)
{
  FAT16 *fat16_ins;

  /* Gets volume data supplied in the context during the fat16_init function */
  struct fuse_context *context;
  context = fuse_get_context();
  fat16_ins = (FAT16 *)context->private_data;

  /* stbuf: setting file/directory attributes */
  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_dev = fat16_ins->Bpb.BS_VollID;
  stbuf->st_blksize = BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus;
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();

  if (strcmp(path, "/") == 0)
  {
    /* Root directory attributes */
    stbuf->st_mode = S_IFDIR | S_IRWXU;
    stbuf->st_size = 0;
    stbuf->st_blocks = 0;
    stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = 0;
  }
  else
  {
    /* File/Directory attributes */
    DIR_ENTRY Dir;

    int res = find_root(fat16_ins, &Dir, path);

    if (res == 0)
    {
      /* FAT-like permissions */
      if (Dir.DIR_Attr == ATTR_DIRECTORY)
      {
        stbuf->st_mode = S_IFDIR | 0755;
      }
      else
      {
        stbuf->st_mode = S_IFREG | 0755;
      }
      stbuf->st_size = Dir.DIR_FileSize;

      /* Number of blocks */
      if (stbuf->st_size % stbuf->st_blksize != 0)
      {
        stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize) + 1;
      }
      else
      {
        stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize);
      }

      /* Implementing the required FAT Date/Time attributes */
      struct tm t;
      memset((char *)&t, 0, sizeof(struct tm));
      t.tm_sec = Dir.DIR_WrtTime & ((1 << 5) - 1);
      t.tm_min = (Dir.DIR_WrtTime >> 5) & ((1 << 6) - 1);
      t.tm_hour = Dir.DIR_WrtTime >> 11;
      t.tm_mday = (Dir.DIR_WrtDate & ((1 << 5) - 1));
      t.tm_mon = (Dir.DIR_WrtDate >> 5) & ((1 << 4) - 1);
      t.tm_year = 80 + (Dir.DIR_WrtDate >> 9);
      stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = mktime(&t);
    }
    else
      return -ENOENT;  // no such file
  }
  return 0;
}

int fat16_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi)
{
    FAT16 *fat16_ins;
	BYTE sector_buffer[BYTES_PER_SECTOR];
	int i, j;
	int RootDirCnt = 1, DirSecCnt = 0;  /* ����ͳ���Ѷ�ȡ�������� */

	struct fuse_context *context;
	context = fuse_get_context();
	fat16_ins = (FAT16 *)context->private_data;

	sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);
  if (strcmp(path, "/") == 0)
  {
    DIR_ENTRY Root;
    /** TODO:
     * ��root directory�µ��ļ���Ŀ¼ͨ��filler��䵽buffer��
     * ע�ⲻ��Ҫ������Ŀ¼
    **/
    /* Starts filling the requested directory entries into the buffer */
    for (i = 1, j = 0; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++, j++)
    {

      /* ���뿪ʼ */
        
		 	if (j == BYTES_PER_SECTOR / FAT_DIR_ENTRY_SIZE) {
		 		// read next sector
				sector_read(fat16_ins->fd,
					    fat16_ins->FirstRootDirSecNum + RootDirCnt,
					    sector_buffer);
				RootDirCnt++;
				j = 0;
		 	}

		 	memcpy(&Root,
		 	       sector_buffer + j * FAT_DIR_ENTRY_SIZE,
		 	       FAT_DIR_ENTRY_SIZE);

		 	if (Root.DIR_Attr != ATTR_LONG_NAME && Root.DIR_Name[0] != 0xe5) {
				
				const char *filename = (const char *)path_decode(Root.DIR_Name);
				filler(buffer, filename, NULL, 0);
		 	}
		

      /* ������� */
    }
  }
  else
  {
    DIR_ENTRY Dir;
    int SecEntryCnt;
    /** TODO:
     * ͨ��find_root��ȡpath��Ӧ��Ŀ¼��Ŀ¼�
     * Ȼ����ʸ�Ŀ¼�������µ��ļ���Ŀ¼ͨ��filler��䵽buffer�У�
     * ͬ��ע�ⲻ��Ҫ������Ŀ¼
     * Hint: ��Ҫ����Ŀ¼��С�����ܿ����������
    **/

    /* Finds the first corresponding directory entry in the root directory and
     * store the result in the directory entry Dir */
    find_root(fat16_ins, &Dir, path);

    /* Calculating the first cluster sector for the given path */
    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
    
    ClusterN = Dir.DIR_FstClusLO;

    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);

    /* Start searching the root's sub-directories starting from Dir */

    /* ���뿪ʼ */
    while (1) {
			while (1) {
				DirSecCnt++;
				for (SecEntryCnt = 0; SecEntryCnt < BYTES_PER_SECTOR / FAT_DIR_ENTRY_SIZE; SecEntryCnt++) {
					memcpy(&Dir,
					       sector_buffer + SecEntryCnt * FAT_DIR_ENTRY_SIZE,
					       FAT_DIR_ENTRY_SIZE);

					if (Dir.DIR_Attr != ATTR_LONG_NAME && Dir.DIR_Name[0] != 0xe5) { // && Dir.DIR_Name[0] != 0xe5
						const char *filename = (const char *)path_decode(Dir.DIR_Name);
						filler(buffer, filename, NULL, 0);
					}
				}

				if (DirSecCnt < fat16_ins->Bpb.BPB_SecPerClus)
					sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt,
						    sector_buffer);
				else
					break;
			}

			if (FatClusEntryVal == 0x00) {
				break;
			} else {
				ClusterN = FatClusEntryVal;
				first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal,
							&FirstSectorofCluster, sector_buffer);
			}
		}


    /* ������� */

  }
  return 0;
}


/** TODO:
 * ��path��Ӧ���ļ���offset�ֽڴ���ʼ��ȡsize�ֽڵ����ݵ�buffer�У�������ʵ�ʶ�ȡ���ֽ���
 * 
 * Hint: �ļ���С������Dir.DIR_FileSize����offset�����ļ���Сʱ��Ӧ�÷���0
**/
int fat16_read(const char *path, char *buffer, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
	FAT16 *fat16_ins;
	struct fuse_context *context;
	BYTE sector_buffer[BYTES_PER_SECTOR];
	// the # of sectors and clusters that have read
	int DirSecCnt, DirClusCnt;
	int BytesRead = 0, ReadSize;
	int ClusInOffset, RemBytesInClus;
	int SecStart, ByteStart;

	context = fuse_get_context();
	fat16_ins = (FAT16 *)context->private_data;

	DIR_ENTRY Dir;
	// not found
	if (find_root(fat16_ins, &Dir, path))
		return 0;
	// offset larger than filesize
	if (offset > Dir.DIR_FileSize)
		return 0;

	size = offset + size > Dir.DIR_FileSize ? Dir.DIR_FileSize - offset : size;
	
	WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;
	ClusterN = Dir.DIR_FstClusLO;

	// move to the cluster of offset
	ClusInOffset = offset / (BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus);
	RemBytesInClus = offset % (BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus);
	for (DirClusCnt = 0; DirClusCnt <= ClusInOffset; DirClusCnt++) {
		first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal,
					&FirstSectorofCluster, sector_buffer);
		ClusterN = FatClusEntryVal;
	}

	// move to the sector of offset
	SecStart = RemBytesInClus / BYTES_PER_SECTOR;
	// offset in the sector
	ByteStart = RemBytesInClus % BYTES_PER_SECTOR;
	DirSecCnt = SecStart;
	
	while (BytesRead < size) {
		if (ByteStart + size - BytesRead > BYTES_PER_SECTOR)
			ReadSize = BYTES_PER_SECTOR - ByteStart;
		else
			ReadSize = size - BytesRead;

		if (DirSecCnt < fat16_ins->Bpb.BPB_SecPerClus) {
			sector_read(fat16_ins->fd, DirSecCnt + FirstSectorofCluster, sector_buffer);
			DirSecCnt++;
		} else {
			first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal,
						&FirstSectorofCluster, sector_buffer);
			ClusterN = FatClusEntryVal;
			DirSecCnt = 1;
		}
		memcpy(buffer + BytesRead,
		       sector_buffer + ByteStart,
		       ReadSize);
		BytesRead += ReadSize;
		ByteStart = 0;
	}

	return size;
}

int fat16_mknod(const char *path, mode_t mode, dev_t devNum)
{
	/* Gets volume data supplied in the context during the fat16_init function */
	FAT16 *fat16_ins;
	struct fuse_context *context;
	context = fuse_get_context();
	fat16_ins = (FAT16 *)context->private_data;

	/** TODO:
   * //finish�����½��ļ��ĸ�Ŀ¼�������ʹ�ø�������org_path_split��get_prt_path
   **/
	/* ���뿪ʼ */
	int depth = 0;
	for (int i = 0; path[i]; ++i)
		if (path[i] == '/')
			++depth;
	char *prtPath = get_prt_path(path, org_path_split(path), depth);
	/* ������� */
    printf("prtpath:%s\n\n",prtPath);
	/** TODO:
   * ���ҿ��õ�entry��ע�����ָ�Ŀ¼����Ŀ¼
   * �����ṩ��һЩ����ʹ�õ�����ʱ����
   * ������ò����ã������Լ�����������ʱ����
   * ����ǰ���кܶ����Ƶĵط���ע�������ʵ��
   **/
	BYTE sector_buffer[BYTES_PER_SECTOR];
	DWORD sectorNum;
	int p = 0, findFlag = 0, offset, dirSecCnt = 0;
	char *name = path_split(path, &depth)[depth - 1];
	WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

	/* If parent directory is root */
	if (strcmp(prtPath, "/") == 0){
		sector_read(fat16_ins->fd, sectorNum = fat16_ins->FirstRootDirSecNum, sector_buffer);
		/* Starts searching free directory entries in root directory */
		/* ���뿪ʼ */
		for (int i = 0; i < fat16_ins->Bpb.BPB_RootEntCnt;i++){
			if (p >= BYTES_PER_SECTOR){
				p %= BYTES_PER_SECTOR;
				sector_read(fat16_ins->fd, ++sectorNum, sector_buffer);
			}
			if (sector_buffer[p] == 0x0){ // 0xe5���� 
				findFlag = 1;
				offset = p;
				break;
			}
			p += 32;
		}
		/* ������� */
	}
	/* Else if parent directory is sub-directory */
	else
	{
		DIR_ENTRY Dir;
		find_root(fat16_ins, &Dir, prtPath);
		/* Find appropriate sector and offset to add the DIR ENTRY*/
		ClusterN = Dir.DIR_FstClusLO;
		first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
		/* Start searching the root's sub-directories starting from Dir */

		/* ���뿪ʼ */
		for (p = 0;;){
			if (sector_buffer[p] == 0x0){ // 0xe5����		
				findFlag = 1;
				offset = p;
				sectorNum = FirstSectorofCluster + dirSecCnt;
				break;
			}
			p += BYTES_PER_DIR;
			if (p >= BYTES_PER_SECTOR){
				p %= BYTES_PER_SECTOR;
				dirSecCnt++;
				if (dirSecCnt >= fat16_ins->Bpb.BPB_SecPerClus){
					dirSecCnt %= fat16_ins->Bpb.BPB_SecPerClus;
					if (FatClusEntryVal >= 0x2 && FatClusEntryVal <= 0xffef)
						first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
					else
						break;
				}
				else{
					sector_read(fat16_ins->fd, FirstSectorofCluster + dirSecCnt, sector_buffer);
				}
			}
		}
		/* ������� */
	}
	/* Add the DIR ENTRY */
	if (findFlag == 1)
		dir_entry_create(fat16_ins, sectorNum, offset, name, ATTR_ARCHIVE, 0xff1f, 0);
	return 0;
}
/**
 * free cluster ʱ��ֻ�޸�FAT��Ӧ����
 * @return ��һ���صĴغ�
  */
int freeCluster(FAT16 *fat16_ins, int ClusterNum){
  BYTE sector_buffer[BYTES_PER_SECTOR];
  WORD FATClusEntryval,FirstSectorofCluster;
  first_sector_by_cluster(fat16_ins,ClusterNum,&FATClusEntryval,&FirstSectorofCluster,sector_buffer);
  FILE *fd = fat16_ins->fd;
  /** TODO:
   * �޸�FAT��
   * ע��������Ҫ�޸�
   **/
   /* ���뿪ʼ */
  BYTE z[] = {0,0,0,0}; 
  fseek(fd , fat16_ins->Bpb.BPB_RsvdSecCnt * fat16_ins->Bpb.BPB_BytsPerSec + 2* ClusterNum, SEEK_SET);
  fwrite(z, sizeof(BYTE), 4, fd); 
  fflush(fd);  
  fseek(fd , (fat16_ins->Bpb.BPB_RsvdSecCnt + fat16_ins->Bpb.BPB_FATSz16) * fat16_ins->Bpb.BPB_BytsPerSec + 2* ClusterNum, SEEK_SET);  
  fwrite(z, sizeof(BYTE), 4, fd); 
  fflush(fd); 
   /* ������� */  
  return FATClusEntryval; 
}

/* Function: remove a file */
int fat16_unlink(const char *path)
{
	/* Gets volume data supplied in the context during the fat16_init function */
	FAT16 *fat16_ins;
	struct fuse_context *context;
	context = fuse_get_context();
	fat16_ins = (FAT16 *)context->private_data;

	/** TODO:
   * ���ո��ļ���ռ�еĴ�
   * ע�����Ʋ�ʹ��freeCluster����
   **/
	WORD ClusterN, N;
	DIR_ENTRY Dir;
	//�ͷ�ʹ�ù��Ĵ�
	if (find_root(fat16_ins, &Dir, path) == 1){
		return 1;
	}
	ClusterN = Dir.DIR_FstClusLO;

	/* ���뿪ʼ */
	while (ClusterN >= 0x2 && ClusterN <= 0xffef){
		WORD temp = fat_entry_by_cluster(fat16_ins, ClusterN);
		freeCluster(fat16_ins, ClusterN);
		ClusterN = temp;
	}
	/* ��������freeCluster�����󣬴˴���������С*/
	/* ��Ҳ���Բ�ʹ��freeCluster������ͨ���Լ��ķ�ʽʵ�� */

	/* ������� */

	/* Find the location(sector number & offset) of file entry */
	/** TODO:
   * �����½��ļ��ĸ�Ŀ¼�������ʹ�ø�������org_path_split��get_prt_path
   * �ⲿ�����ݺ�mknode�������
   **/
	/* ���뿪ʼ */
	int depth = 0;
	for (int i = 0; path[i]; ++i)
		if (path[i] == '/')
			depth++;
	char *prtPath = get_prt_path(path, org_path_split(path), depth);
	/* ������� */

	/** TODO:
   * ��λ�ļ��ڸ�Ŀ¼�е�entry��ע�����ָ�Ŀ¼����Ŀ¼
   * �����ṩ��һЩ����ʹ�õ�����ʱ����
   * ������ò����ã������Լ�����������ʱ����
   * ����ǰ���кܶ����Ƶĵط���ע�������ʵ��
   * �������ƣ��������붼��mknodeһ����ע�⸴��
   **/

	BYTE sector_buffer[BYTES_PER_SECTOR];
	DWORD sectorNum;
	int p = 0, offset, dirSecCnt = 0, find = 0;
	char *name = path_split(path, &depth)[depth - 1];
	WORD FatClusEntryVal, FirstSectorofCluster;

	/* If parent directory is root */
	if (strcmp(prtPath, "/") == 0){
		sector_read(fat16_ins->fd, sectorNum = fat16_ins->FirstRootDirSecNum, sector_buffer);
		/* Starts searching free directory entries in root directory */
		/* ���뿪ʼ */
		for (int i = 0; i < fat16_ins->Bpb.BPB_RootEntCnt; ++i){
			if (p >= BYTES_PER_SECTOR){
				p %= BYTES_PER_SECTOR;
				sector_read(fat16_ins->fd, ++sectorNum, sector_buffer);
			}
			if (memcmp(&sector_buffer[p], name,11) == 0){
				offset = p;
				find = 1;
				break;
			}
			p += 32;
		}
		/* ������� */
	}
	/* Else if parent directory is sub-directory */
	else
	{
		DIR_ENTRY Dir;
		find_root(fat16_ins, &Dir, prtPath);
		/* Find appropriate sector and offset to add the DIR ENTRY*/
		ClusterN = Dir.DIR_FstClusLO;
		first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
		/* Start searching the root's sub-directories starting from Dir */

		/* ���뿪ʼ */
		for (p = 0;;){
			if (memcmp(&sector_buffer[p], name,11) == 0){
				offset = p;
				sectorNum = FirstSectorofCluster + dirSecCnt;
				find = 1;
				break;
			}
			pos += BYTES_PER_DIR;
			if (pos >= BYTES_PER_SECTOR){
				pos %= BYTES_PER_SECTOR;
				++dirSecCnt;
				if (dirSecCnt >= fat16_ins->Bpb.BPB_SecPerClus){
					dirSecCnt %= fat16_ins->Bpb.BPB_SecPerClus;
					if (FatClusEntryVal >= 0x2 && FatClusEntryVal <= 0xffef)
						first_sector_by_cluster(fat16_ins, FatClusEntryVal, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);
					else
						break;
				}
				else{
					sector_read(fat16_ins->fd, FirstSectorofCluster + dirSecCnt, sector_buffer);
				}
			}
		}
		/* ������� */
	}

	/** TODO:
   * ɾ���ļ�������Ӧentry�����
   * ˼��Ҫ�޸�entry�е���Щ��
   **/

	/* Update file entry, change its first byte of file name to 0xe5 */
	if (find){
		FILE *fd = fat16_ins->fd;
		/* ���뿪ʼ */
		fseek(fd, sectorNum * fat16_ins->Bpb.BPB_BytsPerSec + offset, SEEK_SET);
		BYTE tmp = 0xe5;
		fwrite(&tmp, sizeof(BYTE), 1, fd);
		fflush(fd);
		/* ������� */
	}
	return 0;
}

//------------------------------------------------------------------------------

struct fuse_operations fat16_oper = {
    .init = fat16_init,
    .destroy = fat16_destroy,
    .getattr = fat16_getattr,
    .readdir = fat16_readdir,
    .read = fat16_read,
    .mknod = fat16_mknod,
    .unlink = fat16_unlink
    };

//------------------------------------------------------------------------------


void test_path_split() {
  printf("#1 running %s\n", __FUNCTION__);

  char s[][32] = {"/texts", "/dir1/dir2/file.txt", "/.Trash-100"};
  int dr[] = {1, 3, 1};
  char sr[][3][32] = {{"TEXTS      "}, {"DIR1       ", "DIR2       ", "FILE    TXT"}, {"        TRA"}};

  int i, j, r;
  for (i = 0; i < sizeof(dr) / sizeof(dr[0]); i++) {
  
    char **ss = path_split(s[i], &r);
    assert(r == dr[i]);
    for (j = 0; j < dr[i]; j++) {
      assert(strcmp(sr[i][j], ss[j]) == 0);
      free(ss[j]);
    }
    free(ss);
    printf("test case %d: OK\n", i + 1);
  }

  printf("success in %s\n\n", __FUNCTION__);
}

void test_path_decode() {
  printf("#2 running %s\n", __FUNCTION__);

  char s[][32] = {"..        ", "FILE    TXT", "ABCD    RM "};
  char sr[][32] = {"..", "file.txt", "abcd.rm"};

  int i, j, r;
  for (i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
    char *ss = (char *) path_decode(s[i]);
    assert(strcmp(ss, sr[i]) == 0);
    free(ss);
    printf("test case %d: OK\n", i + 1);
  }

  printf("success in %s\n\n", __FUNCTION__);
}

void test_pre_init_fat16() {
  printf("#3 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  assert(fat16_ins->FirstRootDirSecNum == 124);
  assert(fat16_ins->FirstDataSector == 156);
  assert(fat16_ins->Bpb.BPB_RsvdSecCnt == 4);
  assert(fat16_ins->Bpb.BPB_RootEntCnt == 512);
  assert(fat16_ins->Bpb.BS_BootSig == 41);
  assert(fat16_ins->Bpb.BS_VollID == 1576933109);
  assert(fat16_ins->Bpb.Signature_word == 43605);
  
  fclose(fat16_ins->fd);
  free(fat16_ins);
  
  printf("success in %s\n\n", __FUNCTION__);
}

void test_fat_entry_by_cluster() {
  printf("#4 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  int cn[] = {1, 2, 4};
  int ce[] = {65535, 0, 65535};

  int i;
  for (i = 0; i < sizeof(cn) / sizeof(cn[0]); i++) {
    int r = fat_entry_by_cluster(fat16_ins, cn[i]);
    assert(r == ce[i]);
    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}

void test_find_root() {
  printf("#5 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  char path[][32] = {"/dir1", "/makefile", "/log.c"};
  char names[][32] = {"DIR1       ", "MAKEFILE   ", "LOG     C  "};
  int others[][3] = {{100, 4, 0}, {100, 8, 226}, {100, 3, 517}};

  int i;
  for (i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    DIR_ENTRY Dir;
    find_root(fat16_ins, &Dir, path[i]);
    assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
    assert(Dir.DIR_CrtTimeTenth == others[i][0]);
    assert(Dir.DIR_FstClusLO == others[i][1]);
    assert(Dir.DIR_FileSize == others[i][2]);

    printf("test case %d: OK\n", i + 1);
  }
  
  fclose(fat16_ins->fd);
  free(fat16_ins);

  printf("success in %s\n\n", __FUNCTION__);
}

void test_find_subdir() {
  printf("#6 running %s\n", __FUNCTION__);

  FAT16 *fat16_ins = pre_init_fat16();

  char path[][32] = {"/dir1/dir2", "/dir1/dir2/dir3", "/dir1/dir2/dir3/test.c"};
  char names[][32] = {"DIR2       ", "DIR3       ", "TEST    C  "};
  int others[][3] = {{100, 5, 0}, {0, 6, 0}, {0, 7, 517}};

  int i;
  for (i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
    DIR_ENTRY Dir;
    find_root(fat16_ins, &Dir, path[i]);
    assert(strncmp(Dir.DIR_Name, names[i], 11) == 0);
    assert(Dir.DIR_CrtTimeTenth == others[i][0]);
    assert(Dir.DIR_FstClusLO == others[i][1]);
    assert(Dir.DIR_FileSize == others[i][2]);

    printf("test case %d: OK\n", i + 1);
  }
  /*
  char f1[]="/black";
  fat16_mknod(f1, 0, 0,fat16_ins);
  char f2[]="/dir1/white";
  fat16_mknod(f2, 0, 0,fat16_ins);
  fat16_unlink(f2, fat16_ins);
  */
  fclose(fat16_ins->fd);
  free(fat16_ins);
  printf("success in %s\n\n", __FUNCTION__);
}


int main(int argc, char *argv[])
{
  int ret;

  if (strcmp(argv[1], "--test") == 0) {
    printf("--------------\nrunning test\n--------------\n");
    FAT_FILE_NAME = "fat16_test.img";
    test_path_split();
    test_path_decode();
    test_pre_init_fat16();
    test_fat_entry_by_cluster();
    test_find_root();
    test_find_subdir();
    exit(EXIT_SUCCESS);
  }

  /* Starting a pre-initialization of the FAT16 volume */
  FAT16 *fat16_ins = pre_init_fat16();

  ret = fuse_main(argc, argv, &fat16_oper, fat16_ins);

  return ret;
}


