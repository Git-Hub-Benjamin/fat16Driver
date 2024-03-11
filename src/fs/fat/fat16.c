#include "fat16.h"
#include "string/string.h"
#include "disk/disk.h"
#include "disk/streamer.h"
#include "memory/heap/kheap.h"
#include "memory/memory.h"
#include "status.h"
#include "kernel.h"
#include <stdint.h>

#define PEACHOS_FAT16_SIGNATURE 0x29
#define PEACHOS_FAT16_FAT_ENTRY_SIZE 0x02
#define PEACHOS_FAT16_BAD_SECTOR 0xFF7
#define PEACHOS_FAT16_UNUSED 0x00



// Fat directory entry attributes bitmask
#define FAT_FILE_READ_ONLY 0x01
#define FAT_FILE_HIDDEN 0x02
#define FAT_FILE_SYSTEM 0x04
#define FAT_FILE_VOLUME_LABEL 0x08
#define FAT_FILE_SUBDIRECTORY 0x10
#define FAT_FILE_ARCHIVED 0x20
#define FAT_FILE_DEVICE 0x40
#define FAT_FILE_RESERVED 0x80

typedef unsigned int FAT_DIR_ENTRY_TYPE;
enum SEARCHING_DIRECTORY
{
    TYPE_DIR,
    TYPE_FILE,
};

struct Fat16Metadata
{
    int bootStartSect;
    int fatStartSect;
    int rootStartSect;
    int dataStartSect;
    int optimalSectorReadBlockSize;
};

struct fat_header_extended
{
    uint8_t drive_number;
    uint8_t win_nt_bit;
    uint8_t signature;
    uint32_t volume_id;
    uint8_t volume_id_string[11];
    uint8_t system_id_string[8];
} __attribute__((packed));

struct fat_header
{
    uint8_t short_jmp_ins[3];
    uint8_t oem_identifier[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_copies;
    uint16_t root_dir_entries;
    uint16_t number_of_sectors;
    uint8_t media_type;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t hidden_setors;
    uint32_t sectors_big;
} __attribute__((packed));

struct fat_h
{
    struct fat_header primary_header;
    struct fat_header_extended extended_header;
};

struct fat_directory_item
{
    uint8_t filename[8];
    uint8_t ext[3];
    uint8_t attribute;
    uint8_t reserved;
    uint8_t creation_time_tenths_of_a_sec;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access;
    uint16_t high_16_bits_first_cluster;
    uint16_t last_mod_time;
    uint16_t last_mod_date;
    uint16_t low_16_bits_first_cluster;
    uint32_t filesize;
} __attribute__((packed));

struct fat_file_descriptor
{
    struct fat_directory_item file;
    uint32_t pos; // pos is the byte number we are on in the file
    int startingClusterNumber; // starting cluster of file
    int attributes; // attributes of file, may want to expand this to an enum
};

struct fat_private
{
    struct fat_h headers;
    struct fat_directory_item* root_directory;
    struct Fat16Metadata helperData;

    // Used to stream data clusters
    struct disk_stream *cluster_read_stream; //* FREAD
    // Used to stream the file allocation table 
    struct disk_stream *fat_read_stream;     //* FAT TABLE
    // Used in situations where we stream the directory
    struct disk_stream *directory_stream;    //* FOPEN
};

int fat16_resolve(struct disk *disk);
void *fat16_open(struct disk *disk, struct path_part *path, FILE_MODE mode);
int fat16_read(struct disk *disk, void *descriptor, uint32_t size, uint32_t nmemb, char *out_ptr);
// int fat16_seek(void *private, uint32_t offset, FILE_SEEK_MODE seek_mode);
// int fat16_stat(struct disk* disk, void* private, struct file_stat* stat);
// int fat16_close(void* private);

struct filesystem fat16_fs =
{
    .resolve = fat16_resolve,
    .open = fat16_open,
    .read = fat16_read,
    // .seek = fat16_seek,
    // .stat = fat16_stat,
    // .close = fat16_close
};

struct filesystem *fat16_init()
{
    strcpy(fat16_fs.name, "FAT16");
    return &fat16_fs;
}

static void fat16_init_private(struct disk *disk, struct fat_private *private)
{
    memset(private, 0, sizeof(struct fat_private));
    private->cluster_read_stream = diskstreamer_new(disk->id);
    private->fat_read_stream = diskstreamer_new(disk->id);
    private->directory_stream = diskstreamer_new(disk->id);
}

int fat16ClusterToSectorCalculate(struct fat_private* fp, int cluster)
{
    return (fp->helperData.dataStartSect + (cluster - 2) * fp->headers.primary_header.sectors_per_cluster);
}

int fat16_extract_cluster_start(struct fat_directory_item* entry)
{
    return (entry->high_16_bits_first_cluster << 16) | entry->low_16_bits_first_cluster;
}

void fat16_string_copy(const char* src, char* dst)
{
    for(int i = 0; i < 11; i++)
    {
        *dst = *src;
        dst++;
        src++;
    }
}

void fat16_remove_entry_spaces(char* in)
{
    for (int i = 0; i < 11; i++)
    {
        // each entry (file or subdirectory) should be 8 bytes in size
        if(*in == ' ')
        {
            *in = '\0';
            break;
        }
        in++;
    }
}

void fat16_add_extension(const char* in, char* out)
{
    // get to where the extension would be
    in+=7; 
    if(*in != '.')
    {
        // make sure there is an extension associated with this entry
        return;
    }
    int counter = 4; // 4 because extension ".txt" is 4 bytes
    while(*out != '\0')
    {
        // get to where the null terminator is example: "hello\0"
        counter++;
        out++; 
    }

    for(int i = 0; i < 4; i++)
    {
        // add file extension
        *out = *in;
        in++;
        out++;
    }

    // clear the rest of the crap after

    for(int j = 0; j < (11 - counter); j++)
    {
        *out = 0;
        out++;
    }
}

void fat16_make_entry_to_lower(char* in)
{
    for (int i = 0; i < 11; i++)
    {
        if(*in >= 65 && *in <= 95)
        {
            *in = tolower(*in);
        }
        in++;
        // this will go over the total 11 bytes regardless if the directory is like "BAR"
    }

}

// pass in a pointer to the entry, "in" will not be modified, "out" should be a malloced pointer of size 11 bytes, this will be operated on, 
// it will return with "out" pointing to the beggining of the string
void fat16_convert_dir_entry_name(const char* in, char* out)
{
    // first we need to make a copy of the entry / string so we can work on it
    fat16_string_copy(in, out); // i think i can use the strncmp but idc
    // now remove the spaces of this copy
    fat16_remove_entry_spaces(out);
    // now add the extension
    fat16_add_extension(in, out);
    // now make it all lowercase
    fat16_make_entry_to_lower(out);
}

bool fat16_confirm_entry_match(const char* rootDirEntryPtr, const char* pathPartToMatchWith)
{
    char* dirEntryConvert = kzalloc(11); // 11 is the size of file / entry (8 for file 3 for ext)
    fat16_convert_dir_entry_name(rootDirEntryPtr, dirEntryConvert);
    bool equal = istrncmp(pathPartToMatchWith, dirEntryConvert, sizeof(PEACHOS_MAX_PATH));
    kfree(dirEntryConvert);
    return equal;
}

struct fat_directory_item* fat16_search_directory(struct fat_directory_item* fat16Directory, const char* path)
{
    // Automatic value
    struct fat_directory_item* foundedFatDirEntry = 0;

    const char* currentEntryPtr = (const char*)fat16Directory; 
    // this should point the the first byte in the array of entries
    // i need to cast this to a char* because we are not treating this as a pointer to fat_directory_items if it was fat_directory_item[0] would do the first 32
    // bytes and fat_director_item[1] would do the second element (32-63 bytes) no no. we want to point to each byte indivdually
    while(true)
    {
        if(*currentEntryPtr == 0x00)
        {
            // this means the end of the directory entries
            break;
        }
        if(fat16_confirm_entry_match(currentEntryPtr, path) != 0 || *currentEntryPtr == 0xE5) // 0xE5 means deleted file 
        {
            // Come in here if not match
            currentEntryPtr += 32; // Go to next entry
            continue;
        }
        
        // Confirmed match, lets copy the current entry that the match was on into our foundedFatItem pointer
        foundedFatDirEntry = kzalloc(sizeof(struct fat_directory_item)); //! MAKE SURE WE FREE THIS IN CALLE 
        bytecpy(currentEntryPtr, (char*)foundedFatDirEntry, sizeof(struct fat_directory_item)); 
        break;
    }
    
    return foundedFatDirEntry;
}

//! FIX THIS TO RETURN fat_directory_item and not load directory
struct fat_directory_item* fat16_load_directory(struct disk* disk, int sector) // this is the raw sector to read from the disk
{
    // We have the disk, we have the cluster we need to read

    // This part is hard, becasue we are loading a directory from disk into memory right? There are 128 sectors per 1 cluster so that means that we need to read
    // 384208 Bytes into memory, imagine if it uses cluster chaining, this is nearly 1/3 of our heap, we cant do this. So we need to do it in parts. Im going to read
    // 8 sectors in at a time because thats the size of 1 block in the heap, then if we dont find it then we need to recall this function.

    // We are going to load, search and if we dont find it then load again and search again, if we get to the end then we need to check the FAT table, if we find
    // another cluster chained then we follow it, if we dont then the file Or directory does not exsist

    struct fat_private* private_data = disk->fs_private;
    int sectorAmountReadSize = private_data->helperData.optimalSectorReadBlockSize;
    // if the sectors per cluster is like 2, then we will just read 2 sectors at a time, if its above 8 then we will use 8 at a time because 8 * 512 = 4096 (heap size)
    struct fat_directory_item* buffer = kzalloc(sectorAmountReadSize * disk->sector_size); 
    //private_data->helperData.dataRegionBeginningSector, private_data->headers.primary_header.sectors_per_cluster
    diskstreamer_seek(private_data->directory_stream, (sector * disk->sector_size)); 
    // this will set the position of the raw bytes to read
    if(diskstreamer_read(private_data->directory_stream, buffer, sectorAmountReadSize) != 0)
    {
        return ERROR(-EIO); // Error reading the directory / disk
    }
    
    return buffer;
    // buffer will be less than or equal to 4096 bytes, the max sectors that will be read at a time from a cluster is 8 minimum obviously 1
}

int fat16_consult_fat_table(struct disk* disk, int clusterToCheck)
{
    // we need to go into the fat table and offset into this entry, then we need to read if its 0xFFFF (EOF), 0xFFF8F
    //^ 0x0000          Free Cluster
    //! 0x0001 - 0x0002 Not Allowed cluster
    //* 0x0003 - 0xFFEF Pointer to next cluster
    //& 0xFFF7          One or more bad sectors in cluster
    //? 0xFFF8 - 0xFFFF End of file / cluster chain

    if (clusterToCheck < 2) return -EINVARG;

    struct fat_private* private_data = disk->fs_private;
    int byteToReadFromFat = (private_data->helperData.fatStartSect * disk->sector_size) + (2 * clusterToCheck);
    int buffer;
    if(diskstreamer_read(private_data->fat_read_stream, (void*)&buffer, byteToReadFromFat) != 0)
    {
        return -EIO;
    }

    if(!(buffer >= 0x0003 || buffer <= 0xFFEF)) // if buffer is not within the good range then
    {
        return 0;
    }

    return buffer;
}   

FAT_DIR_ENTRY_TYPE fat16FileOrSubDirectory(struct fat_directory_item* entry) // 0 if DIR , 1 if FILE
{
    return (entry->attribute & FAT_FILE_SUBDIRECTORY) ? TYPE_DIR : TYPE_FILE;
}


// Now we will check if the subdirectory bit is set, if it is then set type of fat item to directory if not its a file
//foundedFatItem->fatSearchResult = *(currentEntryPtr + 11) & FAT_FILE_SUBDIRECTORY ? TYPE_DIR : TYPE_FILE; 

struct fat_directory_item* fat16_get_file(struct disk* disk, struct fat_directory_item* current_directory, struct path_part* path)
{
    struct fat_private* private_data = disk->fs_private;
    struct fat_directory_item* response = 0;

    // This first call to fat16_seach_directory will be assuming its from the root
    struct fat_directory_item* fatDirEntryFromRoot = fat16_search_directory(private_data->root_directory, path->part);
    //! We need to kfree this memory, make sure you free its memebers (fatEntry)

    if(fatDirEntryFromRoot == 0)
    {
        return ERROR(-EBADPATH);
    } // if it is 0 then it means that we did not find it in the root directory

    // Ok now we know we found an item, lets distguish file VS directory

    if(fat16FileOrSubDirectory(fatDirEntryFromRoot) != 0) // This means the thing we found was the file we were looking for and its a file so we are done
    {
        // We found the item easily, ok now return the fat_directory_item pointer and the fopen function will make the fat file descriptor
        return fatDirEntryFromRoot;
    }

    // We know that it must be a directory now, so lets search again,

    struct fat_directory_item* loadedDirectory = 0;
    struct fat_directory_item* tempFreeOldDirectory = fatDirEntryFromRoot;
        
    // Quick Access Helper Data
    int sectorsPerCluster = private_data->headers.primary_header.sectors_per_cluster;
    int sectorsReadEveryTime = private_data->helperData.optimalSectorReadBlockSize;
    
    path = path->next;

    while(path != 0)
    {
        int clusterToRead = fat16_extract_cluster_start(tempFreeOldDirectory);
        // this will initally hold the cluster found in the entry, it may hold the one found in fat by the end of finding the entry
        int begginingSectorOfCluster = fat16ClusterToSectorCalculate(private_data, clusterToRead);
        // now get the sector on the disk the cluster is at
        int sectorsReadSoFar = 0;
        // since we only read a certain amount sectors at a time from a cluster we need to keep track of which ones we have read so far
        while(true)
        {
            kfree(tempFreeOldDirectory);
            // free the old directory, we only needed it to extract the cluster we needed to look in, we needed to do it here because we need to kfree the old'
            // directory on each pass through this inner while loop
            if(sectorsReadSoFar < sectorsPerCluster) // meaning we still have more to read if we have not found a match yet
            {
                loadedDirectory = fat16_load_directory(disk,  (begginingSectorOfCluster + sectorsReadSoFar));
                // load the directory of the cluster we are looking for, so we need to convert that to sectors then add the amount we have already read
                tempFreeOldDirectory = loadedDirectory;
                // we need to do this in case that when we find lets say 0:/bar/foo/dee/hello.txt, say we just found "foo" (in the line below), we need to have
                // a pointer to the directoryEntry in memory so we can refrence its cluster on the next go around since path!=0 since it will still point to hello.txt
                loadedDirectory = fat16_search_directory(loadedDirectory, path->part);

                if(loadedDirectory != 0) 
                {
                    // We found a match for something, lets check for errors like 0:/bar/hello.txt/bye.txt
                    if(fat16FileOrSubDirectory(loadedDirectory) == 1 && path->next != 0) 
                    {
                        // if we found a file but there is still another path part then error
                        response = ERROR(-EBADPATH);
                        goto error_out;
                    }
                    // Now we can just break because if its a file, then it will break out of this inner while loop, set path = path->next which will be 0, break out
                    // of the outer while loop and return the current loadedDirectory which is the one we found with the file match, the fopen function will asign this
                    // to a fat16 file descriptor, if this is a folder we can still breakout becase it will also do path = path->next but this will not be 0, it will
                    // be the next director to find, so we do clusterToRead on the one we just found so we know what director to load, then we check if we find the 
                    // thing we are looking for in the sectors we loaded from the cluster we are seaching, if we did greate then we would be in case 1 of this paragraph
                    // with the file, if not then we add the sectors we read to a total sector count read variable and before we read again from the same cluster we 
                    // check if there are any sectors we havent in this cluster --> if(sectorsReadSoFar < sectorsPerCluster) if there are still some left then we go
                    // again if there are no more sectors in this cluster then we go to the else block, the else block the else block will get the cluster offset in 
                    // the fattable and read it into ram, we then check if there is another cluster in the chain, if there is then we reset everything above and start
                    // reading from there still looking for the same directory or file, if there are no more in the chain that means that there was a bad path because,
                    // we could not find the thing the user was looking for.
                    break; 
                }

            }else{
                // If we have gotten here then we know we did not find the entry in the current cluster, we need to look in Fat table to see if there are any more
                // cluster chains we need to look through before we say this directory OR file does not exsist
                clusterToRead = fat16_consult_fat_table(disk, clusterToRead);
                // get the cluster we need to read if any, if we find out that this is the last cluster in the chain then we have to handle it here
                // reset the sectorsreadsofar, obviously this will only matter if there is another cluster in the chain
                if(clusterToRead < 0)
                {
                    response = ERROR(-EIO);
                    goto error_out;
                } // make sure no error

                if(clusterToRead == 0)
                {
                    response = ERROR(-EBADPATH);
                    goto error_out;
                    // This is the end... 
                    //& Also this return 0 could be inaccurate because it ruturns 0 even if there is a bad sector if there is a bad sector in the cluster, 
                    //& (which is not a bad path error) so it could technically be in the directory
                }

                // We must still be good so we keep reading

                sectorsReadSoFar = 0;
                continue;
                // we need to continue or else it will add the sectorsReadSoFar and we havent read any sectors yet
            }
            // If no match keep looking
            sectorsReadSoFar += sectorsReadEveryTime; // this is determined in the resolve function
        }

        path = path->next;
    }

error_out:
    kfree(tempFreeOldDirectory);
    if((int)response < 0) loadedDirectory = response;
    return loadedDirectory; 
}

int readRootDirectory(struct disk* disk)
{
    struct fat_private* private_data = disk->fs_private;
    struct fat_header* tempPrimaryHeaderAccess = &private_data->headers.primary_header;

    // getting ready for the read
    int bytesToRead = sizeof(struct fat_directory_item) * tempPrimaryHeaderAccess->root_dir_entries;
    int rootDirSector = (tempPrimaryHeaderAccess->fat_copies * tempPrimaryHeaderAccess->sectors_per_fat) + tempPrimaryHeaderAccess->reserved_sectors;

    // seek to the byte where the root directory begins, Not really sure if we should use disk->sector_size or tempPrimaryHeaderAccess->BytesPerSector...
    diskstreamer_seek(private_data->directory_stream, rootDirSector * disk->sector_size);

    // allocate space for the entire root directory
    private_data->root_directory = kzalloc(sizeof(struct fat_directory_item) * tempPrimaryHeaderAccess->root_dir_entries);

    // read into the root directory
    if(diskstreamer_read(private_data->directory_stream, private_data->root_directory, bytesToRead) != PEACHOS_ALL_OK)
    {
        kfree(private_data->root_directory);
        return -EIO;
    }

    return 0; // Everything went all good reading the root directory into the fat_private -> root_directory
}

int fat16_read(struct disk *disk, void* descriptor, uint32_t sizeOfElement, uint32_t numOfElements, char* out)
{
    struct fat_file_descriptor* fat_desc = descriptor;
    struct fat_private* private_data = disk->fs_private;

    // less than a sector
    int sectorToReadFrom = private_data->helperData.dataStartSect + (fat_desc->startingClusterNumber - 2) * private_data->headers.primary_header.sectors_per_cluster; 
    int byteToReadFrom = sectorToReadFrom * disk->sector_size;

    // point to the byte to start reading from
    diskstreamer_seek(private_data->cluster_read_stream, byteToReadFrom);
    // read bytes
    if(diskstreamer_read(private_data->cluster_read_stream, out, (sizeOfElement * numOfElements)) != PEACHOS_ALL_OK) return -EIO;
    
    // no error
    return 0;
}

void *fat16_open(struct disk *disk, struct path_part *path, FILE_MODE mode)
{
    void* response = (void*)0;

    if (mode != FILE_MODE_READ) // only can read right now
    {
        response = ERROR(-ERDONLY);
        goto out_one;
    }

    struct fat_file_descriptor *descriptor = kzalloc(sizeof(struct fat_file_descriptor)); // this is what we make a general file descriptor point to
    if (!descriptor)
    {
        response = ERROR(-ENOMEM);
        goto out_two;
    }
    
    struct fat_private* private_data = disk->fs_private;
    struct fat_directory_item* fatDirItem;

    fatDirItem = fat16_get_file(disk, private_data->root_directory, path);
    if (!fatDirItem)
    {
        response = ERROR(-EIO);
        goto out_two;
    }
    
    // copy the returnDirectoryItem from the fat16 file into the fat_file_descriptor, fat_dir_item entry.
    bytecpy((const char*)fatDirItem, (char*)&(descriptor->file), sizeof(struct fat_directory_item));
    
    // set data for file descriptor
    descriptor->pos = 0;
    descriptor->startingClusterNumber = fatDirItem->low_16_bits_first_cluster;

    return descriptor;

out_two:
    kfree(descriptor);
out_one:
    return response;
}

int fat16_resolve(struct disk* disk)
{
    // We need to make sure this is the right file system associated with the disk
    int response = 0;
    struct fat_private* private_data = kzalloc(sizeof(struct fat_private));
    fat16_init_private(disk, private_data);
    // Read boot sector into memory and check for signature

    if(diskstreamer_read(private_data->directory_stream, &private_data->headers, sizeof(private_data->headers)) != PEACHOS_ALL_OK) 
    {
        response = -EIO; // error io
        goto out_one;
    }
    
    if(private_data->headers.extended_header.signature != 0x29)
    {
        response = -EFSNOTUS; // error filesystem not us
        goto out_one;
    }

    // Bind the disk to the filesystem

    disk->fs_private = private_data; // Disk private data will now point to the fat16 private data
    disk->filesystem = &fat16_fs; // Set the disk filesystem

    // Initalize helper data

    struct Fat16Metadata* tempDataAccess = &private_data->helperData;
    struct fat_header* tempHeaderAccess = &private_data->headers.primary_header;

    tempDataAccess->optimalSectorReadBlockSize = 
        private_data->headers.primary_header.sectors_per_cluster < 8 ? private_data->headers.primary_header.sectors_per_cluster : 8;
    
    tempDataAccess->bootStartSect = 0; 
    
    tempDataAccess->fatStartSect = tempHeaderAccess->reserved_sectors;
    
    tempDataAccess->rootStartSect = 
        tempHeaderAccess->reserved_sectors + (tempHeaderAccess->sectors_per_fat * tempHeaderAccess->fat_copies);
    

    //! THIS IS A BS CALCULATION ONLY WORKS WHEN NICELY DIVIDED
    int calculation = tempHeaderAccess->root_dir_entries * sizeof(struct fat_directory_item);

    tempDataAccess->dataStartSect = 
        tempDataAccess->rootStartSect + (calculation / 512);


    // Now read the root directory
    response = readRootDirectory(disk);
    if(response < 0) 
        goto out_two;

    // We should now have the root directory into memory
    return 0;

out_two:
    disk->fs_private = 0;
    disk->filesystem = 0;
out_one:
    kfree(private_data);
    print("ERROR HAPPENED");
    return response;
}