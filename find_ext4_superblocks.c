/*
 * find_ext4_superblocks.c - Find ext4 superblocks in disk images
 *
 * Reads file in 4MB chunks and searches for ext4 superblocks.
 * Prints essential information about found superblocks.
 *
 * Compile: gcc -o find_ext4_superblocks find_ext4_superblocks.c
 * Usage: ./find_ext4_superblocks <disk_image_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <ext2fs/ext2_fs.h> // For ext4 superblock structure

#define CHUNK_SIZE (4 * 1024 * 1024) // 4MB chunks
#define EXT4_MAGIC 0xEF53
#define SUPERBLOCK_SIZE 1024
#define SUPERBLOCK_MAGIC_OFFSET 56

void format_size(uint64_t bytes, char *buffer, size_t buffer_size)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int unit = 0;
    double size = (double)bytes;

    while (size >= 1024.0 && unit < 5)
    {
        size /= 1024.0;
        unit++;
    }

    if (unit == 0)
    {
        snprintf(buffer, buffer_size, "%.0f %s", size, units[unit]);
    }
    else
    {
        snprintf(buffer, buffer_size, "%.1f %s", size, units[unit]);
    }
}

void print_superblock_info(const struct ext2_super_block *sb, off_t file_offset)
{
    char fs_size_str[64];
    char free_space_str[64];
    uint32_t block_size;
    uint64_t fs_size_bytes;
    uint64_t free_bytes;

    // Calculate block size
    block_size = 1024 << sb->s_log_block_size;

    // Calculate filesystem size
    fs_size_bytes = (uint64_t)sb->s_blocks_count * block_size;

    // Calculate free space
    free_bytes = (uint64_t)sb->s_free_blocks_count * block_size;

    format_size(fs_size_bytes, fs_size_str, sizeof(fs_size_str));
    format_size(free_bytes, free_space_str, sizeof(free_space_str));

    time_t tmp_time_t;

    printf("================== EXT4 SUPERBLOCK FOUND ==================\n");
    printf("File offset:          %ld bytes (0x%lx)\n", file_offset, file_offset);
    // printf("Magic number:         0x%04x\n", sb->s_magic);
    printf("Revision level:       %u\n", sb->s_rev_level);
    printf("Block group number:   %u\n", sb->s_block_group_nr);
    printf("Volume name:          %.16s\n", sb->s_volume_name);
    printf("Last mounted on:      %.64s\n", sb->s_last_mounted);
    printf("Mount count:          %u\n", sb->s_mnt_count);
    tmp_time_t = (time_t)sb->s_mkfs_time;
    printf("Creation time:        %s", ctime(&tmp_time_t));
    tmp_time_t = (time_t)sb->s_wtime;
    printf("Write time:           %s", ctime(&tmp_time_t));
    printf("Filesystem state:     %u %s\n", sb->s_state,
           (sb->s_state == 1) ? "(clean)" : (sb->s_state == 2) ? "(errors)"
                                                               : "(unknown)");
    printf("Block size:           %u bytes\n", block_size);
    printf("Total blocks:         %u\n", sb->s_blocks_count);
    // printf("Free blocks:          %u\n", sb->s_free_blocks_count);
    // printf("Reserved blocks:      %u\n", sb->s_r_blocks_count);
    printf("Filesystem size:      %s (%lu bytes)\n", fs_size_str, fs_size_bytes);
    printf("Free space:           %s (%lu bytes)\n", free_space_str, free_bytes);
    printf("Total inodes:         %u\n", sb->s_inodes_count);
    // printf("Free inodes:          %u\n", sb->s_free_inodes_count);
    printf("Inodes per group:     %u\n", sb->s_inodes_per_group);
    printf("Blocks per group:     %u\n", sb->s_blocks_per_group);
    printf("First data block:     %u\n", sb->s_first_data_block);

    // Check if this looks like a primary superblock
    if (file_offset == 1024)
    {
        printf("*** PRIMARY SUPERBLOCK (canonical location) ***\n");
    }

    printf("===========================================================\n\n");
    fflush(stdout);
}

int search_superblocks_in_chunk(const unsigned char *buffer, size_t buffer_size,
                                off_t chunk_offset)
{
    size_t i;
    int found_count = 0;

    // Search for magic number in the chunk
    for (i = 0; i <= buffer_size - SUPERBLOCK_SIZE; i++)
    {
        // Check if there's a magic number at offset 56 from current position
        if (i + SUPERBLOCK_MAGIC_OFFSET + 1 < buffer_size)
        {
            uint16_t magic = *(uint16_t *)(buffer + i + SUPERBLOCK_MAGIC_OFFSET);

            if (magic == EXT4_MAGIC)
            {
                // Found potential superblock, extract information
                if (i + SUPERBLOCK_SIZE <= buffer_size)
                {
                    const struct ext2_super_block *sb = (const struct ext2_super_block *)(buffer + i);
                    off_t file_offset = chunk_offset + i;

                    /*
                    struct tm t;
                    t.tm_year = 2000 - 1900; // Year - 1900
                    t.tm_mon = 0;           // Month, where 0 = jan
                    t.tm_mday = 1;          // Day of the month
                    t.tm_hour = 0;
                    t.tm_min = 0;
                    t.tm_sec = 1;
                    t.tm_isdst = -1; // Is DST on? 1 = yes, 0 = no, -1 = unknown
                    time_t year_2000 = mktime(&t);

                    uint32_t block_size;
                    uint64_t fs_size_bytes;

                    // Calculate block size
                    block_size = 1024 << sb->s_log_block_size;

                    // Calculate filesystem size
                    fs_size_bytes = (uint64_t)sb->s_blocks_count * block_size;
*/
                    // check for QNAP signature
                    if (sb->s_checksum == 0x50414E51 // 'QNAP' signature
                                                     /*
                                                     sb->s_block_group_nr == 0 && // Primary superblock check
                                                     sb->s_blocks_count > 0 && sb->s_blocks_count >= sb->s_free_blocks_count &&
                                                     sb->s_inodes_count > 0 &&
                                                     sb->s_mnt_count > 0 &&
                                                     sb->s_inodes_per_group > 0 &&
                                                     sb->s_mkfs_time >= year_2000 && sb->s_mkfs_time <= time(NULL) &&
                                                     sb->s_wtime >= sb->s_mkfs_time && sb->s_wtime <= time(NULL) &&
                                                     fs_size_bytes / 1024 / 1024 / 1024 / 1024 > 1 &&  // filesystem size > 1TB
                                                     fs_size_bytes / 1024 / 1024 / 1024 / 1024 < 100 && // filesystem size < 100TB
                                                     (sb->s_rev_level == EXT2_GOOD_OLD_REV || sb->s_rev_level == EXT2_DYNAMIC_REV)
                                                     */
                    )
                    {

                        print_superblock_info(sb, file_offset);
                        found_count++;

                        // Skip ahead to avoid finding overlapping matches
                        i += SUPERBLOCK_SIZE - 1;
                    }
                }
            }
        }
    }

    return found_count;
}

int main(int argc, char *argv[])
{
    FILE *file;
    unsigned char *buffer;
    size_t bytes_read;
    off_t total_bytes_read = 0;
    off_t file_size;
    int total_found = 0;
    struct stat st;

    time_t current_time;
    struct tm *time_info;
    char timestamp[100];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <disk_image_file>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/sda1\n", argv[0]);
        fprintf(stderr, "Example: %s disk.img\n", argv[0]);
        return 1;
    }

    // Get file size
    if (stat(argv[1], &st) == -1)
    {
        perror("stat");
        return 1;
    }
    file_size = st.st_size;

    // Open file
    file = fopen(argv[1], "rb");
    if (!file)
    {
        perror("fopen");
        return 1;
    }

    // Allocate buffer for chunks
    buffer = malloc(CHUNK_SIZE);
    if (!buffer)
    {
        fprintf(stderr, "Error: Cannot allocate %d bytes for buffer\n", CHUNK_SIZE);
        fclose(file);
        return 1;
    }

    time(&current_time);
    time_info = localtime(&current_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    printf("Starting: %s\n", timestamp);
    printf("Scanning file: %s\n", argv[1]);
    printf("File size: ");
    char size_str[64];
    format_size(file_size, size_str, sizeof(size_str));
    printf("%s (%ld bytes)\n", size_str, file_size);
    printf("Chunk size: %d MB\n", CHUNK_SIZE / (1024 * 1024));
    printf("Searching for ext4 superblocks...\n\n");
    fflush(stdout);

    // Read and process chunks
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0)
    {
        // Search for superblocks in this chunk
        int found_in_chunk = search_superblocks_in_chunk(buffer, bytes_read, total_bytes_read);
        total_found += found_in_chunk;
        total_bytes_read += bytes_read;

        // Print progress for large files every ~400GB or on last chunk
        if (total_bytes_read % ((long int)CHUNK_SIZE * 100000) == 0 || bytes_read < CHUNK_SIZE)
        {
            time(&current_time);
            time_info = localtime(&current_time);
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);
            double progress = (double)total_bytes_read / file_size * 100.0;
            printf("[%s] Progress: %.1f%% (%ld of %ld GB)\n",
                   timestamp, progress, total_bytes_read / 1024 / 1024 / 1024, file_size / 1024 / 1024 / 1024);
            fflush(stdout);
        }
    }

    if (ferror(file))
    {
        perror("fread");
        free(buffer);
        fclose(file);
        return 1;
    }

    printf("\nScan completed successfully.\n");
    printf("Total bytes read: %ld\n", total_bytes_read);
    printf("Total ext4 superblocks found: %d\n", total_found);

    free(buffer);
    fclose(file);
    return 0;
}
