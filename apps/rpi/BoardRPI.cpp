﻿/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <cmath>

#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "BoardRPI.hpp"
#include "Log.hpp"

using namespace std;

#define SQN_DIR "/tmp/sqn/"

void BoardRPI::sleepSec(uint32_t sec)
{
    sleep(sec);
}

void BoardRPI::getOS(char *buf, int len)
{
    ifstream infile("/etc/os-release");

    string line;

    while (getline(infile, line)) {
        istringstream is_line(line);
        string key;
        if (getline(is_line, key, '=')) {
            string value;
            if (key.compare("PRETTY_NAME") == 0 && getline(is_line, value)) {
                value.erase(remove(value.begin(), value.end(), '"'), value.end());
                memcpy(buf, &value[0], (int) value.size() > len ? len : value.size());
                return;
            }
        }
    }
}

uint32_t BoardRPI::getUptime()
{
    struct sysinfo s_info;
    int error = sysinfo(&s_info);

    if (error != 0) {
        SD_LOG(LOG_ERR, "sysinfo error:  %d\n", error);
    }
    return s_info.uptime;
}

// return time instant in microseconds
uint64_t BoardRPI::getTimeInstant()
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    uint64_t ts = ((uint64_t) 1000000) * ((uint64_t) tp.tv_sec); // seconds to microseconds
    ts += (tp.tv_nsec / 1000);

    return ts;
}

uint32_t BoardRPI::getElapsedTime(uint64_t start_time)
{
    return getTimeInstant() - start_time;
}

uint32_t BoardRPI::getTimestamp()
{
    long ms;  // Milliseconds
    time_t s; // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    s  = spec.tv_sec;
    ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
    if (ms > 999) {
        s++;
        ms = 0;
    }
    return s;
}

#if 0
uint32_t BoardRPI::getTemperature()
{
    static uint32_t temp = 25000;

    // If the pi has a pimoroni board attached, follow the instructions in
    // https://learn.pimoroni.com/article/getting-started-with-enviro-plus
    // to install the necessary python libraries. Then run ~/sediment/utils/pi-sediment.py 
    // before SEDIMENT prover is started. 
    // The script writes a temperautre reading per second to /tmp/temperature.txt.
    int fd = open("/tmp/temperature.txt", O_RDONLY);
    if (fd == -1) {
        // otherwise read the cpu temperature
        fd = open("/sys/class/thermal/thermal_zone0/temp", O_RDONLY);
        if (fd == -1) {
            // otherwise generate a random value
            temp += (rand() % 2000) - 1000;
            return temp;
        }
    }

    char buf[256] = "";
    ssize_t nb = read(fd, buf, sizeof(buf));
    close(fd);

    buf[nb] = '\0';

    return (uint32_t) atoi(buf);
}

uint32_t BoardRPI::getHumidity()
{
    static uint32_t temp = 60000;

    // If the pi has a pimoroni board attached, follow the instructions in
    // https://learn.pimoroni.com/article/getting-started-with-enviro-plus
    // to install the necessary python libraries. Then run ~/sediment/utils/pi-sediment.py 
    // before SEDIMENT prover is started. 
    // The script writes a humidity reading per second to /tmp/humidity.txt.
    int fd = open("/tmp/humidity.txt", O_RDONLY);
    if (fd == -1) {
        // otherwise generate a random value
        temp += (rand() % 3000) - 1000;
        return temp;
    }

    char buf[256] = "";
    ssize_t nb = read(fd, buf, sizeof(buf));
    close(fd);

    buf[nb] = '\0';

    return (uint32_t) atoi(buf);
}
#endif

int BoardRPI::getAllSensors(uint32_t sqn, char *buf, uint32_t len) 
{
    // If the pi has a pimoroni board attached, follow the instructions in
    // https://learn.pimoroni.com/article/getting-started-with-enviro-plus
    // to install the necessary python libraries. Then run ~/sediment/utils/pi-sediment.py 
    // before SEDIMENT prover is started. 
    // The script writes all readings per second to /tmp/sensors.txt.
    int fd = open("/tmp/sensors.txt", O_RDONLY);
    if (fd == -1) {
        return Board::getAllSensors(sqn, buf, len);
    }
    ssize_t n = sprintf(buf, "%d,", sqn);
    ssize_t nb = read(fd, buf + n, len);
    ssize_t sum = n + nb;
    buf[sum] = '\0';
    close(fd);

    return sum;
}

static void get_pathname(char *buf, char *pathname)
{
    int i = 0;

    for (int k = 0; k < 5; k++) {
        while (!isspace(buf[i])) {
            i++;
        }

        while (isspace(buf[i])) {
            i++;
        }
    }

    int orig = i;
    while (!isspace(buf[i])) {
        pathname[i - orig] = buf[i];
        i++;
    }
    pathname[i - orig] = '\0';
}

#if 0
static int get_pid(string &keyword)
{
    const int BUF_SIZE = 256;
    char buf[BUF_SIZE];

    sprintf(buf, "ps aux | grep %s | grep -v grep | grep -v 'sediment/' | awk '{print $2}'", keyword.c_str());

    FILE *fp;
    if ((fp = popen(buf, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    bool found = false;
    while (fgets(buf, BUF_SIZE, fp) != NULL) {
        printf("%s\n", buf);
        if (found) {
            found = false;
            SD_LOG(LOG_ERR, "multiple process with the same keyword: %s", keyword.c_str());
            break;
        }
        found = true;
    }

    if (pclose(fp)) {
        printf("Command not found or exited with error status\n");
        return -1;
    }

    if (!found)
        return -1;

    return atoi(buf);
}

#endif // if 0

void * map_file(char *filename, uint32_t *blockSize)
{
    void *ret = NULL;
    long fileSize;

    int fd = open(filename, O_RDONLY);

    if (fd < 0) {
        SD_LOG(LOG_ERR, "Cannot open file: %s", filename);
        return NULL;
    }

    // Obtain the filesize.
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        SD_LOG(LOG_ERR, "fstat error: %s", filename);
        goto out;
    }

    fileSize = sb.st_size;
    if (fileSize < *blockSize) {
        SD_LOG(LOG_ERR, "requested block size is too big: %d (file) v.s. %d (requested)",
          fileSize, *blockSize);
        *blockSize = fileSize;
    }

    ret = (unsigned char *) mmap(0, fileSize, PROT_READ, MAP_SHARED, fd, 0);
    if (ret == NULL) {
        SD_LOG(LOG_ERR, "mmap error: %s", filename);
    }
out:
    close(fd);
    return ret;
}

void * BoardRPI::getStartingAddr(string &lib_keyword, uint32_t *blockSize)
{
    if (lib_keyword.compare("sediment")) {
        return map_file((char *) lib_keyword.c_str(), blockSize);
    }

    FILE *fp;
    const int LINE_SIZE = 256;
    char buf[LINE_SIZE];

    pid_t pid = getpid();
    // pid_t pid = get_pid(library_keyword);
    if (pid < 0)
        return NULL;

    sprintf(buf, "/proc/%d/maps", pid);
    if ((fp = fopen(buf, "r")) == NULL) {
        SD_LOG(LOG_ERR, "Failed to open config file %s", buf);
        return NULL;
    }

    char keyword[64];
    sprintf(keyword, "%s", executable.c_str());

    void *ret = NULL;
    while (fgets(buf, LINE_SIZE, fp) != NULL) {
        if (!strstr(buf, keyword))
            continue;

        char filename[128];
        get_pathname(buf, filename);

        ret = map_file(filename, blockSize);
        break;
    }
    fclose(fp);
    return ret;
}

static void intFile(char *cat, char *type, string id, char *filename)
{
    system("mkdir -p " SQN_DIR);
    sprintf(filename, SQN_DIR "%s-%s-%s", cat, type, id.c_str());
}

static void saveInt(char *cat, char *type, string id, uint32_t sqn)
{
    char filename[128];

    intFile(cat, type, id, filename);

    int fd = open(filename, O_WRONLY | O_CREAT, 0777);
    if (fd == -1) {
        SD_LOG(LOG_ERR, "cannot open %s", filename);
        return;
    }

    char buf[16] = "";
    sprintf(buf, "%d", sqn);
    write(fd, buf, sizeof(buf));
    close(fd);
}

uint32_t loadSqn(char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        SD_LOG(LOG_DEBUG, "creating %s", filename);
        return 0;
    }

    char buf[16] = "";
    ssize_t nb   = read(fd, buf, sizeof(buf));
    close(fd);

    buf[nb] = '\0';

    return (uint32_t) atoi(buf);
}

void BoardRPI::saveAttestSqn(uint32_t sqn)
{
    saveInt((char *)"sqn", (char *)"attest", id, sqn);
}

uint32_t BoardRPI::getAttestSqn()
{
    char filename[128];

    intFile((char *)"sqn", (char *)"attest", id, filename);
    return loadSqn(filename);
}

void BoardRPI::saveSeecSqn(uint32_t sqn)
{
    saveInt((char *)"sqn", (char *)"seec", id, sqn);
}

uint32_t BoardRPI::getSeecSqn()
{
    char filename[128];

    intFile((char *)"sqn", (char *)"seec", id, filename);
    return loadSqn(filename);
}

void BoardRPI::saveRevCheckSqn(uint32_t sqn)
{
    saveInt((char *)"sqn", (char *)"rev-check", id, sqn);
}

uint32_t BoardRPI::getRevCheckSqn()
{
    char filename[128];

    intFile((char *)"sqn", (char *)"rev-check", id, filename);
    return loadSqn(filename);
}

void BoardRPI::saveRevAckSqn(uint32_t sqn)
{
    saveInt((char *)"sqn", (char *)"rev-ack", id, sqn);
}

uint32_t BoardRPI::getRevAckSqn()
{
    char filename[128];

    intFile((char *)"sqn", (char *)"rev-ack", id, filename);
    return loadSqn(filename);
}

uint32_t BoardRPI::getReportInterval()
{
    char filename[128];

    intFile((char *)"report", (char *)"interval", id, filename);
    return loadSqn(filename);
}

void BoardRPI::saveReportInterval(uint32_t interval)
{
    saveInt((char *)"report", (char *)"interval", id, interval);
}

/**
 * allocate a memory block to collect the configurations.
 * caller is responsible for freeing the buffer.
*/
char* BoardRPI::getConfigBlocks(int *len) 
{
    // for demo purpose, the reporting interval is reloaded from /tmp/sqn/report-interval-<id>
    // instead of the config file.
    char *gatherConfigBlocks(const string &filename, int *len, int **report_interval);  // allocation here
    int *report_interval;
    char *block = gatherConfigBlocks(configFile, len, &report_interval);

    *report_interval = getReportInterval();
    return block;
}
