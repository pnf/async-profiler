/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "writer.h"


Writer& Writer::operator<<(char c) {
    write(&c, 1);
    return *this;
}

Writer& Writer::operator<<(const char* s) {
    write(s, strlen(s));
    return *this;
}

Writer& Writer::operator<<(unsigned int n) {
    char buf[16];
    write(buf, snprintf(buf, sizeof(buf), "%u", n));
    return *this;
}

Writer& Writer::operator<<(int n) {
    char buf[16];
    write(buf, snprintf(buf, sizeof(buf), "%d", n));
    return *this;
}

Writer& Writer::operator<<(long n) {
    char buf[24];
    write(buf, snprintf(buf, sizeof(buf), "%ld", n));
    return *this;
}

FileWriter::FileWriter(const char* file_name) : _size(0) {
    _fd = open(file_name, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    _buf = (char*)malloc(BUF_SIZE);
}

FileWriter::FileWriter(int fd) : _fd(fd), _size(0) {
    _buf = (char*)malloc(BUF_SIZE);
}

FileWriter::~FileWriter() {
    flush(_buf, _size);
    free(_buf);
    if (_fd > STDERR_FILENO) {
        close(_fd);
    }
}

void FileWriter::flush(const char* data, size_t len) {
    while (len > 0) {
        ssize_t bytes = ::write(_fd, data, len);
        if (bytes < 0) {
            _err = errno;
            break;
        }
        data += bytes;
        len -= (size_t)bytes;
    }
}

void FileWriter::write(const char* data, size_t len) {
    if (_size + len > BUF_SIZE) {
        flush(_buf, _size);
        _size = 0;
        if (len > BUF_SIZE) {
            flush(data, len);
            return;
        }
    }
    memcpy(_buf + _size, data, len);
    _size += len;
}

// MS:
AtomicOutputFile::AtomicOutputFile(Arguments &args)  : _fname(args.file()), _tmpname(NULL) {
    if (args._atomicfile) {
        _tmpname = (char*) calloc(strlen(_fname) + strlen(args._atomicfile) + 10, sizeof(char*));
        sprintf(_tmpname, "%s-%sXXXXXX",_fname, args._atomicfile);
        mkstemp(_tmpname);
        Log::info("Opening temporary %s", _tmpname);
    }
    _fileWriter = new FileWriter(_tmpname ? _tmpname : _fname);
}

AtomicOutputFile::~AtomicOutputFile() {
    if (_fileWriter) {
        delete _fileWriter;
        _fileWriter = NULL;
        if (_tmpname) {
            Log::info("Moving %s to %s", _tmpname, _fname);
            rename(_tmpname, _fname);  // atomic
            free(_tmpname);
            _tmpname = NULL;
        }
    }
}

void AtomicOutputFile::write(const char *data, size_t len) {
    _fileWriter->write(data, len);
}

BufferWriter::BufferWriter(size_t capacity) : _size(0), _capacity(capacity) {
    _buf = (char*)malloc(capacity);
}

BufferWriter::~BufferWriter() {
    free(_buf);
}

void BufferWriter::write(const char* data, size_t len) {
    size_t new_size = _size + len;
    if (new_size > _capacity) {
        _capacity = new_size >= _capacity * 2 ? new_size : _capacity * 2;
        _buf = (char*)realloc(_buf, _capacity);
    }
    memcpy(_buf + _size, data, len);
    _size = new_size;
}

void CallbackWriter::write(const char* data, size_t len) {
    if (_output_callback != NULL) {
        _output_callback(data, len);
    }
}

void LogWriter::write(const char* data, size_t len) {
    Log::writeRaw(_logLevel, data, len);
}
