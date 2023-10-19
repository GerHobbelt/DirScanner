#define UNICODE 1
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>       /* clock_t, clock, CLOCKS_PER_SEC */
#include <algorithm>
#include <assert.h>
#include <string>

#include "ntfs_ads_io.h"

#undef max
#undef min

// Make sure we support Long Paths:
#if defined(MAX_PATH) && MAX_PATH > 1500
#error "Bump our Large-File-Names-MAX_PATH replacement define at the line further below!"
#endif
//#undef MAX_PATH
//#define MAX_PATH     1500


using namespace std;


static void barf_on_assert_failure(const char *msg)
{                                   
    fprintf(stderr, "assertion failed: %s\n", msg); 
    exit(666);                      
}      

#define ASSERT(t)                       \
    if (!(t))                           \
    {                                   \
        barf_on_assert_failure(#t);     \
    }      



// overloaded helpers for the stringbuffer template class:

static inline void sb__strcpy__(wchar_t* dest, size_t dmax, const wchar_t* src)
{
	wcscpy_s(dest, dmax, src);
}
static inline void sb__strcpy__(char* dest, size_t dmax, const char* src)
{
	strcpy_s(dest, dmax, src);
}


template <class T>
class stringbuffer
{
public:
	stringbuffer()
	{
		reserve();
	}
	stringbuffer(size_t _size)
	{
		reserve(_size);
	}

	~stringbuffer()
	{
		ASSERT(buf != nullptr);
		if (buf != prepbuf)
		{
			free(buf);
		}
	}

	//
	// disallow the default copy constructor, copy assignment,
	// move constructor, and move assignment functions: only allow
	// our explicit implementation where available.
	//

	stringbuffer(const stringbuffer<T> &o) = delete;             
	//stringbuffer<T> & operator=(const stringbuffer<T> &o) = delete; 
	stringbuffer(stringbuffer<T> &&o) noexcept = delete;                  
	stringbuffer<T> & operator=(stringbuffer<T> &&o) noexcept = delete;

	void reserve(size_t _size = 0)
	{
		_size++;  // account for space of extra NUL sentinel 
		ASSERT(_size < ((DWORD)~0LL));

		// only grow...
		if (_size <= size)
			return;

		if (_size <= MAX_PATH + 1)
		{
			// we're being invoked from a constructor: alias the built-in buffer and be done.

			buf = prepbuf;
			size = MAX_PATH + 1;

			buf[0] = 0;
			buf[size - 1] = 0;
			buf[size - 2] = 0;
		}
		else 
		{
			// minor optimization: quantize the resized size to 64 byte chunks:
			_size += 63;
			_size &= ~63;  // _size MOD 64

			if (buf == nullptr)
			{
				// we're being invoked from a constructor: allocate and be done.

				buf = (T *)malloc(_size * sizeof(T));
				if (!buf)
				{
					fwprintf(stderr, L"FATAL: Out of memory.\n");
					exit(666);
				}

				buf[0] = 0;
				buf[_size - 1] = 0;
				buf[_size - 2] = 0;
			}
			else if (buf == prepbuf)
			{
				// we're growing from prepbuf into a larger heap-allocated buffer:
				// copy the content!
			
				buf = (T *)malloc(_size * sizeof(T));
				if (!buf)
				{
					fwprintf(stderr, L"FATAL: Out of memory.\n");
					exit(666);
				}

				buf[_size - 1] = 0;
				buf[_size - 2] = 0;

				sb__strcpy__(buf, _size, prepbuf);
			}
			else
			{
				// we're growing the heap-allocated space still further.

				buf = (T *)realloc(buf, _size * sizeof(T));
				if (!buf)
				{
					fwprintf(stderr, L"FATAL: Out of memory.\n");
					exit(666);
				}

				// as we grow in steps of 64 bytes each, we can safely punch the double sentinel at the end of the new buffer again:
				buf[_size - 1] = 0;
				buf[_size - 2] = 0;
			}

			size = (DWORD)_size;
		}
	}
	
	// reserve space for stuff we're about to append
	void reserve_extra(size_t add)
	{
		add += wcslen(buf);
		reserve(add);
	}

	operator T *() 
	{
		return buf;
	}
	const T *c_str() const
	{
		return buf;
	}
	T *data() const
	{
		return buf;
	}

	DWORD space() const
	{
		// we're tricking any using code by telling them the space available is less than reality:
		// this way we can be pretty sure our NUL sentinel will survive.
		// (unless the calling code does buffer overflows for a living)
		return size - 1;
	}

	stringbuffer<T> & operator =(const WCHAR *str)
	{
		auto l = wcslen(str);
		reserve(l);
		ASSERT(size > l);
		wcscpy_s(buf, size, str);
		return *this;
	}

	stringbuffer<T> & operator =(const stringbuffer<T> &src_obj)
	{
		const T *src = src_obj.c_str();
		auto l = wcslen(src);
		reserve(l);
		ASSERT(size > l);
		wcscpy_s(buf, size, src);
		return *this;
	}

protected:
	T prepbuf[MAX_PATH + 1];		// optimization: don't have to allocate when we need this much, or less...

	T *    buf  {nullptr};
	DWORD  size {0};
};


typedef stringbuffer<char>    charbuffer;
typedef stringbuffer<wchar_t> wcharbuffer;



static NtQueryInformationFile_f NtQueryInformationFile;
static RtlNtStatusToDosError_f RtlNtStatusToDosError;



// hack: unused attributes bits used by us to signal hardlinks are present
#define FILE_ATTRIBUTE_HAS_MULTIPLE_SITES  0x20000000U
#define FILE_ATTRIBUTE_HARDLINK            0x40000000U
#define FILE_ATTRIBUTE_HAS_ADS             0x80000000U


#define PRIME_MODULUS    16769023

typedef struct HashtableEntry
{
	uint32_t hash			{0};
    DWORD attrs				{0};
    const WCHAR* path       {nullptr};
    uint64_t filesize       {0};
	FILETIME timestamp		{0};
} HashtableEntry;



//
// Globals
//
clock_t ticks;
FILE* output = NULL;
CPINFOEXW CPInfo = { 0 };
int cvtErrors = 0;
int conciseOutput = 0;
int quiet = 0;
ULONG FilesMatched = 0;
ULONG DotsPrinted = 0;
BOOLEAN PrintDirectoryOpenErrors = FALSE;
HashtableEntry UniqueFilePaths[PRIME_MODULUS];
HashtableEntry OutputFilePaths[PRIME_MODULUS];

//----------------------------------------------------------------------
//
// PrintNtError
//
// Formats an error message for the last native error.
//
//----------------------------------------------------------------------
void PrintNtError(NTSTATUS status)
{
    WCHAR* errMsg;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, RtlNtStatusToDosError(status),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errMsg, 0, NULL);
    fwprintf(stderr, L"\r%s\n", errMsg);
    LocalFree(errMsg);
}

//--------------------------------------------------------------------
//
// PrintWin32Error
// 
// Translates a Win32 error into a text equivalent
//
//--------------------------------------------------------------------
void PrintWin32Error(DWORD ErrorCode)
{
    LPTSTR lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, ErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);
    fwprintf(stderr, L"\r%s\n", lpMsgBuf);
    LocalFree(lpMsgBuf);
}

//----------------------------------------------------------------------
//
// EnableTokenPrivilege
//
// Enables the load driver privilege
//
//----------------------------------------------------------------------
BOOL EnableTokenPrivilege(LPCWSTR PrivilegeName)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE	hToken;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

    //
    // Get debug privilege
    //
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, PrivilegeName, &luid))
        return FALSE;

    //
    // first pass.  get current privilege setting
    //
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        &tpPrevious,
        &cbPrevious
    );

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    //
    // second pass.  set privilege based on previous setting
    //
    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = luid;
    tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tpPrevious,
        cbPrevious,
        NULL,
        NULL
    );

    return GetLastError() == ERROR_SUCCESS;
}


//--------------------------------------------------------------------
//
// Parse Mask
//
//--------------------------------------------------------------------
DWORD ParseMask(WCHAR* mask)
{
    DWORD attrs = 0;
    int negate = 0;

    if (!mask)
    {
        fwprintf(stderr, L"Missing attributes mask parameter value.\n");
        exit(1);
    }

    while (*mask)
    {
        switch (*mask)
        {
        case '!':
        case '~':
            negate = 1;
            break;

        case 'R':
            attrs |= FILE_ATTRIBUTE_READONLY;
            break;

        case 'H':
            attrs |= FILE_ATTRIBUTE_HIDDEN;
            break;

        case 'S':
            attrs |= FILE_ATTRIBUTE_SYSTEM;
            break;

        case 'D':
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
            break;

        case 'A':
            attrs |= FILE_ATTRIBUTE_ARCHIVE;
            break;

        case 'd':
            attrs |= FILE_ATTRIBUTE_DEVICE;
            break;

        case 'N':
            attrs |= FILE_ATTRIBUTE_NORMAL;
            break;

        case 'T':
            attrs |= FILE_ATTRIBUTE_TEMPORARY;
            break;

        case 's':
            attrs |= FILE_ATTRIBUTE_SPARSE_FILE;
            break;

        case 'h':
            attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
            break;

        case 'C':
            attrs |= FILE_ATTRIBUTE_COMPRESSED;
            break;

        case 'O':
            attrs |= FILE_ATTRIBUTE_OFFLINE;
            break;

        case 'i':
            attrs |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
            break;

        case 'E':
            attrs |= FILE_ATTRIBUTE_ENCRYPTED;
            break;

        case 't':
            attrs |= FILE_ATTRIBUTE_INTEGRITY_STREAM;
            break;

        case 'V':
            attrs |= FILE_ATTRIBUTE_VIRTUAL;
            break;

        case 'b':
            attrs |= FILE_ATTRIBUTE_NO_SCRUB_DATA;
            break;

        case 'a':
            attrs |= FILE_ATTRIBUTE_EA;
            break;

        case 'P':
            attrs |= FILE_ATTRIBUTE_PINNED;
            break;

        case 'u':
            attrs |= FILE_ATTRIBUTE_UNPINNED;
            break;

        case 'c':
            attrs |= FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
            break;

        case 'o':
            attrs |= FILE_ATTRIBUTE_RECALL_ON_OPEN;
            break;

        case 'l':
            attrs |= FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL;
            break;

        case 'L':
            attrs |= FILE_ATTRIBUTE_HAS_MULTIPLE_SITES;
            break;

        case 'X':
            attrs |= FILE_ATTRIBUTE_HARDLINK;
            break;

		case 'z':
			attrs |= FILE_ATTRIBUTE_HAS_ADS;
			break;

        case 'M':
        case '?':
            attrs |= ~(0
                | FILE_ATTRIBUTE_READONLY
                | FILE_ATTRIBUTE_HIDDEN
                | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_DIRECTORY
                | FILE_ATTRIBUTE_ARCHIVE
                | FILE_ATTRIBUTE_DEVICE
                | FILE_ATTRIBUTE_NORMAL
                | FILE_ATTRIBUTE_TEMPORARY
                | FILE_ATTRIBUTE_SPARSE_FILE
                | FILE_ATTRIBUTE_REPARSE_POINT
                | FILE_ATTRIBUTE_COMPRESSED
                | FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
                | FILE_ATTRIBUTE_ENCRYPTED
                | FILE_ATTRIBUTE_INTEGRITY_STREAM
                | FILE_ATTRIBUTE_VIRTUAL
                | FILE_ATTRIBUTE_NO_SCRUB_DATA
                | FILE_ATTRIBUTE_EA
                | FILE_ATTRIBUTE_PINNED
                | FILE_ATTRIBUTE_UNPINNED
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL
                | FILE_ATTRIBUTE_HAS_MULTIPLE_SITES
                | FILE_ATTRIBUTE_HARDLINK
				| FILE_ATTRIBUTE_HAS_ADS
				);
            break;

        default:
            fwprintf(stderr, L"\rError reading attributes mask: unknown attribute %C.\n", *mask);
            exit(1);
        }
        mask++;
    }

    if (negate)
        attrs = ~attrs;

    return attrs;
}

const CHAR *FileAttributes2String(CHAR attr_str[32], DWORD attrs)
{
	CHAR *s = attr_str;

#define MARK(flag, marker)										\
	*s++ = ((attrs & (flag)) ? (marker) : '.');                 \
	attrs &= ~(flag);

	MARK(FILE_ATTRIBUTE_READONLY, 'R');
	MARK(FILE_ATTRIBUTE_HIDDEN, 'H');
	MARK(FILE_ATTRIBUTE_SYSTEM, 'S');
	MARK(FILE_ATTRIBUTE_DIRECTORY, 'D');
	MARK(FILE_ATTRIBUTE_ARCHIVE, 'A');
	MARK(FILE_ATTRIBUTE_DEVICE, 'd');
	MARK(FILE_ATTRIBUTE_NORMAL, 'N');
	MARK(FILE_ATTRIBUTE_TEMPORARY, 'T');
	MARK(FILE_ATTRIBUTE_SPARSE_FILE, 's');
	MARK(FILE_ATTRIBUTE_REPARSE_POINT, 'h');
	MARK(FILE_ATTRIBUTE_COMPRESSED, 'C');
	MARK(FILE_ATTRIBUTE_OFFLINE, 'O');
	MARK(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, 'i');
	MARK(FILE_ATTRIBUTE_ENCRYPTED, 'E');
	MARK(FILE_ATTRIBUTE_INTEGRITY_STREAM, 't');
	MARK(FILE_ATTRIBUTE_VIRTUAL, 'V');
	MARK(FILE_ATTRIBUTE_NO_SCRUB_DATA, 'b');
	MARK(FILE_ATTRIBUTE_EA, 'a');
	MARK(FILE_ATTRIBUTE_PINNED, 'P');
	MARK(FILE_ATTRIBUTE_UNPINNED, 'u');
	MARK(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, 'c');
	MARK(FILE_ATTRIBUTE_RECALL_ON_OPEN, 'o');
	MARK(FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL, 'l');
	MARK(FILE_ATTRIBUTE_HAS_MULTIPLE_SITES | FILE_ATTRIBUTE_HARDLINK, (attrs & FILE_ATTRIBUTE_HARDLINK) ? 'L' : '*');
	MARK(FILE_ATTRIBUTE_HAS_ADS, 'Z');
	MARK(~0, '?');		// catch-all for any remaining, unknown flags
    *s = 0;

    return attr_str;
}

void FileSize2String(CHAR fsize_str[32], uint64_t filesize)
{
    snprintf(fsize_str, 32, "%21I64u", filesize);
    ASSERT(strnlen(fsize_str, 32) < 32);
}

void FileTime2String(CHAR fsize_str[32], FILETIME timestamp)
{
	FILETIME localtime;
	SYSTEMTIME tm;
	// use local time: this ensures the date&time shown matches the timestamp shown in Windows Explorer.
	if (FileTimeToLocalFileTime(&timestamp, &localtime) &&
	    FileTimeToSystemTime(&localtime, &tm))
	{
		snprintf(fsize_str, 32, "%04u-%02u-%02uT%02u:%02u:%02u.%04u", tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond, tm.wMilliseconds);
		ASSERT(strnlen(fsize_str, 32) < 32);
	}
	else
	{
		strcpy(fsize_str, "---INVALID-TIMESTAMP---");
		ASSERT(strnlen(fsize_str, 32) < 32);
	}
}


// Produce a hash 1..PRIME (NOTE the 1-based number: this makes it easy and fast to detect empty (hash=0) slots!)
unsigned int CalculateHash(const WCHAR* str)
{
    uint64_t hash = 5381;

    while (*str)
    {
        uint64_t c = (*str++) & 0xFFFF;

        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return (unsigned int)(hash % PRIME_MODULUS) + 1;
}



// Make sure all path separators are windows standard: '\'.
// Also reduce duplicate path separators, e.g. '//' and '///' into single ones: '\'
// Rewrites string IN-PLACE.
void NormalizePathSeparators(wcharbuffer &src)
{
	WCHAR *str = src;
    WCHAR* start = str;
    WCHAR* dst = str;
    while (*str)
    {
        WCHAR c = *str++;
        if (c == '/')
            c = '\\';
        // bunch consecutive '\' separators EXCEPT at the start, where we may have '\\?\'!
        if (c == '\\' && str - start >= 2)
        {
            WCHAR c2;
            do
            {
                c2 = *str++;
                if (c2 == '/')
                    c2 = '\\';
            } while (c2 == '\\');
            str--;
        }
        *dst++ = c;
    }
    *dst = 0;
}



void CvtUTF16ToUTF8(charbuffer &dst, const WCHAR* src)
{
    // https://docs.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
    int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS | WC_NO_BEST_FIT_CHARS, src, -1, NULL, 0, NULL, NULL);
    if (len == 0)
    {
        fwprintf(stderr, L"\rWARNING: Error while converting string to UTF8 for output to file. The data will be sanitized!\n    Offending string: \"%s\"\n", src);
        PrintWin32Error(GetLastError());
        len = WideCharToMultiByte(CP_UTF8, WC_NO_BEST_FIT_CHARS, src, -1, NULL, 0, NULL, NULL);
        cvtErrors++;
    }
	dst.reserve(len + 8 /* a little slack + space for terminating sentinel */ );

	char *p = dst;
    p[0] = 0;
    int rv = WideCharToMultiByte(CP_UTF8, WC_NO_BEST_FIT_CHARS, src, -1, p, (int)dst.space(), NULL, NULL);
    if (rv == 0)
    {
        fwprintf(stderr, L"\rERROR: Error while converting string to UTF8 for output to file.\n    Offending string: \"%s\"\n", src);
        PrintWin32Error(GetLastError());
        exit(3);
    }
}



void CloseOutput(void)
{
    if (output && output != stdout)
    {
        // Dump the hash table content as UTF8 to file.
        // And clear the hash table too! It may be re-used in another round.
        for (int i = 0; i < PRIME_MODULUS; i++)
        {
            HashtableEntry *slot = &OutputFilePaths[i];
            if (!slot->hash)
                continue;
            ASSERT(slot->path != NULL);

            // write filename as UTF8 and check it for sanity while we do:
            charbuffer fname;
            CvtUTF16ToUTF8(fname, slot->path);
            if (conciseOutput)
            {
                fprintf(output, "%s\n", fname.c_str());
            }
            else
            {
                DWORD attrs = slot->attrs;
                CHAR attr_str[32];
				CHAR fsize_str[32];
				CHAR time_str[32];

				FileAttributes2String(attr_str, attrs);
				FileSize2String(fsize_str, slot->filesize);
				FileTime2String(time_str, slot->timestamp);

                fprintf(output, "$%08lx:%s %s %s %s\n", (unsigned long)attrs, attr_str, fsize_str, time_str, fname.c_str());
            }

            free((void *)slot->path);
        }

        fclose(output);

        memset(OutputFilePaths, 0, sizeof(OutputFilePaths));
    }
    output = NULL;
}


int TestAndAddInHashtable(const WCHAR* str, const DWORD attrs, uint64_t filesize, FILETIME timestamp, HashtableEntry *UniqueFilePaths)
{
    unsigned int hash = CalculateHash(str);
    unsigned int idx = hash - 1;
    HashtableEntry* slot = &UniqueFilePaths[idx];

    while (slot->hash)
    {
        if (!wcscmp(slot->path, str))
            return 1;                   // 1: exists already
        do {
            // jump and test next viable slot
            idx += 43;                  // mutual prime with PRIME_MODULUS
            idx = idx % PRIME_MODULUS;
            slot = &UniqueFilePaths[idx];
        } while (slot->hash && slot->hash != hash);
    }

    assert(!slot->hash);
    slot->hash = hash;
    slot->path = _wcsdup(str);
    slot->attrs = attrs;
    slot->filesize = filesize;
	slot->timestamp = timestamp;
    return 0;                   // 0: not present before, ADDED now!
}


// overload these two Win32 APIs with our own 'self growing' charbuffer interface paramters...

HANDLE FindFirstFileNameW(_In_ LPCWSTR lpFileName, _In_ DWORD dwFlags, _Inout_ wcharbuffer &LinkName)
{
	DWORD slen = LinkName.space();
	HANDLE h = FindFirstFileNameW(lpFileName, dwFlags, &slen, LinkName.data());
	if (h == INVALID_HANDLE_VALUE && slen > LinkName.space())
	{
		LinkName.reserve(slen + 1);
		slen = LinkName.space();
		h = FindFirstFileNameW(lpFileName, dwFlags, &slen, LinkName.data());
	}
	return h;
}

BOOL FindNextFileNameW(_In_ HANDLE hFindStream, _Inout_ wcharbuffer &LinkName)
{
	DWORD slen = LinkName.space();
	BOOL rv = FindNextFileNameW(hFindStream, &slen, LinkName.data());
	if (slen > LinkName.space())
	{
		LinkName.reserve(slen + 1);
		slen = LinkName.space();
		rv = FindNextFileNameW(hFindStream, &slen, LinkName.data());
	}
	return rv;
}



// Return TRUE when file is hardlinked at least once, i.e. has two paths on the disk AT LEAST.
BOOL FileHasMultipleInstances(const WCHAR* FileName)
{
	wcharbuffer linkPath;
    int linkCount = 0;
    HANDLE fnameHandle = FindFirstFileNameW(FileName, 0, linkPath);
	if (fnameHandle != INVALID_HANDLE_VALUE)
    {
        if (FindNextFileNameW(fnameHandle, linkPath))
        {
            linkCount++;
        }
        FindClose(fnameHandle);
    }
    return !!linkCount;
}


struct ADS_CHECK_REPORTDATA {
	PFILE_STREAM_INFORMATION streamInfo {nullptr};
	ULONG streamInfoSize				{0};
	unsigned int additionalStreamCount  {0};
	BOOLEAN hasOpenError                {FALSE};
	DWORD error                         {ERROR_SUCCESS};
	wcharbuffer errorMessage;

	~ADS_CHECK_REPORTDATA() 
	{
		if (streamInfo)
			free(streamInfo);
	}

	BOOL producedAnError()
	{
		return error != ERROR_SUCCESS;
	}
};


// Queries a file to obtain stream information.
//
// Return TRUE when file has *any* ADS (Alternative Data Streams); hence we need not look any further than a streams list that's longer than just basic/fundamental `::$DATA`.
BOOL FileHasADS(const WCHAR* FileName, ADS_CHECK_REPORTDATA &report)
{
	HANDLE   fileHandle;

	fileHandle = CreateFile(FileName, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS, 0);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		report.hasOpenError = TRUE;
		report.errorMessage.reserve(wcslen(FileName) + 100);
		swprintf(report.errorMessage, report.errorMessage.space(), L"Error opening \"%s\" for reading ADS info", FileName);
		report.error = GetLastError();
		ASSERT(report.error != ERROR_SUCCESS);
	}
	else
	{
		// + https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile
		// + https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_stream_information
		IO_STATUS_BLOCK ioStatus = { 0 };
		NTSTATUS status = ERROR_SUCCESS;
		unsigned int count = 0;

		ULONG streamInfoSize = 512;
		PFILE_STREAM_INFORMATION streamInfo = (PFILE_STREAM_INFORMATION)malloc(streamInfoSize);
		if (streamInfo == nullptr)
		{
			report.errorMessage.reserve(wcslen(FileName) + 200);
			swprintf(report.errorMessage, report.errorMessage.space(), L"ERROR: Out of memory while allocating %lu bytes space for file stream info while inpecting \"%s\"", streamInfoSize, FileName);
			report.error = GetLastError();
			ASSERT(report.error != ERROR_SUCCESS);
			status = ERROR_NOT_ENOUGH_MEMORY | ERROR_SEVERITY_ERROR | APPLICATION_ERROR_MASK;
		}

		while (streamInfo != nullptr)
		{
			memset(&ioStatus, 0, sizeof(ioStatus));
			memset(streamInfo, 0, streamInfoSize);
			status = NtQueryInformationFile(fileHandle, &ioStatus,
				streamInfo, streamInfoSize,
				FileStreamInformation);
			if (status == STATUS_BUFFER_OVERFLOW)
			{
				free(streamInfo);
				streamInfoSize += 16384;
				streamInfo = (PFILE_STREAM_INFORMATION)malloc(streamInfoSize);
				if (streamInfo == nullptr)
				{
					report.errorMessage.reserve(wcslen(FileName) + 200);
					swprintf(report.errorMessage, report.errorMessage.space(), L"ERROR: Out of memory while allocating %lu bytes space for file stream info while inpecting \"%s\"", streamInfoSize, FileName);
					report.error = GetLastError();
					ASSERT(report.error != ERROR_SUCCESS);
					status = ERROR_NOT_ENOUGH_MEMORY | ERROR_SEVERITY_ERROR | APPLICATION_ERROR_MASK;
				}
			}
			else
			{
				break;
			}
		}

		//
		// If success, dump the contents
		//
		if (NT_SUCCESS(status) && ioStatus.Information)
		{
			PFILE_STREAM_INFORMATION streamInfoPtr = streamInfo;
			ULONG actualInfoSize = (ULONG)ioStatus.Information;
			ASSERT(ioStatus.Information < (ULONG_PTR)(~(ULONG)0));
			PFILE_STREAM_INFORMATION streamInfoPtrEOF = (PFILE_STREAM_INFORMATION)(((BYTE *)streamInfo) + actualInfoSize);
			WCHAR streamName[MAX_PATH + 1];

			while (streamInfoPtr < streamInfoPtrEOF)
			{
				ULONG nameLen = std::min((ULONG)sizeof(streamName), streamInfoPtr->StreamNameLength);
				if (streamInfoPtr->StreamNameLength > 0)
				{
					ASSERT(streamInfoPtr->StreamNameLength == nameLen);
					memcpy(streamName, streamInfoPtr->StreamName, nameLen);
				}
				streamName[nameLen / 2] = 0;

				//
				// Skip the standard Data stream
				//
				if (_wcsicmp(streamName, L"::$DATA"))
				{
					count++;
				}

				if (streamInfoPtr->NextEntryOffset == 0)
					break;

				streamInfoPtr = (PFILE_STREAM_INFORMATION)((BYTE *)streamInfoPtr + streamInfoPtr->NextEntryOffset);
			}

			report.additionalStreamCount = count;
			report.streamInfo = streamInfo;
			report.streamInfoSize = actualInfoSize;

			// prevent streamInfo from being freed prematurely below: caller will want to peruse it!
			streamInfo = nullptr;
		}
		else if (!NT_SUCCESS(status) && status != (ERROR_NOT_ENOUGH_MEMORY | ERROR_SEVERITY_ERROR | APPLICATION_ERROR_MASK) /* this one will already have been reported */ )
		{
			report.errorMessage.reserve(wcslen(FileName) + 100);
			swprintf(report.errorMessage, report.errorMessage.space(), L"Error while inspecting \"%s\"", FileName);
			report.error = RtlNtStatusToDosError(status);
		}
		free(streamInfo);
		CloseHandle(fileHandle);

		if ((report.streamInfo == nullptr || report.streamInfoSize == 0) && !report.producedAnError())
		{
			report.error = E_UNEXPECTED;
		}
	}

	if ((report.streamInfo == nullptr || report.streamInfoSize == 0) && !report.producedAnError())
	{
		report.error = E_UNEXPECTED;
	}

	return (report.additionalStreamCount > 0);
}

FILETIME determineLatestTime(const FILETIME &a, const FILETIME &b, const FILETIME &c)
{
	FILETIME t = a;
	if (b.dwHighDateTime > t.dwHighDateTime)
		t = b;
	else if (b.dwHighDateTime == t.dwHighDateTime && b.dwLowDateTime == t.dwLowDateTime)
		t = b;
	if (c.dwHighDateTime > t.dwHighDateTime)
		t = c;
	else if (c.dwHighDateTime == t.dwHighDateTime && c.dwLowDateTime == t.dwLowDateTime)
		t = c;
	return t;
}


void ClearProgress(void)
{
    if (!conciseOutput && !quiet)
    {
        fwprintf(stderr, L"\r     \r");
        DotsPrinted = 0;
    }
}


void ShowProgress(void)
{
    if (!conciseOutput && !quiet)
    {
        clock_t t2 = clock();

        if (t2 - ticks >= CLOCKS_PER_SEC / 2)
        {
            ticks = t2;

            if (DotsPrinted == 3)
            {
                ClearProgress();
            }
            else
            {
                DotsPrinted++;
                fwprintf(stderr, L".");
            }
            fflush(stdout);
        }
    }
}



//--------------------------------------------------------------------
//
// ProcessFile
//
// Queries a file to obtain stream information.
//
//--------------------------------------------------------------------
uint64_t ProcessFile(const WCHAR* FileName, const WIN32_FIND_DATA &foundFile, BOOLEAN IsDirectory, DWORD mandatoryAttribs, DWORD wantedAnyAttribs, DWORD rejectedAttribs, BOOLEAN showLinks, BOOLEAN reportDiskUsage, int showADS)
{
    WIN32_FILE_ATTRIBUTE_DATA attr_data = { INVALID_FILE_ATTRIBUTES };
	
	// The next call reports the size on disk used by a directory while foundFile (as filled by firstfirst/FindNext) will report 0(zero).
	// For *files* the reported file size will be identical to the size reported by Findfirst/FindNext UNLESS the file is special or OPENED
	// by another process, e.g. logfiles being redirected to in a parallel running process. !@#$
    BOOL rv = GetFileAttributesEx(FileName, GetFileExInfoStandard, &attr_data);
	ASSERT(rv == 1);

    DWORD attrs = attr_data.dwFileAttributes;
    uint64_t filesize = attr_data.nFileSizeLow + (((uint64_t)attr_data.nFileSizeHigh) << 32);
	ASSERT(attrs == foundFile.dwFileAttributes);
	uint64_t filesize2 = foundFile.nFileSizeLow + (((uint64_t)foundFile.nFileSizeHigh) << 32);
	
	if (filesize < filesize2 && !IsDirectory)
	{
		fwprintf(stderr, L"Assertion failed for %s: %I64u != %I64u\n", FileName, filesize, filesize2);
		ASSERT(filesize == filesize2);
	}
	if (filesize2 != 0 && IsDirectory)
	{
		ASSERT(IsDirectory ? filesize2 == 0 : TRUE);
	}
	FILETIME latest_time = determineLatestTime(foundFile.ftCreationTime, foundFile.ftLastWriteTime, foundFile.ftLastAccessTime);

    if (!rv || attrs == INVALID_FILE_ATTRIBUTES)
    {
        fwprintf(stderr, L"\rError reading attributes of %s:\n", FileName);
        PrintWin32Error(GetLastError());
    }
    else
    {
        // First do the easy filter stuff. 
        // Then, after we've done that, we go in and scan the filesystem to see if the file has hardlinks
        // and we filter on THAT.

		BOOL mandatoryLinks = !!(mandatoryAttribs & FILE_ATTRIBUTE_HAS_MULTIPLE_SITES);
		BOOL wantedLinks = !!(wantedAnyAttribs & FILE_ATTRIBUTE_HAS_MULTIPLE_SITES);
		BOOL rejectedLinks = !!(rejectedAttribs & FILE_ATTRIBUTE_HAS_MULTIPLE_SITES);

		BOOL mandatoryHardLink = !!(mandatoryAttribs & FILE_ATTRIBUTE_HARDLINK);
		BOOL wantedHardLink = !!(wantedAnyAttribs & FILE_ATTRIBUTE_HARDLINK);
		BOOL rejectedHardLink = !!(rejectedAttribs & FILE_ATTRIBUTE_HARDLINK);

		BOOL mandatoryADS = !!(mandatoryAttribs & FILE_ATTRIBUTE_HAS_ADS);
		BOOL wantedADS = !!(wantedAnyAttribs & FILE_ATTRIBUTE_HAS_ADS);
		BOOL rejectedADS = !!(rejectedAttribs & FILE_ATTRIBUTE_HAS_ADS);

		mandatoryAttribs &= ~(FILE_ATTRIBUTE_HAS_MULTIPLE_SITES | FILE_ATTRIBUTE_HARDLINK | FILE_ATTRIBUTE_HAS_ADS);
        wantedAnyAttribs &= ~(FILE_ATTRIBUTE_HAS_MULTIPLE_SITES | FILE_ATTRIBUTE_HARDLINK | FILE_ATTRIBUTE_HAS_ADS);
        rejectedAttribs &= ~(FILE_ATTRIBUTE_HAS_MULTIPLE_SITES | FILE_ATTRIBUTE_HARDLINK | FILE_ATTRIBUTE_HAS_ADS);

        if ((attrs & mandatoryAttribs) != mandatoryAttribs)
            return filesize;
        if (wantedAnyAttribs && (attrs & wantedAnyAttribs) == 0)
            return filesize;
        if (attrs & rejectedAttribs)
            return filesize;

        BOOL hasLinks = FileHasMultipleInstances(FileName);

        if (mandatoryLinks && !hasLinks)
            return filesize;
        // when 'has multiple sites' or 'is a hardlink' is the only thing we *want*, it's kinda mandatory, eh:
        if (wantedLinks && !wantedAnyAttribs && !wantedADS && !hasLinks)
            return filesize;
        if (wantedHardLink && !wantedAnyAttribs && !wantedADS && !hasLinks)
            return filesize;
        if (rejectedLinks && hasLinks)
            return filesize;

        if (hasLinks)
            attrs |= FILE_ATTRIBUTE_HAS_MULTIPLE_SITES;

        // register all links in a hash table, so next time we test, we'll hit 
        // one of those entries and declare that one a "hardlink", UNIX Style.
        BOOL isHardlink = FALSE;
        if (hasLinks)
        {
            if (!TestAndAddInHashtable(FileName, attrs, filesize, latest_time, UniqueFilePaths))
            {
                wcharbuffer linkPath;
                wcharbuffer fullPath;
                HANDLE fnameHandle = FindFirstFileNameW(FileName, 0, linkPath);
                if (fnameHandle != INVALID_HANDLE_VALUE)
                {
                    if (wcscmp(linkPath, FileName + 6 /* skip \\?\X: long filename prefix plus drive part as that is not present in the link path */))
                    {
						fullPath.reserve(wcslen(linkPath) + 6);
                        wcsncpy_s(fullPath.data(), fullPath.space(), FileName, 6);
                        wcscat_s(fullPath.data(), fullPath.space(), linkPath);
                        TestAndAddInHashtable(fullPath, attrs | FILE_ATTRIBUTE_HARDLINK, filesize, latest_time, UniqueFilePaths);
                    }

                    while (FindNextFileNameW(fnameHandle, linkPath))
                    {
                        if (wcscmp(linkPath, FileName + 6 /* skip \\?\X: long filename prefix plus drive part as that is not present in the link path */))
                        {
							fullPath.reserve(wcslen(linkPath) + 6);
							wcsncpy_s(fullPath.data(), fullPath.space(), FileName, 6);
                            wcscat_s(fullPath.data(), fullPath.space(), linkPath);
                            TestAndAddInHashtable(fullPath, attrs | FILE_ATTRIBUTE_HARDLINK, filesize, latest_time, UniqueFilePaths);
                        }
                    }
                    FindClose(fnameHandle);
                }
            }
            else
            {
                isHardlink = TRUE;

                attrs |= FILE_ATTRIBUTE_HARDLINK;
            }
        }

        if (mandatoryHardLink && !isHardlink)
            return filesize;
        // when 'is hardlink' is the only thing we *want*, it's kinda mandatory, eh:
        if (wantedHardLink && !wantedAnyAttribs && !wantedLinks && !wantedADS && !isHardlink)
            return filesize;
        if (rejectedHardLink && isHardlink)
            return filesize;

		{
			// only do the (costly!) check when we need it for the attribute check, or to show the info it produces:
			// (NOTE that the ADS_CHECK_REPORTDATA destructor automagically cleans up heap memory when we exit this scope: cleaner code!)
			ADS_CHECK_REPORTDATA ADS_report;

			BOOL hasADS = (
				(showADS || mandatoryADS || (wantedADS && !wantedAnyAttribs && !wantedLinks && !wantedHardLink) || rejectedADS) ?
				FileHasADS(FileName, ADS_report) :
				FALSE 
			);

			// only perform these filter checks when we have actual legal  data to compare against:
			if (!ADS_report.producedAnError())
			{
				if (mandatoryADS && !hasADS)
					return filesize;
				// when 'has ADS' is the only thing we *want*, it's kinda mandatory, eh:
				if (wantedADS && !wantedAnyAttribs && !wantedLinks && !wantedHardLink && !hasADS)
					return filesize;
				if (rejectedADS && hasADS)
					return filesize;
			}

			if (hasADS)
			{
				attrs |= FILE_ATTRIBUTE_HAS_ADS;
			}

			FilesMatched++;

			if (!output)
			{
				// List all files when we either are running in regular mode OR are running in reportdiskUsage mode with noisy output, i.e. quiet disabled.
				if (!reportDiskUsage || !quiet)
				{
					if (!conciseOutput)
					{
						CHAR attr_str[32];
						CHAR fsize_str[32];
						CHAR crtsize_str[32];
						CHAR latsize_str[32];
						CHAR lwtsize_str[32];

						FileAttributes2String(attr_str, attrs);
						FileSize2String(fsize_str, filesize);
						FileTime2String(crtsize_str, foundFile.ftCreationTime);
						FileTime2String(lwtsize_str, foundFile.ftLastWriteTime);
						FileTime2String(latsize_str, foundFile.ftLastWriteTime);

						ClearProgress();
						fwprintf(stdout, L"%hs %hs %hs %hs %hs %s\n", attr_str, fsize_str, crtsize_str, lwtsize_str, latsize_str, FileName + 4 /* skip \\?\ prefix */);
					}
					else
					{
						// only dump the file paths to STDOUT in concise mode when NO output file has been specified.
						ClearProgress();
						fwprintf(stdout, L"%s\n", FileName + 4 /* skip \\?\ prefix */);
					}
				}
			}
			else
			{
				// register filename in the OUTPUT hash table when we're going to output it 'unordered' to output file.
				TestAndAddInHashtable(FileName + 4 /* skip \\?\ prefix */, attrs, filesize, latest_time, OutputFilePaths);
			}

			if (showLinks && !output)
			{
				wcharbuffer linkPath;
				int linkCount = 0;
				HANDLE fnameHandle = FindFirstFileNameW(FileName, 0, linkPath);
				if (fnameHandle == INVALID_HANDLE_VALUE)
				{
					fwprintf(stderr, L"\rError reading link names for %s:\n", FileName);
					PrintWin32Error(GetLastError());
				}
				else
				{
					if (wcscmp(linkPath, FileName + 6 /* skip \\?\X: long filename prefix plus drive part as that is not present in the link path */))
					{
						fwprintf(stdout, L"\r#--Link: %2.2s%s\n", FileName + 4, linkPath.c_str());
					}
					linkCount++;

					while (FindNextFileNameW(fnameHandle, linkPath))
					{
						if (wcscmp(linkPath, FileName + 6 /* skip \\?\X: long filename prefix plus drive part as that is not present in the link path */))
						{
							fwprintf(stdout, L"\r#--Link: %2.2s%s\n", FileName + 4, linkPath.c_str());
						}
						linkCount++;
					}
					// EVERY file has ONE "hardlink" at least. UNIX-like "hardlinked files" have MULTIPLE sites:
					if (linkCount > 1)
					{
						fwprintf(stdout, L"\r#--Number of sites: %d\n", linkCount);
					}

					if (GetLastError() != ERROR_HANDLE_EOF)
					{
						fwprintf(stderr, L"\rError reading link names for %s:\n", FileName);
						PrintWin32Error(GetLastError());
					}
					FindClose(fnameHandle);
				}
			}

			if (showADS && !output)
			{
				if (ADS_report.producedAnError())
				{
					if (!ADS_report.hasOpenError || !IsDirectory || PrintDirectoryOpenErrors)
					{
						fwprintf(stderr, L"\r%s:\n", ADS_report.errorMessage.c_str());
						PrintWin32Error(ADS_report.error);
					}
				}
				else if (ADS_report.additionalStreamCount > 0)
				{
					// + https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_stream_information
					ASSERT(ADS_report.streamInfoSize > 0);
					PFILE_STREAM_INFORMATION streamInfoPtr = ADS_report.streamInfo;
					PFILE_STREAM_INFORMATION streamInfoPtrEOF = (PFILE_STREAM_INFORMATION)(((BYTE *)ADS_report.streamInfo) + ADS_report.streamInfoSize);
					wcharbuffer streamName;
					wcharbuffer fullStreamName;

					while (streamInfoPtr < streamInfoPtrEOF)
					{
						ULONG nameLen = streamInfoPtr->StreamNameLength;
						if (streamInfoPtr->StreamNameLength > 0)
						{
							streamName.reserve(nameLen);
							memcpy(streamName.data(), streamInfoPtr->StreamName, nameLen);
						}
						streamName[nameLen / 2] = 0;

						//
						// Skip the standard Data stream
						//
						if (_wcsicmp(streamName, L"::$DATA"))
						{
							fwprintf(stdout, L"   %24s\t%21I64d\n", streamName.c_str(), streamInfoPtr->StreamSize.QuadPart);

							fullStreamName.reserve(wcslen(FileName) + wcslen(streamName) + 1);
							swprintf(fullStreamName, fullStreamName.space(), L"%s%s", FileName, streamName.c_str());
							//fullStreamName[fullStreamName.space() - 1] = 0;
							HANDLE adsFileHandle = CreateFile(fullStreamName, GENERIC_READ,
								FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
								OPEN_EXISTING,
								FILE_FLAG_BACKUP_SEMANTICS, 0);
							if (adsFileHandle == INVALID_HANDLE_VALUE)
							{
								fwprintf(stderr, L"\rError opening ADS stream \"%s\":\n", fullStreamName.c_str());
								PrintWin32Error(GetLastError());
							}
							else
							{
								size_t content_len = streamInfoPtr->StreamSize.QuadPart;
								BYTE* content = (BYTE *)malloc(content_len + 8);
								if (content == nullptr)
								{
									fwprintf(stderr, L"\rERROR: Out of memory while allocating %lu bytes space for file stream info while inspecting ADS stream \"%s\":\n", ADS_report.streamInfoSize, fullStreamName.c_str());
									PrintWin32Error(GetLastError());
								}
								else
								{
									DWORD actual_len = 0;

									BOOL rv = ReadFile(adsFileHandle, content, (DWORD)content_len + 4, &actual_len, NULL);
									if (!rv)
									{
										fwprintf(stderr, L"   Error reading ADS stream \"%s\":\n", fullStreamName.c_str());
										PrintWin32Error(GetLastError());
										free(content);
										content = NULL;
									}

									if (content && actual_len > 0)
									{
										if (actual_len != content_len)
										{
											fwprintf(stderr, L"   Warning: actual length %zu != expected length %zu for \"%s\".\n", (size_t)actual_len, content_len, fullStreamName.c_str());
										}
										memset(content + actual_len, 0, 4);

										// check if content is plain text or binary: use some simple heuristics for that:
										bool is_plain_text = true;
										for (size_t i = 0; i < actual_len; i++)
										{
											int c = content[i];
											if (c < 32 && c != '\r' && c != '\n' && c != '\t')
											{
												is_plain_text = false;
												break;
											}
											if (c == 127)
											{
												is_plain_text = false;
												break;
											}
										}

										if (is_plain_text)
										{
											// trim the trailing newlines:
											BYTE* end = content + content_len - 1;
											for (; end >= content; end--)
											{
												if (*end == '\r' || *end == '\n')
													*end = 0;
												else
													break;
											}

											fwprintf(stdout, L"      --> text content:\n------------------------------------------\n%S\n------------------------------------------\n\n", content);
										}
										else
										{
											for (size_t i = 0; i < actual_len; i += 16)
											{
												fwprintf(stdout, L"   %08zu: \n", i);
												for (size_t j = 0; j < 16; j++)
												{
													if (j + i < actual_len)
														fwprintf(stdout, L"%02x ", content[i + j]);
													else
														fwprintf(stdout, L"   ");
												}
												fwprintf(stdout, L" | ");
												for (size_t j = 0; j < 16; j++)
												{
													if (j + i < actual_len)
													{
														int c = content[i + j];
														if (isprint(c))
															fwprintf(stdout, L"%c ", c);
														else
															fwprintf(stdout, L". ");
													}
													else
														fwprintf(stdout, L"  ");
												}
												fwprintf(stdout, L"\n");
											}
										}
									}
									free(content);
								}
								CloseHandle(adsFileHandle);
							}
						}

						if (streamInfoPtr->NextEntryOffset == 0)
							break;

						streamInfoPtr = (PFILE_STREAM_INFORMATION)((BYTE *)streamInfoPtr + streamInfoPtr->NextEntryOffset);
					}
				}
				// else: no extra ADS streams exist, so there's nothing to report!
			}
		}
	}

	return filesize;
}

struct DirResponse
{
	unsigned int    fileCount		{0};
	unsigned int    directoryCount  {0};

	uint64_t        diskSpaceCost   {0};
};

//--------------------------------------------------------------------
//
// ProcessDirectory
// 
// Recursive routine that passes files to the stream analyzing 
// function.
//
//--------------------------------------------------------------------
DirResponse ProcessDirectory(wcharbuffer &PathName, wcharbuffer &SearchPattern,
    BOOLEAN Recurse, DWORD mandatoryAttribs, DWORD wantedAnyAttribs, DWORD rejectedAttribs, BOOLEAN showLinks, BOOLEAN reportDiskUsage, int showADS, int dirTreeDepth)
{
    wcharbuffer		subName;
	wcharbuffer		fileSearchName;
	wcharbuffer		searchName;
    HANDLE			dirHandle = INVALID_HANDLE_VALUE;
    HANDLE			patternHandle;
    BOOLEAN	        firstCall = (SearchPattern[0] == 0);
    WIN32_FIND_DATA foundFile;
	DirResponse     counts;
	uint64_t        diskSpaceCostWithoutSubDirCosts;
	auto            PathNameLen = wcslen(PathName);

    //
    // Scan the files and/or directories if this is a directory
    //
    if (firstCall)
    {
        if (PathName[PathNameLen - 1] == L'\\')
        {
            PathName[PathNameLen - 1] = 0;
			PathNameLen--;
        }

        if (wcsrchr(PathName, '*'))
        {
            LPWSTR fns = wcsrchr(PathName, '\\');
            if (fns)
            {
                SearchPattern = fns + 1;
                searchName = PathName;
				searchName.reserve(PathNameLen + 4);		// make sure there's space for the wildcards we're about to append
                LPTSTR last = wcsrchr(searchName, '\\');
                ASSERT(last != NULL);
                wcscpy_s(last + 1, searchName.space() - (last + 1 - searchName), L"*.*");
            }
            else
            {
                SearchPattern = PathName;
				searchName = PathName;
            }
            fileSearchName = PathName;
        }
        else
        {
            // check if the specified path is a file or directory:
            int is_dir = FALSE;

            if ((patternHandle = FindFirstFile(PathName, &foundFile)) != INVALID_HANDLE_VALUE)
            {
                is_dir = !!(foundFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                FindClose(patternHandle);
            }

            if (is_dir)
            {
                SearchPattern = L"*.*";

                if (Recurse)
                {
					searchName.reserve(PathNameLen + 4);
					fileSearchName.reserve(PathNameLen + 4);
					swprintf(searchName, searchName.space(), L"%s\\*.*", PathName.c_str());
                    swprintf(fileSearchName, fileSearchName.space(), L"%s\\*.*", PathName.c_str());
                }
                else
                {
                    searchName = PathName;
                    fileSearchName = PathName;
                }
            }
            else
            {
                const WCHAR * dirEnd = wcsrchr(PathName, '\\');
                if (!dirEnd)
                    dirEnd = wcsrchr(PathName, ':');
                const WCHAR * basename;
                if (dirEnd)
                    basename = dirEnd + 1;
                else
                {
                    dirEnd = PathName;
                    basename = PathName;
                }

                SearchPattern = basename;

                if (Recurse)
                {
					searchName.reserve(PathNameLen + 4);
					swprintf(searchName, searchName.space(), L"%.*s\\*.*", (int)(dirEnd - PathName.c_str()), PathName.c_str());
                    fileSearchName = PathName;
                }
                else
                {
                    searchName = PathName;
                    fileSearchName = PathName;
                }
            }
        }
    }
    else
    {
		searchName.reserve(PathNameLen + 4);
		fileSearchName.reserve(PathNameLen + wcslen(SearchPattern) + 1);
		swprintf(searchName, searchName.space(), L"%s\\*.*", PathName.c_str());
        swprintf(fileSearchName, fileSearchName.space(), L"%s\\%s", PathName.c_str(), SearchPattern.c_str());
    }

    //
    // Process all the files, according to the search pattern
    //
    if ((patternHandle = FindFirstFile(fileSearchName, &foundFile)) != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(foundFile.cFileName, L".") &&
                wcscmp(foundFile.cFileName, L".."))
            {
                subName = searchName;
				subName.reserve_extra(wcslen(foundFile.cFileName));
				LPWSTR fn = wcsrchr(subName, '\\');
                if (fn)
                    wcscpy_s(fn + 1, subName.space() - (fn + 1 - subName), foundFile.cFileName);
                else
                    subName = foundFile.cFileName;

                //
                // Do this file/directory
                //
                ShowProgress();

				BOOLEAN is_dir = (BOOLEAN)!!(foundFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);

				if (is_dir)
				{
					// make sure we don't count directories TWICE.
					if (!Recurse)
						counts.directoryCount++;
				}
				else
				{
					counts.fileCount++;
				}

				counts.diskSpaceCost += ProcessFile(subName, foundFile, is_dir, 
                    mandatoryAttribs, wantedAnyAttribs, rejectedAttribs, showLinks, reportDiskUsage, showADS
                );
            }
        } while (FindNextFile(patternHandle, &foundFile));
        FindClose(patternHandle);
    }

	diskSpaceCostWithoutSubDirCosts = counts.diskSpaceCost;

    //
    // Now recurse if we're supposed to
    //
    if (Recurse)
    {
        ShowProgress();

        if (firstCall && !wcsrchr(searchName, L'\\'))
        {
            if (wcsrchr(searchName, L'*'))
            {
                if ((dirHandle = FindFirstFile(L"*.*", &foundFile)) == INVALID_HANDLE_VALUE)
                {
                    //
                    // Nothing to process
                    //
					goto finish;
				}
            }
            else
            {
                if ((dirHandle = FindFirstFile(searchName, &foundFile)) == INVALID_HANDLE_VALUE)
                {
                    //
                    // Nothing to process
                    //
					goto finish;
				}
            }
        }
        else
        {
            if ((dirHandle = FindFirstFile(searchName, &foundFile)) == INVALID_HANDLE_VALUE)
            {
                //
                // Nothing to process
                //
                goto finish;
            }
        }
        firstCall = FALSE;

        do
        {
            if ((foundFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcscmp(foundFile.cFileName, L".") &&
                wcscmp(foundFile.cFileName, L".."))
            {
                subName = searchName;
				subName.reserve_extra(wcslen(foundFile.cFileName));
                LPWSTR fns = wcsrchr(subName, '\\');
                if (fns)
                    wcscpy_s(fns + 1, subName.space() - (fns + 1 - subName), foundFile.cFileName);
                else
                    subName = foundFile.cFileName;

                //
                // Go into this directory
                //
                ShowProgress();

				counts.directoryCount++;

				auto rv = ProcessDirectory(subName, SearchPattern, Recurse, mandatoryAttribs, wantedAnyAttribs, rejectedAttribs, showLinks, reportDiskUsage, showADS, dirTreeDepth + 1);

				counts.diskSpaceCost += rv.diskSpaceCost;
				counts.diskSpaceCost += rv.directoryCount;
				counts.fileCount += rv.fileCount;
            }
        } while (FindNextFile(dirHandle, &foundFile));
    }

    FindClose(dirHandle);

finish:
	if (reportDiskUsage)
	{
		ClearProgress();
		fwprintf(stdout, L"## Disk Usage............. %21I64u %21I64u @ Depth: %6i, Dirs: %8u, Files: %8u ... %s\n", counts.diskSpaceCost, diskSpaceCostWithoutSubDirCosts, dirTreeDepth, counts.directoryCount, counts.fileCount, searchName + 4);
	}

	return counts;
}


int Usage(const WCHAR* ProgramName)
{
    const WCHAR* baseName = wcsrchr(ProgramName, '\\');
    if (!baseName)
        baseName = wcsrchr(ProgramName, '//');
    if (!baseName)
        baseName = ProgramName;
    else
        baseName++;

    fwprintf(stderr, L"\nDirScanner v1.4 - List directory contents including NTFS hardlinks\n");
    fwprintf(stderr, L"Copyright (C) 2021-2023 Ger Hobbelt\n");
    fwprintf(stderr, L"Some parts Copyright (C) 1999-2005 Mark Russinovich\n");

    fwprintf(stderr, L"usage: %s [-s] [-m mask] [-r mask] [-w mask] [-o file] [-u] [-f filter] <file or directory> ...\n", baseName);
    fwprintf(stderr, L"-c     Concise output, i.e. do NOT print the attributes\n");
    fwprintf(stderr, L"-q     Quiet mode: no progress, no info lines\n");
    fwprintf(stderr, L"-s     Recurse subdirectories\n");
    fwprintf(stderr, L"-m     mask of attributes which are Mandatory (MUST HAVE)\n");
    fwprintf(stderr, L"-w     mask of attributes which are Wanted (MAY HAVE)\n");
    fwprintf(stderr, L"-r     mask of attributes which are Rejected (HAS NOT)\n\n");
	fwprintf(stderr, L"-l     list all hardlink sites for every file which has multiple sites (hardlinks)\n");
	fwprintf(stderr, L"-a     list all ADS (Advanced Data Streams) for each file. Repeat this option to also dump the streams' content.\n");
	fwprintf(stderr, L"-o     write the collected list of paths to the specified file (SEMI-RANDOM HASH-based order)\n");
	fwprintf(stderr, L"-u     Report disk usage per element. Directories report the total amount of storage taken up by all matched files within.\n");
	fwprintf(stderr, L"-f     only output files (and/or disk usage lines) when filter criteria match\n\n");
	fwprintf(stderr, L"\n");
    fwprintf(stderr, L"The M,W,R masks are processed as follows:\n"
            L"  mask & MUST(Mandatory) == MUST\n"
            L"  mask & MAY(Wanted) != 0          (if '-w' was specified)\n"
            L"  mask & NOT(Rejected) == 0\n"
            L"only files which pass all three checks will be listed.\n\n");
    fwprintf(stderr, L"Mask/Attributes:\n");
    fwprintf(stderr, L"       R : READONLY\n");
    fwprintf(stderr, L"       H : HIDDEN\n");
    fwprintf(stderr, L"       S : SYSTEM\n");
    fwprintf(stderr, L"       D : DIRECTORY\n");
    fwprintf(stderr, L"       A : ARCHIVE\n");
    fwprintf(stderr, L"       d : DEVICE\n");
    fwprintf(stderr, L"       N : NORMAL\n");
    fwprintf(stderr, L"       T : TEMPORARY\n");
    fwprintf(stderr, L"       s : SPARSE_FILE\n");
    fwprintf(stderr, L"       h : REPARSE_POINT\n");
    fwprintf(stderr, L"       C : COMPRESSED\n");
    fwprintf(stderr, L"       O : OFFLINE\n");
    fwprintf(stderr, L"       i : NOT_CONTENT_INDEXED\n");
    fwprintf(stderr, L"       E : ENCRYPTED\n");
    fwprintf(stderr, L"       t : INTEGRITY_STREAM\n");
	fwprintf(stderr, L"       z : ADVANCED_DATA_STREAM\n");
	fwprintf(stderr, L"       V : VIRTUAL\n");
    fwprintf(stderr, L"       b : NO_SCRUB_DATA\n");
    fwprintf(stderr, L"       a : EA\n");
    fwprintf(stderr, L"       P : PINNED\n");
    fwprintf(stderr, L"       u : UNPINNED\n");
    fwprintf(stderr, L"       c : RECALL_ON_DATA_ACCESS\n");
    fwprintf(stderr, L"       o : RECALL_ON_OPEN\n");
    fwprintf(stderr, L"       l : STRICTLY_SEQUENTIAL\n");
    fwprintf(stderr, L"       L : MULTIPLE_SITES (i.e. file has hardlinks on the drive)\n");
    fwprintf(stderr, L"       X : HARDLINK (i.e. file is a 'hardlink'.)\n");
    fwprintf(stderr, L"       M : misc. (unknown)\n");
    fwprintf(stderr, L"       ? : misc. (unknown)\n");
    fwprintf(stderr, L"       ~ : *NEGATE* the entire specified mask\n");
    fwprintf(stderr, L"       ! : *NEGATE* the entire specified mask\n");
    fwprintf(stderr, L"\n");
    fwprintf(stderr, L"NOTE: we consider a file a 'hardlink' in the UNIX sense when it's the *second or later*\n");
    fwprintf(stderr, L"      file path we encounter for the given file during the scan.\n");
    fwprintf(stderr, L"      Hence you can filter with '/w ~X', i.e. not wanting to see hardlinks, to get a\n");
    fwprintf(stderr, L"      list of unique files in the given search path (there may be links to these files elsewhere).\n");
    fwprintf(stderr, L"      You can filter with '/w L' to see all file paths for 'hardlinked' files.\n");
    fwprintf(stderr, L"      You can filter with '/m L /r X' to see the *first occurrence* of each 'hardlinked' file\n");
    fwprintf(stderr, L"      in the given search path.\n");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"NOTE: '-u' disk usage mode only counts the files matching the user-supplied wildcard pattern,\n");
	fwprintf(stderr, L"      if any was provided.\n");
	fwprintf(stderr, L"      Every directory reports both its cummulative size (including subdirectories) and its\n");
	fwprintf(stderr, L"      bare size, i.e. only the sum of files in the directory itself.\n");
	fwprintf(stderr, L"      The cost of storing any directory file structures (as reported by the OS) on disk are\n");
	fwprintf(stderr, L"      included in the reported sums. As such even an empty directory will report some minimal\n");
	fwprintf(stderr, L"      cost.\n");
	fwprintf(stderr, L"      Thus you can get a report similar to UNIX 'du', but advanced features built in.\n");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"NOTE: '-f' filter expression is constructed as follows: it is a collection of 1 or more sets\n");
	fwprintf(stderr, L"      separated by a colon(:); each set starts with an (optional) 'L'-prefixed level (tree depth)\n");
	fwprintf(stderr, L"      for which the set applies -- no 'L' level implies the set applies to *all* tree depths.\n");
	fwprintf(stderr, L"      A '+' or '-' prefix for the number implies 'this and all higher(inside)' and 'this and all\n");
	fwprintf(stderr, L"      lower(outside)' levels apply.\n");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"      Condition sets are evaluated in order of appearance and function as a a logical OR: any\n");
	fwprintf(stderr, L"      matching condition set will result in the file/line being output.");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"      The set further includes a comma(,) separated set of conditions, each typed by a prefix:\n");
	fwprintf(stderr, L"      - 'S' (size check): specify any of < <= = => > followed by a number. Number can have unit\n");
	fwprintf(stderr, L"                          postfix 'K' (1000), 'M' (1e6), 'G' (1e9), 'T' (1e12)\n");
	fwprintf(stderr, L"      - 'TS' (tree size check): specify any of < <= = => > followed by a number. Number can have\n");
	fwprintf(stderr, L"                          unit postfix 'K' (1000), 'M' (1e6), 'G' (1e9), 'T' (1e12)\n");
	fwprintf(stderr, L"      - 'A' (attribute check): specify one of the m,w,r attribute sets by prefixing with\n");
	fwprintf(stderr, L"                          'M=', 'W=', 'R=' (must, want, reject). No prefix implies MUST('M') set.\n");
	fwprintf(stderr, L"      - 'C' (count check): specify prefix 'D' (directories), 'F' (files), 'TD' (dirs in tree),\n");
	fwprintf(stderr, L"                          'TF' (files in tree); no prefix implies 'F'. specify any of < <= = => >\n");
	fwprintf(stderr, L"                          followed by a number. Number can have unit 'K', 'M', etc. same as above.\n");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"      'L' depth levels start at zero(0) as shown in the report lines output by this tool. Level\n");
	fwprintf(stderr, L"      zero is the first level visited by the scan. 'TS' considers the total size collected for the\n");
	fwprintf(stderr, L"      subtree at hand and is mostly useful for filtering '-u' disk usage reports. Ditto for 'C'.\n");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"      Note that the 'C' conditions in particular require the tool to buffer its output as the\n");
	fwprintf(stderr, L"      condition can only be sanely applied once all relevant counts have been collected,\n");
	fwprintf(stderr, L"      resulting in increased memory usage an very \"bursty\" output once the conditions *can* be\n");
	fwprintf(stderr, L"      applied.  Performance should be impacted only minimally, though.\n");
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"      Example filter: 'S>10M,A=R,AR=S:L+2S>=5M:L4,S>150,S<=1K'\n");
	fwprintf(stderr, L"      Explanation: 'S>10M,A=R,AR=S' applies to all levels and selects only file sizes > 10M with\n");
	fwprintf(stderr, L"      their read-only attribute set and must not have the system attrib.\n");
	fwprintf(stderr, L"      'L+2S>=5M' applies to depth level 2 and selects any file size >= M. Note that the level 'L+2'\n");
	fwprintf(stderr, L"      does not need to be followed by a comma, though doing so would help readability: 'L+2,S>=5M'\n");
	fwprintf(stderr, L"      'L4,S>150,S<=1K' applies to depth level 4 only and picks any file that's between 150 bytes\n");
	fwprintf(stderr, L"      '(exclusive bound) and 1K (inclusive bound). Note here that a range/band like this may be\n");
	fwprintf(stderr, L"      specified like this, but we do not accept more complex (multi-band) size criteria mixes in a\n");
	fwprintf(stderr, L"      condition set. If you want that, create multiple sets, e.g. 'S>150,S<=1K:S<20:S>1T' which\n");
	fwprintf(stderr, L"      picks the same set of file sizes as before *plus* any file smaller than 20 bytes or larger\n");
	fwprintf(stderr, L"      than 1Tb. This example has three sets, all applying to all depth levels as no 'L' prefix\n");
	fwprintf(stderr, L"      was given in any of them: condition sets may overlap like that.\n");
	fwprintf(stderr, L"\n");

    return -1;
}


int wmain(int argc, WCHAR* argv[])
{
    BOOLEAN     recurse = FALSE;
    BOOLEAN     regular_only = FALSE;
    DWORD		fsFlags;
    BOOLEAN     showLinks = FALSE;
	BOOLEAN     reportDiskUsage = FALSE;
	int         showADS = 0;
	DWORD       mandatoryAttribs = 0;
    DWORD       wantedAnyAttribs = 0;
    DWORD       rejectedAttribs = 0;
    wcharbuffer     searchPattern;
	wcharbuffer		searchPath;
	wcharbuffer		listOutputPath;
	DirResponse     totals;
    int         i;

    ticks = clock();

    if (argc <= 1)
    {
        return Usage(argv[0]);
    }

    //
    // Enable backup privilege if we can
    //
    if (EnableTokenPrivilege(SE_BACKUP_NAME))
    {
        PrintDirectoryOpenErrors = TRUE;
    }

    //
    // Load the NTDLL entry point we need
    //
    if (!(NtQueryInformationFile = (NtQueryInformationFile_f)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationFile")))
    {
        fwprintf(stderr, L"\nCould not find NtQueryInformationFile entry point in NTDLL.DLL\n");
        exit(1);
    }
    if (!(RtlNtStatusToDosError = (RtlNtStatusToDosError_f)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlNtStatusToDosError")))
    {
        fwprintf(stderr, L"\nCould not find RtlNtStatusToDosError entry point in NTDLL.DLL\n");
        exit(1);
    }

    {
        if (!GetCPInfoExW(CP_UTF8, 0, &CPInfo))
        {
            memset(&CPInfo, 0, sizeof(CPInfo));
            CPInfo.DefaultChar[0] = '?';
        }
    }

    // Now go through the search paths sequentially, while we parse the commandline parameters alongside.
    // Order of appearancee is important, hence you can specify different attribute mask filters
    // for different search paths!

    {
        auto last_arg = argv[argc - 1];
        if ((last_arg[0] == L'/' || last_arg[0] == L'-') && last_arg[2] == 0)
        {
            fwprintf(stderr, L"Unused commandline parameters at the end of your commandline. Please clean up: %s\n", last_arg);
            return Usage(argv[0]);
        }
    }

    memset(UniqueFilePaths, 0, sizeof(UniqueFilePaths));
    memset(OutputFilePaths, 0, sizeof(OutputFilePaths));

    output = NULL;
    atexit(CloseOutput);

    for (i = 1; i < argc; i++)
    {
        auto opt = argv[i];

        // only match '/X' and '-X' options; the rest is search paths:
        if ((opt[0] == L'/' || opt[0] == L'-') && opt[2] == 0)
        {
			if (opt[1] == L'c' || opt[1] == L'C')
			{
				conciseOutput = TRUE;
			}
			else if (opt[1] == L'a' || opt[1] == L'A')
            {
                showADS++;
            }
            else if (opt[1] == L's' || opt[1] == L'S')
            {
                recurse = TRUE;
            }
            else if (opt[1] == L'l' || opt[1] == L'L')
            {
                showLinks = TRUE;
            }
            else if (opt[1] == L'q' || opt[1] == L'Q')
            {
                quiet = TRUE;
            }
            else if (opt[1] == L'm' || opt[1] == 'M')
            {
                i++;
                mandatoryAttribs = ParseMask(argv[i]);
            }
            else if (opt[1] == L'w' || opt[1] == 'W')
            {
                i++;
                wantedAnyAttribs = ParseMask(argv[i]);
            }
            else if (opt[1] == L'r' || opt[1] == 'R')
            {
                i++;
                rejectedAttribs = ParseMask(argv[i]);
            }
            else if (opt[1] == L'o' || opt[1] == 'O')
            {
                CloseOutput();

                i++;
                listOutputPath = argv[i];
                NormalizePathSeparators(listOutputPath);

                charbuffer fname(listOutputPath.space() * 5);
                CvtUTF16ToUTF8(fname, listOutputPath);
                errno_t err = fopen_s(&output, fname, "w");
                if (!output || err)
                {
                    char msg[1024];
                    strerror_s(msg, errno);
                    fwprintf(stderr, L"Unable to open file '%s' for writing: ", listOutputPath.c_str());
                    fprintf(stderr, "%s.\n\n", msg);
                    return EXIT_FAILURE;
                }
            }
			else if (opt[1] == L'u' || opt[1] == 'U')
			{
				reportDiskUsage = TRUE;
			}
			else
            {
                fwprintf(stderr, L"Unrecognized commandline argument: %s\n\n", opt);
                return Usage(argv[0]);
            }

            continue;
        }

		// As the Windows GetFullPathName() API is a nasty animal that does NOT cope with 
		// being fed UNC paths, so we need some prepwork before we can use it to expand 
		// any path to an absolute path.
		//
		// Check if the specified path is a full UNC path:
		const WCHAR *specPath = argv[i];
		searchPath = specPath;
		NormalizePathSeparators(searchPath);

		if (wcsncmp(searchPath, L"\\\\?\\", 4) == 0)
		{
			// nothing to do...
		}
		else 
		{
			wcharbuffer buf;
			buf = specPath;
			NormalizePathSeparators(buf);

			// https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
			searchPath = L"\\\\?\\";

			PWCHAR filePart = NULL;
			GetFullPathName(buf, searchPath.space() - 4, searchPath + 4, &filePart);
			NormalizePathSeparators(searchPath);
		}

        if (!quiet)
        {
            fwprintf(stderr, L"Scanning: %s\n", searchPath.c_str());
        }

        //
        // Check that it's a NTFS volume and report limited abilities when it's not
        //
        if (searchPath[4 + 1] == L':')
        {
            // User very probably specified a '\\?\D:\...' UNC path. Check the drive letter in there.
            fsFlags = 0;
            WCHAR volume[] = L"C:\\";
            volume[0] = searchPath[4];
            GetVolumeInformation(volume, NULL, 0, NULL, NULL, &fsFlags, NULL, 0);
            if (!(fsFlags & FILE_SUPPORTS_HARD_LINKS))
            {
                fwprintf(stderr, L"\nWARNING: The specified volume %s does not support Windows/NTFS hardlinks. We won't be able to find any of those then!\n\n", volume);
                // ignore this inability, so we can scan network drives, etc. anyway.
            }
			if (!(fsFlags & FILE_NAMED_STREAMS))
			{
				fwprintf(stderr, L"\nWARNING: The specified volume %s does not support Windows/NTFS Advanced Data Streams a.k.a. Named Streams. We won't be able to find any of those then!\n\n", volume);
				// ignore this inability, so we can scan network drives, etc. anyway.
			}
			if (!(fsFlags & FILE_SUPPORTS_INTEGRITY_STREAMS))
			{
				fwprintf(stderr, L"\nWARNING: The specified volume %s does not support Windows/NTFS Integrity Streams. We won't be able to find any of those then!\n\n", volume);
				// ignore this inability, so we can scan network drives, etc. anyway.
			}
			if (!(fsFlags & FILE_SUPPORTS_EXTENDED_ATTRIBUTES))
			{
				fwprintf(stderr, L"\nWARNING: The specified volume %s does not support Extended Attributes. We won't be able to find any of those then!\n\n", volume);
				// ignore this inability, so we can scan network drives, etc. anyway.
			}
		}

        //
        // Now go and process directories
        //
        searchPattern[0] = 0;           // signal initial call of this recursive function
        auto rv = ProcessDirectory(searchPath, searchPattern, recurse, mandatoryAttribs, wantedAnyAttribs, rejectedAttribs, showLinks, reportDiskUsage, showADS, 0);
		totals.directoryCount += rv.directoryCount;
		totals.fileCount += rv.fileCount;
		totals.diskSpaceCost += rv.diskSpaceCost;
    }

    CloseOutput();

    // reset progress dots to empty line before we exit.
    ClearProgress();

    if (!FilesMatched)
    {
        if (!quiet)
        {
            fwprintf(stderr, L"\rNo matching files found.\n\n");
        }
    }

	if (reportDiskUsage)
	{
		ClearProgress();
		fwprintf(stdout, L"## Disk Usage............. %21I64u ..................... @ .............. Dirs: %8u, Files: %8u ... (---TOTAL---)\n", totals.diskSpaceCost, totals.directoryCount, totals.fileCount);
	}

    return 0;
}
