#ifndef Base64_hpp
#define Base64_hpp

//***************define***************//
#define DEFAULT_BASECODE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"//MIME Base64
#define DEFAULT_FULLCODE '='//MIME Base64

#define INIT_THROW true//抛出初始化异常


#if INIT_THROW
#define THROW_ERROR(reason) throw(reason)
#else
#define THROW_ERROR(reason)
#endif
//***************define***************//

//***************include***************//
#include <string.h>
//***************include***************//

//***************class***************//

class Base64
{
public:
	typedef char CHAR;
	typedef char *PCHAR;
	typedef const char CCHAR;
	typedef const char *PCCHAR;
	typedef unsigned char UCHAR;
	typedef unsigned char *PUCHAR;
	typedef const unsigned char CUCHAR;
	typedef const unsigned char *PCUCHAR;
	typedef long LONG;
	typedef unsigned long ULONG;
	typedef unsigned long long ULONGLONG;
	typedef void VOID;
	typedef void *PVOID;
	typedef const void *PCVOID;
	typedef bool BOOL;
protected:
#define BASECODE_COUNT ((ULONG)(64))//BASE64
#define BASECODEAP_COUNT (((ULONG)((UCHAR)(-1)))+1)//UCHAR_MAX+1

	UCHAR ucFullCode;//填充字符
	UCHAR ucBaseCode[BASECODE_COUNT + sizeof('\0')];//加密字符集 Use:[0]~[64] Full:[64]=0 Text:[0]~[63]
	UCHAR ucBaseCodeMap[BASECODEAP_COUNT];//加密字符集映射：通过加密字符获得该字符在字符集中的位置（映射集）

	mutable ULONG ulLastError;//类的最后一个错误码
	mutable BOOL bAvailable;//类是否可用（如果ucBaseCode内数据不正确、映射不成功则该值为false，类不可用，否则可用），用于保证加密数据不因加密串问题而受到损坏

	//字符集映射函数
	BOOL MapTheBaseCode(VOID) noexcept;
public:
	Base64(PCUCHAR _ucBaseCode = (PCUCHAR)DEFAULT_BASECODE, UCHAR _ucFullCode = DEFAULT_FULLCODE);//构造类
	Base64(const Base64 &) = default;
	Base64(Base64 &&) = default;
	~Base64(VOID) = default;

	BOOL SetBaseCode(PCUCHAR pcucBaseCode) noexcept;//设置加密字符串
	PCUCHAR GetBaseCode(VOID) const noexcept;//获取加密字符串

	BOOL SetFullCode(UCHAR cucFullCode) noexcept;//设置填充字符
	UCHAR GetFullCode(VOID) const noexcept;//获取填充字符

	ULONGLONG GetEnCodeSize(PCVOID pData, ULONGLONG ullDataSize) const noexcept;//获取加密后字符串长度
	BOOL EnCode(PCVOID pData, ULONGLONG ullDataSize, PUCHAR pCode, ULONGLONG ullCodeSize) noexcept;//加密指定内存的指定字节数到指定字符串

	ULONGLONG GetDeCodeSize(PCUCHAR pCode, ULONGLONG ullCodeSize) const noexcept;//获取解密后数据字节长度
	BOOL DeCode(PCUCHAR pCode, ULONGLONG ullCodeSize, PVOID pData, ULONGLONG ullDataSize) noexcept;//解密指定字符串到指定内存的指定字节数

	VOID SetLastError(ULONG ulErrorCode) noexcept;//设置最后一个错误码
	ULONG GetLastError(VOID) const noexcept;//获取最后一个错误码
	PCCHAR GetErrorReason(ULONG ulErrorCode) const noexcept;//从错误码获得错误原因

private:
	enum enErrorCode
	{
		NO_ERROR = 0,//无错误
		CIPHER_REPEATING_CHAR,//加密串中出现重复字符
		FILL_CODE_IN_CIPHER,//加密串中出现填充字符
		NULL_DATA_POINTER,//数据指针为空
		NULL_CODE_POINTER,//字符指针为空
		TARGET_TOO_SMALL,//加解密目标不足以容纳结果

		UNKNOW_ERROR,//未知错误
	};

	static inline Base64::PCCHAR pErrorReason[UNKNOW_ERROR + 1] =
	{
		"无错误",
		"加密串中出现重复字符",
		"加密串中出现填充字符",
		"数据指针为空",
		"字符指针为空",
		"目标内存太小",

		"未知错误",
	};
};

//***************class***************//

//***************funtion***************//

Base64::BOOL Base64::MapTheBaseCode(VOID) noexcept
{
	//将ucBaseCodeMap初始化为BASECODE_COUNT,以便在后续检查中发现错误
	memset(ucBaseCodeMap, BASECODE_COUNT, BASECODEAP_COUNT * sizeof(UCHAR));

	for (ULONG i = 0; i < BASECODE_COUNT; i += 1)
	{
		if (ucBaseCodeMap[ucBaseCode[i]] != BASECODE_COUNT)
		{
			return false;//重复字符
		}
		ucBaseCodeMap[ucBaseCode[i]] = (UCHAR)i;//映射加密字符(快速解码用)
	}

	return true;
}

Base64::Base64(PCUCHAR _ucBaseCode, UCHAR _ucFullCode) :
	ucFullCode(_ucFullCode), ulLastError(NO_ERROR), bAvailable(false)//设置该类为不可用状态
{
	//拷贝输入字符串
	memcpy(ucBaseCode, _ucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//安全起见给字符串末尾赋值为0

	//检查填充字符是否位于加密串中
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)
	{
		SetLastError(FILL_CODE_IN_CIPHER);
		THROW_ERROR("加密串中出现填充字符!");//填充字符与字符串中的某个字符相同
		return;
	}

	//映射加密串
	if (!MapTheBaseCode())
	{
		SetLastError(CIPHER_REPEATING_CHAR);
		THROW_ERROR("加密串中出现重复字符!");
		return;
	}

	//成功初始化，该类可用
	bAvailable = true;
}


Base64::BOOL Base64::SetBaseCode(PCUCHAR pcucBaseCode) noexcept
{
	//设置该类为不可用状态
	bAvailable = false;

	//拷贝输入字符串
	memcpy(ucBaseCode, pcucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//安全起见给字符串末尾赋值为0

	//映射加密串
	if (!MapTheBaseCode())
	{
		SetLastError(CIPHER_REPEATING_CHAR);
		return false;
	}

	//检查通过，该类为可用状态
	bAvailable = true;
	return true;
}

Base64::PCUCHAR Base64::GetBaseCode(VOID) const noexcept
{
	return ucBaseCode;
}


Base64::BOOL Base64::SetFullCode(UCHAR cucFullCode) noexcept
{
	//设置该类为不可用状态
	bAvailable = false;
	//设置填充字符
	ucFullCode = cucFullCode;

	//验证字符
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)//返回非NULL代表填充字符在加密串中
	{
		SetLastError(FILL_CODE_IN_CIPHER);
		return false;
	}

	//检查通过，设置类为可用状态
	bAvailable = true;
	return true;
}

Base64::UCHAR Base64::GetFullCode(VOID) const noexcept
{
	return ucFullCode;
}

Base64::ULONGLONG Base64::GetEnCodeSize(PCVOID pData, ULONGLONG ullDataSize) const noexcept
{
	return ullDataSize <= 3 ? 4 : (ullDataSize / 3 * 4 + ((ullDataSize % 3) ? 4 : 0));
}

Base64::BOOL Base64::EnCode(PCVOID pData, ULONGLONG ullDataSize, PUCHAR pCode, ULONGLONG ullCodeSize) noexcept
{
	//类的状态为不可用
	if (!bAvailable)
	{
		return false;
	}

	if (pData == NULL || ullDataSize == 0)
	{
		SetLastError(NULL_DATA_POINTER);
		return false;
	}

	if (pCode == NULL || ullCodeSize == 0)
	{
		SetLastError(NULL_CODE_POINTER);
		return false;
	}

	if (GetEnCodeSize(pData, ullDataSize) > ullCodeSize)
	{
		SetLastError(TARGET_TOO_SMALL);
		return false;
	}

	PCUCHAR pEncodeData = (PCUCHAR)pData;
	ULONGLONG i, j;

	for (i = 3, j = 4; i <= ullDataSize; i += 3, j += 4)
	{
		//加密3字节数据到4个Base64字符
		pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
		pCode[j - 3] = ucBaseCode[(((pEncodeData[i - 3] & 0x03) << 4) | ((pEncodeData[i - 2] & 0xF0) >> 4))];
		pCode[j - 2] = ucBaseCode[(((pEncodeData[i - 2] & 0x0F) << 2) | ((pEncodeData[i - 1] & 0xC0) >> 6))];
		pCode[j - 1] = ucBaseCode[pEncodeData[i - 1] & 0x3F];
	}

	switch ((ullDataSize % 3) - 1)
	{
		case 0:
			//加密剩余字符并设置填充字符
			pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
			pCode[j - 3] = ucBaseCode[((pEncodeData[i - 3] & 0x03) << 4)];
			pCode[j - 2] = ucFullCode;
			pCode[j - 1] = ucFullCode;
			break;
		case 1:
			//加密剩余字符并设置填充字符
			pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
			pCode[j - 3] = ucBaseCode[(((pEncodeData[i - 3] & 0x03) << 4) | ((pEncodeData[i - 2] & 0xF0) >> 4))];
			pCode[j - 2] = ucBaseCode[(((pEncodeData[i - 2] & 0x0F) << 2) | ((pEncodeData[i - 1] & 0xC0) >> 6))];
			pCode[j - 1] = ucFullCode;
			break;
		default:
			break;
	}

	return true;
}


Base64::ULONGLONG Base64::GetDeCodeSize(PCUCHAR pCode, ULONGLONG ullCodeSize) const noexcept
{
	ULONGLONG ullFullCodeCount = 0;
	if (pCode != NULL)
	{
		if (pCode[ullCodeSize - 2] == ucFullCode)
		{
			ullFullCodeCount = 2;
		}
		else if (pCode[ullCodeSize - 1] == ucFullCode)
		{
			ullFullCodeCount = 1;
		}
	}

	return (ullCodeSize <= 4 ? 3 : ullCodeSize / 4 * 3) - ullFullCodeCount;
}

Base64::BOOL Base64::DeCode(PCUCHAR pCode, ULONGLONG ullCodeSize, PVOID pData, ULONGLONG ullDataSize) noexcept
{
	//类的状态为不可用
	if (!bAvailable)
	{
		return false;
	}

	if (pCode == NULL || ullCodeSize == 0)
	{
		SetLastError(NULL_CODE_POINTER);
		return false;
	}

	if (pData == NULL || ullDataSize == 0)
	{
		SetLastError(NULL_DATA_POINTER);
		return false;
	}

	if (GetDeCodeSize(pCode, ullCodeSize) > ullDataSize)
	{
		SetLastError(TARGET_TOO_SMALL);
		return false;
	}

	//不是4的倍数
	if (ullCodeSize % 4 != 0)
	{
		return false;
	}

	//计算实际要解码的数据（排除填充字符）
	if (pCode[ullCodeSize - 2] == ucFullCode)
	{
		ullCodeSize -= 3;
	}
	else if (pCode[ullCodeSize - 1] == ucFullCode)
	{
		ullCodeSize -= 2;
	}

	PUCHAR pDecodeData = (PUCHAR)pData;
	ULONGLONG i, j;
	UCHAR ucCode[4] = {0};

	for (i = 4, j = 3; i <= ullCodeSize; i += 4, j += 3)
	{
		//查找映射并检查是否存在于映射集中
		for (LONG k = -4; k < 0; k += 1)
		{
			if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//该字符不在映射集中
			{
				return false;
			}
		}

		//解密4个Base64字符到3个字节数据
		pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
		pDecodeData[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
		pDecodeData[j - 1] = ((ucCode[2] & 0x03) << 6) | (ucCode[3] >> 0);
	}

	switch ((ullCodeSize % 4) - 1)
	{
		case 0:
			//查找映射并检查是否存在于映射集中
			for (LONG k = -4; k < -2; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//该字符不在映射集中
				{
					return false;
				}
			}

			//解密剩余字符
			pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			break;
		case 1:
			//查找映射并检查是否存在于映射集中
			for (LONG k = -4; k < -1; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//该字符不在映射集中
				{
					return false;
				}
			}

			//解密剩余字符
			pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			pDecodeData[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
			break;
		default:
			break;
	}

	return true;
}


Base64::VOID Base64::SetLastError(ULONG ulErrorCode) noexcept
{
	ulLastError = ulErrorCode;
}

Base64::ULONG Base64::GetLastError(VOID) const noexcept
{
	return ulLastError;
}

Base64::PCCHAR Base64::GetErrorReason(ULONG ulErrorCode) const noexcept
{
	if (ulLastError >= UNKNOW_ERROR)
	{
		return pErrorReason[UNKNOW_ERROR];
	}

	return pErrorReason[ulErrorCode];
}
//***************funtion***************//

#endif // !Base64_hpp