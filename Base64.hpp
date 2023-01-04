#ifndef Base64_hpp
#define Base64_hpp

//***************define***************//
#define DEFAULT_BASECODE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"//MIME Base64
#define DEFAULT_FULLCODE '='//MIME Base64
#define INIT_THROW true//抛出初始化异常

#define CONST const
#define NOEXCEPT noexcept

#define BASECODE_COUNT ((ULONG)(64))//BASE64
#define BASECODEAP_COUNT (((ULONG)((UCHAR)(-1)))+1)//UCHAR_MAX+1

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
	UCHAR ucFullCode;//填充字符
	UCHAR ucBaseCode[BASECODE_COUNT + sizeof('\0')];//加密字符集 Use:[0]~[64] Full:[64]=0 Text:[0]~[63]
	UCHAR ucBaseCodeMap[BASECODEAP_COUNT];//加密字符集映射：通过加密字符获得该字符在字符集中的位置（映射集）
	BOOL bAvailable;//类是否可用（如果ucBaseCode内数据不正确、映射不成功则该值为false，类不可用，否则可用），用于保证加密数据不因加密串问题而受到损坏

	//字符集映射函数
	BOOL MapTheBaseCode(VOID) NOEXCEPT;
public:
	Base64(PCUCHAR _ucBaseCode = (PCUCHAR)DEFAULT_BASECODE, UCHAR _ucFullCode = DEFAULT_FULLCODE);//构造类
	Base64(CONST Base64 &) = default;
	Base64(Base64 &&) = default;
	~Base64(VOID) = default;

	BOOL SetBaseCode(PCUCHAR pcucBaseCode) NOEXCEPT;//设置加密字符串
	PCUCHAR GetBaseCode(VOID) CONST NOEXCEPT;//获取加密字符串

	BOOL SetFullCode(UCHAR cucFullCode) NOEXCEPT;//设置填充字符
	UCHAR GetFullCode(VOID) CONST NOEXCEPT;//获取填充字符

	ULONGLONG GetEnCodeSize(PCVOID pcEnCodeData, ULONGLONG ullEncodeSize) CONST NOEXCEPT;//获取加密后字符串长度
	BOOL EnCode(PCVOID pcData, ULONGLONG ullDataSize, PUCHAR pEncode) CONST NOEXCEPT;//加密指定内存的指定字节数到指定字符串

	ULONGLONG GetDeCodeSize(PCUCHAR pcDeCodeText, ULONGLONG ullDecodeSize) CONST NOEXCEPT;//获取解密后数据字节长度
	BOOL DeCode(PCUCHAR pcucCode, ULONGLONG ullCodeSize, PVOID pData) CONST NOEXCEPT;//解密指定字符串到指定内存的指定字节数
};
//***************class***************//

//***************funtion***************//

Base64::BOOL Base64::MapTheBaseCode(VOID) NOEXCEPT
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
	ucFullCode(_ucFullCode), bAvailable(false)
{
	//拷贝输入字符串
	memcpy(ucBaseCode, _ucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//安全起见给字符串末尾赋值为0

	//检查填充字符是否位于加密串中
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)
	{
		THROW_ERROR("加密串中出现填充字符!");//填充字符与字符串中的某个字符相同
		return;
	}

	//映射加密串
	if (!MapTheBaseCode())
	{
		THROW_ERROR("加密串中出现重复字符!");
		return;
	}

	//成功初始化，该类可用
	bAvailable = true;
}


Base64::BOOL Base64::SetBaseCode(PCUCHAR pcucBaseCode) NOEXCEPT
{
	//设置该类为不可用状态
	bAvailable = false;

	//拷贝输入字符串
	memcpy(ucBaseCode, pcucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//安全起见给字符串末尾赋值为0

	//映射加密串
	bAvailable = MapTheBaseCode();
	return bAvailable;
}

Base64::PCUCHAR Base64::GetBaseCode(VOID) CONST NOEXCEPT
{
	return ucBaseCode;
}


Base64::BOOL Base64::SetFullCode(UCHAR cucFullCode) NOEXCEPT
{
	//设置该类为不可用状态
	bAvailable = false;
	//设置填充字符
	ucFullCode = cucFullCode;

	//验证字符
	bAvailable = strchr((PCCHAR)ucBaseCode, ucFullCode) == NULL;//返回NULL代表填充字符不在加密串中
	return bAvailable;
}

Base64::UCHAR Base64::GetFullCode(VOID) CONST NOEXCEPT
{
	return ucFullCode;
}


Base64::ULONGLONG Base64::GetEnCodeSize(PCVOID pcEnCodeData, ULONGLONG ullEncodeSize) CONST NOEXCEPT
{
	return ullEncodeSize <= 3 ? 4 : (ullEncodeSize / 3 * 4 + ((ullEncodeSize % 3) ? 4 : 0));
}

Base64::BOOL Base64::EnCode(PCVOID pcData, ULONGLONG ullDataSize, PUCHAR pEncode) CONST NOEXCEPT
{
	//类的状态为不可用
	if (!bAvailable)
	{
		return false;
	}

	PCUCHAR pcucCode = (PCUCHAR)pcData;
	ULONGLONG i, j;

	for (i = 3, j = 4; i <= ullDataSize; i += 3, j += 4)
	{
		//加密3字节数据到4个Base64字符
		pEncode[j - 4] = ucBaseCode[(pcucCode[i - 3] >> 2)];
		pEncode[j - 3] = ucBaseCode[(((pcucCode[i - 3] & 0x03) << 4) | ((pcucCode[i - 2] & 0xF0) >> 4))];
		pEncode[j - 2] = ucBaseCode[(((pcucCode[i - 2] & 0x0F) << 2) | ((pcucCode[i - 1] & 0xC0) >> 6))];
		pEncode[j - 1] = ucBaseCode[pcucCode[i - 1] & 0x3F];
	}

	switch ((ullDataSize % 3) - 1)
	{
		case 0:
			//加密剩余字符并设置填充字符
			pEncode[j - 4] = ucBaseCode[(pcucCode[i - 3] >> 2)];
			pEncode[j - 3] = ucBaseCode[((pcucCode[i - 3] & 0x03) << 4)];
			pEncode[j - 2] = ucFullCode;
			pEncode[j - 1] = ucFullCode;
			break;
		case 1:
			//加密剩余字符并设置填充字符
			pEncode[j - 4] = ucBaseCode[(pcucCode[i - 3] >> 2)];
			pEncode[j - 3] = ucBaseCode[(((pcucCode[i - 3] & 0x03) << 4) | ((pcucCode[i - 2] & 0xF0) >> 4))];
			pEncode[j - 2] = ucBaseCode[(((pcucCode[i - 2] & 0x0F) << 2) | ((pcucCode[i - 1] & 0xC0) >> 6))];
			pEncode[j - 1] = ucFullCode;
			break;
		default:
			break;
	}

	return true;
}


Base64::ULONGLONG Base64::GetDeCodeSize(PCUCHAR pcDeCodeText, ULONGLONG ullDecodeSize) CONST NOEXCEPT
{
	ULONGLONG ullFullCodeCount = 0;
	if (pcDeCodeText)
	{
		if (pcDeCodeText[ullDecodeSize - 2] == ucFullCode)
		{
			ullFullCodeCount = 2;
		}
		else if (pcDeCodeText[ullDecodeSize - 1] == ucFullCode)
		{
			ullFullCodeCount = 1;
		}
	}

	return (ullDecodeSize <= 4 ? 3 : ullDecodeSize / 4 * 3) - ullFullCodeCount;
}

Base64::BOOL Base64::DeCode(PCUCHAR pcucCode, ULONGLONG ullCodeSize, PVOID pData) CONST NOEXCEPT
{
	//类的状态为不可用
	if (!bAvailable)
	{
		return false;
	}

	//不是4的倍数
	if (ullCodeSize % 4 != 0)
	{
		return false;
	}

	//计算实际要解码的数据（排除填充字符）
	if (pcucCode[ullCodeSize - 2] == ucFullCode)
	{
		ullCodeSize -= 3;
	}
	else if (pcucCode[ullCodeSize - 1] == ucFullCode)
	{
		ullCodeSize -= 2;
	}

	PUCHAR cpDecode = (PUCHAR)pData;
	ULONGLONG i, j;
	UCHAR ucCode[4] = {0};

	for (i = 4, j = 3; i <= ullCodeSize; i += 4, j += 3)
	{
		//查找映射并检查是否存在于映射集中
		for (LONG k = -4; k < 0; k += 1)
		{
			if ((ucCode[k + 4] = ucBaseCodeMap[pcucCode[i + k]]) == BASECODE_COUNT)//该字符不在映射集中
			{
				return false;
			}
		}

		//解密4个Base64字符到3个字节数据
		cpDecode[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
		cpDecode[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
		cpDecode[j - 1] = ((ucCode[2] & 0x03) << 6) | (ucCode[3] >> 0);
	}

	switch ((ullCodeSize % 4) - 1)
	{
		case 0:
			//查找映射并检查是否存在于映射集中
			for (LONG k = -4; k < -2; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pcucCode[i + k]]) == BASECODE_COUNT)//该字符不在映射集中
				{
					return false;
				}
			}

			//解密剩余字符
			cpDecode[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			break;
		case 1:
			//查找映射并检查是否存在于映射集中
			for (LONG k = -4; k < -1; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pcucCode[i + k]]) == BASECODE_COUNT)//该字符不在映射集中
				{
					return false;
				}
			}

			//解密剩余字符
			cpDecode[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			cpDecode[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
			break;
		default:
			break;
	}

	return true;
}
//***************funtion***************//

//***************undef***************//
#undef CONST
#undef NOEXCEPT
//***************undef***************//

#endif // !Base64_hpp