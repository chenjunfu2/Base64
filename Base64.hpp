#ifndef Base64_hpp
#define Base64_hpp

//***************define***************//
#define DEFAULT_BASECODE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"//MIME Base64
#define DEFAULT_FULLCODE '='//MIME Base64
#define INIT_THROW true//�׳���ʼ���쳣

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
	UCHAR ucFullCode;//����ַ�
	UCHAR ucBaseCode[BASECODE_COUNT + sizeof('\0')];//�����ַ��� Use:[0]~[64] Full:[64]=0 Text:[0]~[63]
	UCHAR ucBaseCodeMap[BASECODEAP_COUNT];//�����ַ���ӳ�䣺ͨ�������ַ���ø��ַ����ַ����е�λ�ã�ӳ�伯��
	BOOL bAvailable;//���Ƿ���ã����ucBaseCode�����ݲ���ȷ��ӳ�䲻�ɹ����ֵΪfalse���಻���ã�������ã������ڱ�֤�������ݲ�����ܴ�������ܵ���

	//�ַ���ӳ�亯��
	BOOL MapTheBaseCode(VOID) NOEXCEPT;
public:
	Base64(PCUCHAR _ucBaseCode = (PCUCHAR)DEFAULT_BASECODE, UCHAR _ucFullCode = DEFAULT_FULLCODE);//������
	Base64(CONST Base64 &) = default;
	Base64(Base64 &&) = default;
	~Base64(VOID) = default;

	BOOL SetBaseCode(PCUCHAR pcucBaseCode) NOEXCEPT;//���ü����ַ���
	PCUCHAR GetBaseCode(VOID) CONST NOEXCEPT;//��ȡ�����ַ���

	BOOL SetFullCode(UCHAR cucFullCode) NOEXCEPT;//��������ַ�
	UCHAR GetFullCode(VOID) CONST NOEXCEPT;//��ȡ����ַ�

	ULONGLONG GetEnCodeSize(PCVOID pcEnCodeData, ULONGLONG ullEncodeSize) CONST NOEXCEPT;//��ȡ���ܺ��ַ�������
	BOOL EnCode(PCVOID pcData, ULONGLONG ullDataSize, PUCHAR pEncode) CONST NOEXCEPT;//����ָ���ڴ��ָ���ֽ�����ָ���ַ���

	ULONGLONG GetDeCodeSize(PCUCHAR pcDeCodeText, ULONGLONG ullDecodeSize) CONST NOEXCEPT;//��ȡ���ܺ������ֽڳ���
	BOOL DeCode(PCUCHAR pcucCode, ULONGLONG ullCodeSize, PVOID pData) CONST NOEXCEPT;//����ָ���ַ�����ָ���ڴ��ָ���ֽ���
};
//***************class***************//

//***************funtion***************//

Base64::BOOL Base64::MapTheBaseCode(VOID) NOEXCEPT
{
	//��ucBaseCodeMap��ʼ��ΪBASECODE_COUNT,�Ա��ں�������з��ִ���
	memset(ucBaseCodeMap, BASECODE_COUNT, BASECODEAP_COUNT * sizeof(UCHAR));

	for (ULONG i = 0; i < BASECODE_COUNT; i += 1)
	{
		if (ucBaseCodeMap[ucBaseCode[i]] != BASECODE_COUNT)
		{
			return false;//�ظ��ַ�
		}
		ucBaseCodeMap[ucBaseCode[i]] = (UCHAR)i;//ӳ������ַ�(���ٽ�����)
	}

	return true;
}

Base64::Base64(PCUCHAR _ucBaseCode, UCHAR _ucFullCode) :
	ucFullCode(_ucFullCode), bAvailable(false)
{
	//���������ַ���
	memcpy(ucBaseCode, _ucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//��ȫ������ַ���ĩβ��ֵΪ0

	//�������ַ��Ƿ�λ�ڼ��ܴ���
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)
	{
		THROW_ERROR("���ܴ��г�������ַ�!");//����ַ����ַ����е�ĳ���ַ���ͬ
		return;
	}

	//ӳ����ܴ�
	if (!MapTheBaseCode())
	{
		THROW_ERROR("���ܴ��г����ظ��ַ�!");
		return;
	}

	//�ɹ���ʼ�����������
	bAvailable = true;
}


Base64::BOOL Base64::SetBaseCode(PCUCHAR pcucBaseCode) NOEXCEPT
{
	//���ø���Ϊ������״̬
	bAvailable = false;

	//���������ַ���
	memcpy(ucBaseCode, pcucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//��ȫ������ַ���ĩβ��ֵΪ0

	//ӳ����ܴ�
	bAvailable = MapTheBaseCode();
	return bAvailable;
}

Base64::PCUCHAR Base64::GetBaseCode(VOID) CONST NOEXCEPT
{
	return ucBaseCode;
}


Base64::BOOL Base64::SetFullCode(UCHAR cucFullCode) NOEXCEPT
{
	//���ø���Ϊ������״̬
	bAvailable = false;
	//��������ַ�
	ucFullCode = cucFullCode;

	//��֤�ַ�
	bAvailable = strchr((PCCHAR)ucBaseCode, ucFullCode) == NULL;//����NULL��������ַ����ڼ��ܴ���
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
	//���״̬Ϊ������
	if (!bAvailable)
	{
		return false;
	}

	PCUCHAR pcucCode = (PCUCHAR)pcData;
	ULONGLONG i, j;

	for (i = 3, j = 4; i <= ullDataSize; i += 3, j += 4)
	{
		//����3�ֽ����ݵ�4��Base64�ַ�
		pEncode[j - 4] = ucBaseCode[(pcucCode[i - 3] >> 2)];
		pEncode[j - 3] = ucBaseCode[(((pcucCode[i - 3] & 0x03) << 4) | ((pcucCode[i - 2] & 0xF0) >> 4))];
		pEncode[j - 2] = ucBaseCode[(((pcucCode[i - 2] & 0x0F) << 2) | ((pcucCode[i - 1] & 0xC0) >> 6))];
		pEncode[j - 1] = ucBaseCode[pcucCode[i - 1] & 0x3F];
	}

	switch ((ullDataSize % 3) - 1)
	{
		case 0:
			//����ʣ���ַ�����������ַ�
			pEncode[j - 4] = ucBaseCode[(pcucCode[i - 3] >> 2)];
			pEncode[j - 3] = ucBaseCode[((pcucCode[i - 3] & 0x03) << 4)];
			pEncode[j - 2] = ucFullCode;
			pEncode[j - 1] = ucFullCode;
			break;
		case 1:
			//����ʣ���ַ�����������ַ�
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
	//���״̬Ϊ������
	if (!bAvailable)
	{
		return false;
	}

	//����4�ı���
	if (ullCodeSize % 4 != 0)
	{
		return false;
	}

	//����ʵ��Ҫ��������ݣ��ų�����ַ���
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
		//����ӳ�䲢����Ƿ������ӳ�伯��
		for (LONG k = -4; k < 0; k += 1)
		{
			if ((ucCode[k + 4] = ucBaseCodeMap[pcucCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
			{
				return false;
			}
		}

		//����4��Base64�ַ���3���ֽ�����
		cpDecode[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
		cpDecode[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
		cpDecode[j - 1] = ((ucCode[2] & 0x03) << 6) | (ucCode[3] >> 0);
	}

	switch ((ullCodeSize % 4) - 1)
	{
		case 0:
			//����ӳ�䲢����Ƿ������ӳ�伯��
			for (LONG k = -4; k < -2; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pcucCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
				{
					return false;
				}
			}

			//����ʣ���ַ�
			cpDecode[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			break;
		case 1:
			//����ӳ�䲢����Ƿ������ӳ�伯��
			for (LONG k = -4; k < -1; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pcucCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
				{
					return false;
				}
			}

			//����ʣ���ַ�
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