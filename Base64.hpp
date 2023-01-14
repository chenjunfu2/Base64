#ifndef Base64_hpp
#define Base64_hpp

//***************define***************//
#define DEFAULT_BASECODE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"//MIME Base64
#define DEFAULT_FULLCODE '='//MIME Base64

#define INIT_THROW false//�׳���ʼ���쳣


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

	enum class ErrorCode
	{
		CLASS_NO_ERROR = 0,//�޴���
		NULL_BASE_CODE,//���봮Ϊ��
		BASE_CODE_REPEAT_CHAR,//���봮�г����ظ��ַ�
		FILL_CODE_IN_BASE_CODE,//���봮�г�������ַ�
		NULL_DATA_POINTER,//����ָ��Ϊ��
		NULL_CODE_POINTER,//�ַ�ָ��Ϊ��
		TARGET_TOO_SMALL,//�ӽ���Ŀ�겻�������ɽ��
		NOT_FOUR_MULTIPLE,//�����ܴ����Ȳ���4�ı���
		FIND_UNKNOW_CHAR,//�����ܴ��г���δ֪�ַ�

		UNKNOW_ERROR,//δ֪����
	};
protected:
#define BASECODE_COUNT ((ULONG)(64))//BASE64
#define BASECODEAP_COUNT (((ULONG)((UCHAR)(-1)))+1)//UCHAR_MAX+1

	UCHAR ucFullCode;//����ַ�
	UCHAR ucBaseCode[BASECODE_COUNT + sizeof('\0')];//�����ַ��� Use:[0]~[64] Full:[64]=0 Text:[0]~[63]
	UCHAR ucBaseCodeMap[BASECODEAP_COUNT];//�����ַ���ӳ�䣺ͨ�������ַ���ø��ַ����ַ����е�λ�ã�ӳ�伯��

	mutable ErrorCode ecLastError;//������һ��������
	mutable BOOL bAvailable;//���Ƿ���ã����ucBaseCode�����ݲ���ȷ��ӳ�䲻�ɹ����ֵΪfalse���಻���ã�������ã������ڱ�֤�������ݲ�����ܴ�������ܵ���

	//�ַ���ӳ�亯��
	BOOL MapTheBaseCode(VOID) noexcept;
public:
	Base64(PCUCHAR _ucBaseCode = (PCUCHAR)DEFAULT_BASECODE, UCHAR _ucFullCode = DEFAULT_FULLCODE);//������
	Base64(const Base64 &) = default;
	Base64(Base64 &&) = default;
	~Base64(VOID) = default;

	BOOL SetBaseCode(PCUCHAR pBaseCode) noexcept;//�������봮
	PCUCHAR GetBaseCode(VOID) const noexcept;//��ȡ���봮

	BOOL SetFullCode(UCHAR cFullCode) noexcept;//��������ַ�
	UCHAR GetFullCode(VOID) const noexcept;//��ȡ����ַ�

	ULONGLONG GetEnCodeSize(PCVOID pData, ULONGLONG ullDataSize) const noexcept;//��ȡ���ܺ��ַ�������
	BOOL EnCode(PCVOID pData, ULONGLONG ullDataSize, PUCHAR pCode, ULONGLONG ullCodeSize) const noexcept;//����ָ���ڴ��ָ���ֽ�����ָ���ַ���

	ULONGLONG GetDeCodeSize(PCUCHAR pCode, ULONGLONG ullCodeSize) const noexcept;//��ȡ���ܺ������ֽڳ���
	BOOL DeCode(PCUCHAR pCode, ULONGLONG ullCodeSize, PVOID pData, ULONGLONG ullDataSize) const noexcept;//����ָ���ַ�����ָ���ڴ��ָ���ֽ���

	VOID SetLastError(ErrorCode ecErrorCode) const noexcept;//�������һ��������
	ErrorCode GetLastError(VOID) const noexcept;//��ȡ���һ��������
	PCCHAR GetErrorReason(ErrorCode ecErrorCode) const noexcept;//�Ӵ������ô���ԭ��
private:
	static inline Base64::PCCHAR pErrorReason[(ULONG)ErrorCode::UNKNOW_ERROR + 1] = 
	{
		"�޴���",
		"���봮Ϊ��",
		"���봮�г����ظ��ַ�",
		"���봮�г�������ַ�",
		"����ָ��Ϊ��",
		"�ַ�ָ��Ϊ��",
		"Ŀ���ڴ�̫С",
		"�����ܴ����Ȳ���4�ı���",
		"�����ܴ��г���δ֪�ַ�",

		"δ֪����",
	};
};

//***************class***************//

//***************funtion***************//

Base64::BOOL Base64::MapTheBaseCode(VOID) noexcept
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
	ucFullCode(_ucFullCode), ecLastError(ErrorCode::CLASS_NO_ERROR), bAvailable(false)//���ø���Ϊ������״̬
{
	if (_ucBaseCode == NULL)
	{
		SetLastError(ErrorCode::NULL_BASE_CODE);
		THROW_ERROR(GetErrorReason(GetLastError()));
		return;
	}

	//���������ַ���
	memcpy(ucBaseCode, _ucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//��ȫ������ַ���ĩβ��ֵΪ0

	//�������ַ��Ƿ�λ�ڼ��ܴ���
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)
	{
		SetLastError(ErrorCode::FILL_CODE_IN_BASE_CODE);
		THROW_ERROR(GetErrorReason(GetLastError()));
		return;
	}

	//ӳ����ܴ�
	if (!MapTheBaseCode())
	{
		SetLastError(ErrorCode::BASE_CODE_REPEAT_CHAR);
		THROW_ERROR(GetErrorReason(GetLastError()));
		return;
	}

	//�ɹ���ʼ�����������
	bAvailable = true;
}


Base64::BOOL Base64::SetBaseCode(PCUCHAR pBaseCode) noexcept
{
	//���ø���Ϊ������״̬
	bAvailable = false;

	//�մ�
	if (pBaseCode == NULL)
	{
		SetLastError(ErrorCode::NULL_BASE_CODE);
		return false;
	}

	//���������ַ���
	memcpy(ucBaseCode, pBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//��ȫ������ַ���ĩβ��ֵΪ0

	//ӳ����ܴ�
	if (!MapTheBaseCode())
	{
		SetLastError(ErrorCode::BASE_CODE_REPEAT_CHAR);
		return false;
	}

	//���ͨ��������Ϊ����״̬
	bAvailable = true;
	return true;
}

Base64::PCUCHAR Base64::GetBaseCode(VOID) const noexcept
{
	return ucBaseCode;
}


Base64::BOOL Base64::SetFullCode(UCHAR cFullCode) noexcept
{
	//���ø���Ϊ������״̬
	bAvailable = false;
	//��������ַ�
	ucFullCode = cFullCode;

	//��֤�ַ�
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)//���ط�NULL��������ַ��ڼ��ܴ���
	{
		SetLastError(ErrorCode::FILL_CODE_IN_BASE_CODE);
		return false;
	}

	//���ͨ����������Ϊ����״̬
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

Base64::BOOL Base64::EnCode(PCVOID pData, ULONGLONG ullDataSize, PUCHAR pCode, ULONGLONG ullCodeSize) const noexcept
{
	//���״̬Ϊ������
	if (!bAvailable)
	{
		return false;
	}

	if (pData == NULL || ullDataSize == 0)
	{
		SetLastError(ErrorCode::NULL_DATA_POINTER);
		return false;
	}

	if (pCode == NULL || ullCodeSize == 0)
	{
		SetLastError(ErrorCode::NULL_CODE_POINTER);
		return false;
	}

	if (GetEnCodeSize(pData, ullDataSize) > ullCodeSize)
	{
		SetLastError(ErrorCode::TARGET_TOO_SMALL);
		return false;
	}

	PCUCHAR pEncodeData = (PCUCHAR)pData;
	ULONGLONG i, j;

	for (i = 3, j = 4; i <= ullDataSize; i += 3, j += 4)
	{
		//����3�ֽ����ݵ�4��Base64�ַ�
		pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
		pCode[j - 3] = ucBaseCode[(((pEncodeData[i - 3] & 0x03) << 4) | ((pEncodeData[i - 2] & 0xF0) >> 4))];
		pCode[j - 2] = ucBaseCode[(((pEncodeData[i - 2] & 0x0F) << 2) | ((pEncodeData[i - 1] & 0xC0) >> 6))];
		pCode[j - 1] = ucBaseCode[pEncodeData[i - 1] & 0x3F];
	}

	switch ((ullDataSize % 3) - 1)
	{
		case 0:
			//����ʣ���ַ�����������ַ�
			pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
			pCode[j - 3] = ucBaseCode[((pEncodeData[i - 3] & 0x03) << 4)];
			pCode[j - 2] = ucFullCode;
			pCode[j - 1] = ucFullCode;
			break;
		case 1:
			//����ʣ���ַ�����������ַ�
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

Base64::BOOL Base64::DeCode(PCUCHAR pCode, ULONGLONG ullCodeSize, PVOID pData, ULONGLONG ullDataSize) const noexcept
{
	//���״̬Ϊ������
	if (!bAvailable)
	{
		return false;
	}

	if (pCode == NULL || ullCodeSize == 0)
	{
		SetLastError(ErrorCode::NULL_CODE_POINTER);
		return false;
	}

	if (pData == NULL || ullDataSize == 0)
	{
		SetLastError(ErrorCode::NULL_DATA_POINTER);
		return false;
	}

	if (GetDeCodeSize(pCode, ullCodeSize) > ullDataSize)
	{
		SetLastError(ErrorCode::TARGET_TOO_SMALL);
		return false;
	}

	//����4�ı���
	if (ullCodeSize % 4 != 0)
	{
		SetLastError(ErrorCode::NOT_FOUR_MULTIPLE);
		return false;
	}

	//����ʵ��Ҫ��������ݣ��ų�����ַ���
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
		//����ӳ�䲢����Ƿ������ӳ�伯��
		for (LONG k = -4; k < 0; k += 1)
		{
			if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
			{
				SetLastError(ErrorCode::FIND_UNKNOW_CHAR);
				return false;
			}
		}

		//����4��Base64�ַ���3���ֽ�����
		pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
		pDecodeData[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
		pDecodeData[j - 1] = ((ucCode[2] & 0x03) << 6) | (ucCode[3] >> 0);
	}

	switch ((ullCodeSize % 4) - 1)
	{
		case 0:
			//����ӳ�䲢����Ƿ������ӳ�伯��
			for (LONG k = -4; k < -2; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
				{
					SetLastError(ErrorCode::FIND_UNKNOW_CHAR);
					return false;
				}
			}

			//����ʣ���ַ�
			pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			break;
		case 1:
			//����ӳ�䲢����Ƿ������ӳ�伯��
			for (LONG k = -4; k < -1; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
				{
					SetLastError(ErrorCode::FIND_UNKNOW_CHAR);
					return false;
				}
			}

			//����ʣ���ַ�
			pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			pDecodeData[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
			break;
		default:
			break;
	}

	return true;
}

Base64::VOID Base64::SetLastError(ErrorCode ecErrorCode) const noexcept
{
	ecLastError = ecErrorCode;
}

Base64::ErrorCode Base64::GetLastError(VOID) const noexcept
{
	return ecLastError;
}

Base64::PCCHAR Base64::GetErrorReason(ErrorCode ecErrorCode) const noexcept
{
	if (ecLastError >= ErrorCode::UNKNOW_ERROR)
	{
		return pErrorReason[(ULONG)ErrorCode::UNKNOW_ERROR];
	}

	return pErrorReason[(ULONG)ecErrorCode];
}
//***************funtion***************//

#endif // !Base64_hpp