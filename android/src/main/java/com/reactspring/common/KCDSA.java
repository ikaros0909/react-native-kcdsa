package com.reactspring.common;

import java.util.Random;

public class KCDSA {
	public static final int SHA_224 = 1;
    public static final int SHA_256 = 2;
	
    final static int CTR_SUCCESS = 0;
    final static int CTR_VERIFY_FAIL = 1;
    final static int CTR_FATAL_ERROR = 2;
	final static int CTR_INVALID_POINTER = 3;
	final static int CTR_INVALID_ALG_PARAMS = 4;
	final static int CTR_MEMORY_ALLOC_ERROR = 5;
	final static int CTR_BUFFER_TOO_SMALL = 6;
	final static int CTR_INVALID_SIGNATURE_LEN = 8;
	final static int ERROR_OverModulus = 23;
	final static int CTR_BN_NEGATIVE_RESULT = 24;
	
	final static int BN_MAX_BITS = 3072;
    final static int MAX_SEED_LEN = 64;
    final static int BitsInDIGIT = 32;
	
	public static int KISA_KCDSA_CreateObject(KISA_KCDSA kcdsa){
        kcdsa.KCDSA_P = new BIGNUM(((BN_MAX_BITS - 1) / BitsInDIGIT + 1) + 1);
        kcdsa.KCDSA_Q = new BIGNUM(((256 - 1) / BitsInDIGIT + 1) + 1);
        kcdsa.KCDSA_G = new BIGNUM(((BN_MAX_BITS - 1) / BitsInDIGIT + 1) + 1);
        kcdsa.KCDSA_x = new BIGNUM(((256 - 1) / BitsInDIGIT + 1) + 1);
        kcdsa.KCDSA_y = new BIGNUM(((BN_MAX_BITS - 1) / BitsInDIGIT + 1) + 1);
        kcdsa.Count = 0;
        kcdsa.SeedLen = MAX_SEED_LEN;

        if ( (kcdsa.KCDSA_P == null) || (kcdsa.KCDSA_Q == null) || (kcdsa.KCDSA_G == null) || (kcdsa.KCDSA_x == null) || (kcdsa.KCDSA_y == null) ){
            KISA_KCDSA_DestroyObject(kcdsa);
            return -1;
        }

        return 0;
    }
	
	public static int KISA_KCDSA_GenerateParameters(int PrimeBits, int SubPrimeBits, KISA_KCDSA kcdsa, int HASH) {
		int i, j, ret;
		int Count = 0;
		byte[] bzTmp = new byte[3072 / 8 + 4];
		byte[] tSeed = new byte[256 / 8 + 4];
		//int[] g = new int[96];
		/*p = 2048, q = 224, SHA-224 test vector*/
		/*p = 2048, q = 224, SHA-256 test vector*/
		int g[] = 
			{ 0x967500f2, 0x4ae06466, 0x8c2eb468, 0xc05a92f8, 0xc314fe16, 0x545cf834, 0x73320013, 0x2024bb80, 
			  0xf8bb047b, 0x66e0db04, 0x629340c6, 0xecd4ec10, 0x046a12e8, 0x806cc64e, 0x59fc0842, 0xc01ad8a8, 
			  0xb5c6285d, 0x3800b9a0, 0x586dd871, 0x9c8c85d0, 0x6e10c0da, 0xceb7b4fa, 0x5ffcb0a8, 0x80cf3ae4, 
			  0x2f30525f, 0x6c1fb75c, 0x376a90e7, 0x6c1af700, 0xf858eca7, 0x12246fc6, 0xba7e782e, 0xf06dbc24, 
			  0xc9888ea8, 0xc031eeba, 0x4568dc7d, 0x582d8950, 0xf9c038b1, 0x764675a0, 0xd85a401d, 0xc8fc9984, 
			  0x462ceac2, 0x5263048e, 0x7354ace8, 0x40d3e2d0, 0x9be0a6db, 0x847b9b84, 0xfb5620bb, 0xc0b23380, 
			  0xf89cd4fc, 0xbe143a82, 0x12609c96, 0x48998c38, 0x5d600a68, 0x00b51688, 0x31982079, 0xf088edf8, 
			  0xca2c4805, 0x4a5e31a0, 0x581ea864, 0xf46c56c0, 0x1e008eaa, 0x9c0f5422, 0x87aca828, 0x8cd78a90 
			};
		/*p = 2048, q = 256, SHA-256 test vector*/
		/*int g[] = 
			{ 0xe8b24a24, 0xac387aec, 0x8aec08c2, 0x84c12e6c, 0xbe1cd1b6, 0x38463461, 0x6010f000, 0x104068c0, 
			  0x7f5aac40, 0x7c9ff2d4, 0xf4a43f0a, 0x0654781e, 0xd86e34e8, 0xe64c5694, 0xcd8e849d, 0x747db63c, 
			  0x185064a8, 0xd408d05c, 0x4c5b78d0, 0x8a941bd2, 0x1bc25c5b, 0x880abc78, 0x3c18123c, 0x29bc289a, 
			  0x04f91eac, 0x2edc49e6, 0x10300019, 0xc028c020, 0x72e0c0d0, 0x37ca6c57, 0xbc97a2d4, 0x04e877fa, 
			  0x9ea41876, 0xf846c4c8, 0xd68ce56e, 0x45be04d5, 0x308426fc, 0xe8703c38, 0x2c183074, 0x0cd3e504, 
			  0x8594d375, 0x9a159c53, 0x286246d8, 0x76f8aa1e, 0x2147d472, 0x8431e7ec, 0x789cc107, 0xe8e0e010, 
			  0x2040c840, 0x09042f30, 0xefb92ccf, 0xfc8fe9d4, 0xda48e662, 0x36d2b8ce, 0x942d4aa8, 0xebccdd2b, 
			  0xbd2b840d, 0x101cac10, 0x3c901434, 0x8bc4908c, 0xcc4bad84, 0xcd948b7d, 0xb256284b, 0xcfbaee38 
			};*/
		/*p = 3072, q = 256, SHA-256 test vector*/
		/*int g[] = 
			{ 0xf042e385, 0x287a8c5e, 0x0080c0c0, 0x50004040, 0x3f1d3060, 0x4725c321, 0x9cecba29, 0x2c686420, 
			  0xbcf8f4b0, 0x2fc92360, 0x47e13b55, 0x844c536d, 0xf0e8a018, 0x448840b8, 0x2c5238de, 0xdf354b21, 
			  0x92165a5e, 0x4c86cace, 0x16f82458, 0x0ef092f4, 0xb8e88aec, 0x38787838, 0xb8f8f8b8, 0x80275543, 
			  0x882684a2, 0xa06c8caa, 0x76724894, 0xa502be3a, 0x7da7913b, 0x9af46913, 0x28b0f800, 0x88105860, 
			  0xf1d71cc0, 0xd9bf65cb, 0x56a74db3, 0x488c9002, 0xb8fc00c4, 0x94063834, 0xcd6fd1f3, 0xc090c9eb, 
			  0x00d060b0, 0x0a8040c0, 0xd200ee9c, 0x9ac8b664, 0xc24e9abb, 0x129eeaf6, 0xd00d3a46, 0xa8923ca6, 
			  0x006a147e, 0x5c3810a8, 0xbc040cd4, 0x73e91f34, 0x16bcc7bd, 0xe4b80a30, 0x14e87cd0, 0x7302ac00, 
			  0x2b5d4f01, 0xe31507b9, 0x60f04071, 0xa0308090, 0xbc7ac0d0, 0x7b6917be, 0xae31df4d, 0xbedab652, 
			  0xc4101c62, 0x56d00a38, 0xee68a29c, 0x0ce44f79, 0x2c049cf4, 0xad24bc14, 0x88beb46a, 0x30665c12, 
			  0x027498ba, 0x32c61a2e, 0x29eb4a5e, 0x5263e527, 0x0afcae20, 0x60806000, 0xd0806000, 0x3dbbf940, 
			  0xc543817f, 0x38140907, 0x4824c01c, 0x5834d02c, 0xe923d05a, 0x81bbb56f, 0x3ca4cc07, 0xc860b894, 
			  0x9a60d8f0, 0x02c84e94, 0xd5cb81fc, 0x062a0eb2, 0xf61afea2, 0x28aaec4c, 0xa0226466, 0xcafddcde 
			};*/
		
		/*p = 2048, q = 224, SHA-224 test vector*/
		tSeed[0] = (byte)0xc0; tSeed[1] = 0x52; tSeed[2] = (byte)0xa2; tSeed[3] = 0x76;
		tSeed[4] = 0x41; tSeed[5] = 0x00; tSeed[6] = (byte)0xf0; tSeed[7] = (byte)0xf4;
		tSeed[8] = (byte)0xec; tSeed[9] = (byte)0x90; tSeed[10] = 0x6b; tSeed[11] = (byte)0x9c;
		tSeed[12] = 0x5c; tSeed[13] = 0x6b; tSeed[14] = 0x10; tSeed[15] = 0x6e;
		tSeed[16] = 0x34; tSeed[17] = 0x70; tSeed[18] = (byte)0xdf; tSeed[19] = (byte)0xc1;
		tSeed[20] = 0x36; tSeed[21] = (byte)0x9f; tSeed[22] = 0x12; tSeed[23] = (byte)0xc0;
		tSeed[24] = 0x62; tSeed[25] = (byte)0xf8; tSeed[26] = 0x0e; tSeed[27] = (byte)0xe9;
		/*p = 2048, q = 224, SHA-256 test vector*/
		/*tSeed[0] = (byte)0xe1; tSeed[1] = 0x75; tSeed[2] = (byte)0xca; tSeed[3] = (byte)0xd0;
		tSeed[4] = (byte)0xea; tSeed[5] = (byte)0xcb; tSeed[6] = (byte)0x74; tSeed[7] = (byte)0xdd;
		tSeed[8] = (byte)0xb4; tSeed[9] = (byte)0x5f; tSeed[10] = 0x15; tSeed[11] = (byte)0xf1;
		tSeed[12] = (byte)0xf2; tSeed[13] = 0x57; tSeed[14] = 0x22; tSeed[15] = (byte)0xbf;
		tSeed[16] = 0x15; tSeed[17] = 0x56; tSeed[18] = (byte)0xef; tSeed[19] = (byte)0x86;
		tSeed[20] = 0x0a; tSeed[21] = (byte)0x0f; tSeed[22] = (byte)0xe0; tSeed[23] = (byte)0x31;
		tSeed[24] = 0x71; tSeed[25] = (byte)0x18; tSeed[26] = 0x44; tSeed[27] = (byte)0x9b;*/
		/*p = 2048, q = 256, SHA-256 test vector*/
		/*tSeed[0] = (byte)0xf7; tSeed[1] = 0x5a; tSeed[2] = (byte)0xbd; tSeed[3] = (byte)0xa0;
		tSeed[4] = (byte)0x03; tSeed[5] = (byte)0x2c; tSeed[6] = (byte)0xe2; tSeed[7] = (byte)0x18;
		tSeed[8] = (byte)0xce; tSeed[9] = (byte)0x04; tSeed[10] = (byte)0xba; tSeed[11] = (byte)0xf0;
		tSeed[12] = (byte)0xa6; tSeed[13] = (byte)0xdc; tSeed[14] = (byte)0x92; tSeed[15] = (byte)0xc8;
		tSeed[16] = 0x7e; tSeed[17] = (byte)0xb4; tSeed[18] = (byte)0x6a; tSeed[19] = (byte)0xa0;
		tSeed[20] = 0x56; tSeed[21] = (byte)0x8c; tSeed[22] = (byte)0x42; tSeed[23] = (byte)0x78;
		tSeed[24] = 0x2e; tSeed[25] = (byte)0x64; tSeed[26] = 0x4c; tSeed[27] = (byte)0xc2;
		tSeed[28] = (byte)0xb8; tSeed[29] = (byte)0x2e; tSeed[30] = 0x24; tSeed[31] = (byte)0x9a;*/
		/*p = 3072, q = 256, SHA-256 test vector*/
		/*tSeed[0] = (byte)0xb8; tSeed[1] = 0x56; tSeed[2] = (byte)0x20; tSeed[3] = (byte)0x16;
		tSeed[4] = (byte)0x38; tSeed[5] = (byte)0x55; tSeed[6] = (byte)0xa7; tSeed[7] = (byte)0xc0;
		tSeed[8] = (byte)0x05; tSeed[9] = (byte)0x76; tSeed[10] = (byte)0x13; tSeed[11] = (byte)0xdc;
		tSeed[12] = (byte)0xd1; tSeed[13] = (byte)0xf2; tSeed[14] = (byte)0xae; tSeed[15] = (byte)0x61;
		tSeed[16] = (byte)0x80; tSeed[17] = (byte)0xc4; tSeed[18] = (byte)0x34; tSeed[19] = (byte)0xd0;
		tSeed[20] = (byte)0x98; tSeed[21] = (byte)0x90; tSeed[22] = (byte)0xea; tSeed[23] = (byte)0x70;
		tSeed[24] = 0x22; tSeed[25] = (byte)0x00; tSeed[26] = (byte)0x83; tSeed[27] = (byte)0xf2;
		tSeed[28] = (byte)0x8d; tSeed[29] = (byte)0x27; tSeed[30] = 0x54; tSeed[31] = (byte)0xad;*/
		
		BIGNUM BN_Tmp1 = null, BN_Tmp2 = null, KCDSA_J = null;
		
		SHA_ALG_INFO sha_algInfo = new SHA_ALG_INFO();
		Random random = new Random();
		
		if (kcdsa == null)	return CTR_INVALID_POINTER;

		if ((PrimeBits < 2048) || (PrimeBits > 3072)  || ((PrimeBits % 256) != 0))
			return CTR_INVALID_ALG_PARAMS;
		if ((SubPrimeBits < 224) || (SubPrimeBits > 256) || ((SubPrimeBits % 32) != 0))
			return CTR_INVALID_ALG_PARAMS;
		
		BN_Tmp1 = new BIGNUM(PrimeBits / 32 + 1);
		BN_Tmp2 = new BIGNUM(PrimeBits / 32 + 1);
		
		for (j = 0; j < (int)(PrimeBits / 32 + 2); j++)
		{
			BN_Tmp1.pData[j] = 0;
			BN_Tmp2.pData[j] = 0;
		}
		
		if (HASH == SHA_224)
		{
			for (j = 0; j < 32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j < 4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j < 64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else if (HASH == SHA_256)
		{
			for (j = 0; j < 32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j < 4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j < 64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else
		{
			ret = CTR_INVALID_ALG_PARAMS;
			return ret;
		}
		
		for(;;) {
			//for(j=0; j<SubPrimeBits/8; j++)
				//tSeed[j] = (byte)(random.nextInt());
			
			kcdsa.SeedLen = SubPrimeBits / 8;
			
			if(HASH == SHA_224) {
				ret = KCDSA_PRNG_SHA_224(sha_algInfo, tSeed, kcdsa.SeedLen, bzTmp, PrimeBits - SubPrimeBits - 4);
				if(ret != CTR_SUCCESS) return ret;
			}
			else {
				ret = KCDSA_PRNG_SHA_256(sha_algInfo, tSeed, kcdsa.SeedLen, bzTmp, PrimeBits - SubPrimeBits - 4);
				if(ret != CTR_SUCCESS) return ret;
			}
			
			BIGNUM.OS2BN(bzTmp, (PrimeBits - SubPrimeBits) / 8, BN_Tmp1);
			
			BIGNUM.SetBitDIGIT(BN_Tmp1.pData, PrimeBits - SubPrimeBits - 1);
			BIGNUM.SetBitDIGIT(BN_Tmp1.pData, 0);
			
			if (BIGNUM.MillerRabin(BN_Tmp1) == CTR_SUCCESS) break;
		}
		
		KCDSA_J = new BIGNUM(PrimeBits / 32 + 1);
		
		for (j = BN_Tmp1.Length - 1; j >= 0; j--) KCDSA_J.pData[j] = BN_Tmp1.pData[j];
		KCDSA_J.Length = BN_Tmp1.Length;
		KCDSA_J.Space = BN_Tmp1.Space;
		
		for (Count = 1; Count < (1 << 24); Count++) {
			if (Count == (1 << 24)) return CTR_FATAL_ERROR;
			int tmp = 0;

			tmp = BIGNUM.BIG_W2B(Count);
			tSeed[kcdsa.SeedLen] = (byte) (tmp & 0xff);
			tSeed[kcdsa.SeedLen + 1] = (byte) (tmp >>> 8 & 0xff);
			tSeed[kcdsa.SeedLen + 2] = (byte) (tmp >>> 16 & 0xff);
			tSeed[kcdsa.SeedLen + 3] = (byte) (tmp >>> 24 & 0xff);
			tSeed[kcdsa.SeedLen] = 0;

			if (HASH == SHA_224)	{
				ret = KCDSA_PRNG_SHA_224(sha_algInfo, tSeed, kcdsa.SeedLen + 4, bzTmp, SubPrimeBits);
				if(ret != CTR_SUCCESS) return ret;
			} else {
				ret = KCDSA_PRNG_SHA_256(sha_algInfo, tSeed, kcdsa.SeedLen + 4, bzTmp, SubPrimeBits);
				if(ret != CTR_SUCCESS) return ret;
			}

			BIGNUM.OS2BN(bzTmp, SubPrimeBits / 8, kcdsa.KCDSA_Q);

			BIGNUM.SetBitDIGIT(kcdsa.KCDSA_Q.pData, SubPrimeBits - 1);
			BIGNUM.SetBitDIGIT(kcdsa.KCDSA_Q.pData, 0);

			ret = BIGNUM.BN_Mul(kcdsa.KCDSA_P, BN_Tmp1, kcdsa.KCDSA_Q);
			if(ret != CTR_SUCCESS) return ret;
			if (BIGNUM.CheckBitDIGIT(kcdsa.KCDSA_P.pData, PrimeBits - 1) != 0) continue;
			ret = BIGNUM.BN_SHL(kcdsa.KCDSA_P, kcdsa.KCDSA_P, 1);
			if(ret != CTR_SUCCESS) return ret;
			BIGNUM.SetBitDIGIT(kcdsa.KCDSA_P.pData, 0);

			if (BIGNUM.MillerRabin(kcdsa.KCDSA_Q) != CTR_SUCCESS)	continue;

			if (BIGNUM.MillerRabin(kcdsa.KCDSA_P) == CTR_SUCCESS)	break;
		}
		
		kcdsa.Count = Count;
		
		ret = BIGNUM.BN_SHL(KCDSA_J, KCDSA_J, 1);
		if(ret != CTR_SUCCESS) return ret;
		
		for (;;) {
			//for (i = 0; i < PrimeBits / 32; i++)
				//g[i] = random.nextInt();
			
			for (i = 0; i < PrimeBits / 32; i++) BN_Tmp2.pData[i] = g[i];
			BN_Tmp2.Length = PrimeBits / 32;
			BN_Tmp2.Space = PrimeBits / 32 + 1;

			ret = BIGNUM.BN_ModExp(kcdsa.KCDSA_G, BN_Tmp2, KCDSA_J, kcdsa.KCDSA_P);
			if(ret != CTR_SUCCESS) return ret;

			if (BIGNUM.BN_Cmp(kcdsa.KCDSA_G, BIGNUM.BN_One) != 0)
				break;
		}
		
		ret = CTR_SUCCESS;
		
		if(BN_Tmp1 != null) BIGNUM.DestroyBigNum(BN_Tmp1);
		if(BN_Tmp2 != null) BIGNUM.DestroyBigNum(BN_Tmp2);
		if(KCDSA_J != null) BIGNUM.DestroyBigNum(KCDSA_J);
		return ret;
	}
	
	public static int KISA_KCDSA_GenerateKeyPair(KISA_KCDSA kcdsa, byte[] pbSrc, int dSrcByteLen, int qLen, int HASH) {
		int ret = 0;
		int i = 0;
		BIGNUM BN_Tmp1 = null, XKEY = null;
		
		if(kcdsa == null)
			return CTR_INVALID_POINTER; 
		
		i = kcdsa.KCDSA_P.Length;
		BN_Tmp1 = new BIGNUM(i + 1);
		XKEY = new BIGNUM(qLen / 32);
		
		if(kcdsa.KCDSA_x.Length == 0) {
			ret = BIGNUM.BN_Rand(XKEY, qLen);
			if(ret != CTR_SUCCESS) return ret;
			
			/*p = 2048, q = 224, SHA-224 test vector*/
			/*p = 2048, q = 224, SHA-256 test vector*/
			XKEY.pData[0] = 0xa89150be;
			XKEY.pData[1] = 0xeff64b4c;
			XKEY.pData[2] = 0x4b90ffdf;
			XKEY.pData[3] = 0x046d5de1;
			XKEY.pData[4] = 0xd61495ea;
			XKEY.pData[5] = 0x20d9ba54;
			XKEY.pData[6] = 0xf910456a;
			XKEY.Length = 7;
			XKEY.Space = 8;
			/*p = 2048, q = 256, SHA-256 test vector*/
			/*XKEY.pData[0] = 0xb948da94;
			XKEY.pData[1] = 0xc0a936e2;
			XKEY.pData[2] = 0x2e97da0b;
			XKEY.pData[3] = 0x8b904cf1;
			XKEY.pData[4] = 0x3bf2ab78;
			XKEY.pData[5] = 0x587274d3;
			XKEY.pData[6] = 0xa667cf10;
			XKEY.pData[7] = 0xf0f30814;
			XKEY.Length = 8;
			XKEY.Space = 9;*/
			/*p = 3072, q = 256, SHA-256 test vector*/
			/*XKEY.pData[0] = 0x14dfce52;
			XKEY.pData[1] = 0xf1a369ab;
			XKEY.pData[2] = 0xfa2bb0cd;
			XKEY.pData[3] = 0xc3ca4c8e;
			XKEY.pData[4] = 0xc40e94d7;
			XKEY.pData[5] = 0x47c7ac5b;
			XKEY.pData[6] = 0xd9e9230d;
			XKEY.pData[7] = 0x80f96d39;
			XKEY.Length = 8;
			XKEY.Space = 9;*/
			
			ret = Generate_Random(XKEY, pbSrc, dSrcByteLen, kcdsa.KCDSA_x.pData, qLen, kcdsa, HASH);
			kcdsa.KCDSA_x.Length = qLen / 32;
		}
		
		ret = BIGNUM.BN_ModInv(BN_Tmp1, kcdsa.KCDSA_x, kcdsa.KCDSA_Q);
		
		ret = BIGNUM.BN_ModExp(kcdsa.KCDSA_y, kcdsa.KCDSA_G, BN_Tmp1, kcdsa.KCDSA_P);

		if( BN_Tmp1 != null )  BIGNUM.DestroyBigNum(BN_Tmp1);
		if( XKEY != null )  BIGNUM.DestroyBigNum(XKEY);
		
		return ret;
	}
	
	public static int KISA_KCDSA_sign(KISA_KCDSA kcdsa,byte[] MsgDigest, int MsgDigestLen, byte[] Signature, int HASH, byte[] t_omgri, int omgri_len) {
		byte[] bzTmp = new byte[3072 / 8];
		byte[] bzTmp1 = new byte[64];
		byte[] hashTmp;
		int i = 0, j = 0, qByteLen = 0, DigestLen = 0;
		int ret, siglen;
		BIGNUM BN_K = null, BN_Tmp1 = null, KCDSA_s = null, KKEY = null;
		SHA_ALG_INFO sha_algInfo = new SHA_ALG_INFO();
		
		if (HASH == SHA_224)
		{
			for (j = 0; j<32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j<4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j<64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else if (HASH == SHA_256)
		{
			for (j = 0; j<32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j<4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j<64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else {
			ret = CTR_INVALID_ALG_PARAMS;
			return ret;
		}
		
		if (kcdsa == null)	return CTR_INVALID_POINTER;

		if (HASH == SHA_224)
			DigestLen = 28;
		else if (HASH == SHA_256)
			DigestLen = 32;
		
		qByteLen = 4 * (kcdsa.KCDSA_Q.Length);
		
		if((HASH == SHA_224 && qByteLen == 28) || (HASH == SHA_256 && qByteLen == 32))
			siglen = DigestLen + qByteLen;
		else
			siglen = qByteLen + qByteLen;
		
		if (Signature == null)	return CTR_INVALID_POINTER;
		if (MsgDigest == null)	return CTR_INVALID_POINTER;
		
		i = kcdsa.KCDSA_P.Length;
		BN_K = new BIGNUM(i + 1);
		BN_Tmp1 = new BIGNUM(i + 1);
		
		i = kcdsa.KCDSA_Q.Length;
		KCDSA_s = new BIGNUM(i + 1);
		KKEY = new BIGNUM(i + 1);
		
		//ret = BIGNUM.BN_Rand(KKEY, 8 * qByteLen);
		//if(ret != CTR_SUCCESS) return ret;
		
		/*p = 2048, q = 224, SHA-224 test vector*/
		/*p = 2048, q = 224, SHA-256 test vector*/
		KKEY.pData[0] = 0xc1fb7222;
		KKEY.pData[1] = 0x71382b7d;
		KKEY.pData[2] = 0xd33ad7fb;
		KKEY.pData[3] = 0x04ac91d7;
		KKEY.pData[4] = 0x74f4f9db;
		KKEY.pData[5] = 0xd5ee4a09;
		KKEY.pData[6] = 0xb7b75e77;
		KKEY.Length = 7;
		/*p = 2048, q = 256, SHA-256 test vector*/
		/*KKEY.pData[0] = 0x9475cf69;
		KKEY.pData[1] = 0x3d053f8a;
		KKEY.pData[2] = 0x9f55d297;
		KKEY.pData[3] = 0xb5ef2d93;
		KKEY.pData[4] = 0x59536696;
		KKEY.pData[5] = 0x4b2a759e;
		KKEY.pData[6] = 0xf737ace8;
		KKEY.pData[7] = 0xb2425ced;
		KKEY.Length = 8;*/
		/*p = 3072, q = 256, SHA-256 test vector*/
		/*KKEY.pData[0] = 0x80804468;
		KKEY.pData[1] = 0x8dad0082;
		KKEY.pData[2] = 0x726b22c0;
		KKEY.pData[3] = 0x1acaa16c;
		KKEY.pData[4] = 0xe4f6028e;
		KKEY.pData[5] = 0x0383e4e9;
		KKEY.pData[6] = 0xc87ae1f6;
		KKEY.pData[7] = 0xa3d070cb;
		KKEY.Length = 8;*/
		
		ret = Generate_Random(KKEY, t_omgri, omgri_len, BN_K.pData, kcdsa.KCDSA_Q.Length * 32, kcdsa, HASH);
		BN_K.Length = kcdsa.KCDSA_Q.Length;
		BN_K.Space = kcdsa.KCDSA_Q.Length + 1;
		
		if (BIGNUM.BN_Cmp(BN_K, kcdsa.KCDSA_Q) >= 0) {
			ret = BIGNUM.BN_Sub(BN_K, BN_K, kcdsa.KCDSA_Q);
			if(ret != CTR_SUCCESS) return ret;
		}
		
		ret = BIGNUM.BN_ModExp(BN_Tmp1, kcdsa.KCDSA_G, BN_K, kcdsa.KCDSA_P);
		if(ret != CTR_SUCCESS) return ret;
		
		i = 4 * kcdsa.KCDSA_P.Length;
		ret = BIGNUM.BN2OS(BN_Tmp1, i, bzTmp);
		j = i;
		if (HASH == SHA_224)
		{
			SHA224.SHA224_Init(sha_algInfo);
			SHA224.SHA224_Update(sha_algInfo, bzTmp, j);
			SHA224.SHA224_Final(sha_algInfo, bzTmp);
			for(int k=0; k<28; k++) Signature[k] = bzTmp[k];
		}
		else if (HASH == SHA_256)
		{
			SHA256.SHA256_Init(sha_algInfo);
			SHA256.SHA256_Update(sha_algInfo, bzTmp, j);
			SHA256.SHA256_Final(sha_algInfo, bzTmp);
			if(qByteLen == 28)
				for(int k=0; k<28; k++) Signature[k] = bzTmp[k + 4];
			else
				for(int k=0; k<32; k++) Signature[k] = bzTmp[k];
		}
		
		hashTmp = new byte[64 + MsgDigestLen];
		
		i = kcdsa.KCDSA_y.Length;
		kcdsa.KCDSA_y.Length = 512 / 32;
		ret = BIGNUM.BN2OS(kcdsa.KCDSA_y, 512 / 8, bzTmp1);
		if(ret != CTR_SUCCESS) return ret;
		kcdsa.KCDSA_y.Length = i;
		for(int k=0; k<64; k++) hashTmp[k] = bzTmp1[k];
		for(int k=0; k<MsgDigestLen; k++) hashTmp[k+64] = MsgDigest[k];
		
		if (HASH == SHA_224)
		{
			for (j = 0; j<32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j<4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j<64; j++)
				sha_algInfo.Buffer[j] = 0;
			SHA224.SHA224_Init(sha_algInfo);
			SHA224.SHA224_Update(sha_algInfo, hashTmp, 64 + MsgDigestLen);
			SHA224.SHA224_Final(sha_algInfo, hashTmp);
		}
		else if (HASH == SHA_256)
		{
			for (j = 0; j<32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j<4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j<64; j++)
				sha_algInfo.Buffer[j] = 0;
			SHA256.SHA256_Init(sha_algInfo);
			SHA256.SHA256_Update(sha_algInfo, hashTmp, 64 + MsgDigestLen);
			SHA256.SHA256_Final(sha_algInfo, hashTmp);
		}
		
		if ((HASH == SHA_224 && qByteLen == 28) || (HASH == SHA_256 && qByteLen == 32))
			for (i = 0; i < DigestLen; i++)	bzTmp[i] ^= hashTmp[i];
		else
		{
			for (i = 0; i < qByteLen; i++) bzTmp[i + 4] ^= hashTmp[i + 4];
			for (i = 0; i < qByteLen; i++) bzTmp[i] = bzTmp[i + 4];
		}
		
		BIGNUM.OS2BN(bzTmp, i, BN_Tmp1);
		
		ret = BIGNUM.BN_ModRed(BN_Tmp1, BN_Tmp1, kcdsa.KCDSA_Q);
		if(ret != CTR_SUCCESS) return ret;
		
		ret = BIGNUM.BN_ModSub(BN_K, BN_K, BN_Tmp1, kcdsa.KCDSA_Q);
		if(ret != CTR_SUCCESS) return ret;
		
		ret = BIGNUM.BN_ModMul(KCDSA_s, kcdsa.KCDSA_x, BN_K, kcdsa.KCDSA_Q);
		if(ret != CTR_SUCCESS) return ret;

		ret = BIGNUM.BN2OS(KCDSA_s, qByteLen, Signature, qByteLen);
		if(ret != CTR_SUCCESS) return ret;
		
		if( BN_K != null )  BIGNUM.DestroyBigNum(BN_K);
		if( BN_Tmp1 != null )  BIGNUM.DestroyBigNum(BN_Tmp1);
		if( KCDSA_s != null )  BIGNUM.DestroyBigNum(KCDSA_s);
		if( KKEY != null )  BIGNUM.DestroyBigNum(KKEY);
		
		return siglen;
	}
	
	public static int KISA_KCDSA_verify(KISA_KCDSA kcdsa,byte[] MsgDigest, int MsgDigestLen, byte[] Signature, int SignLen, int HASH) {
		byte[] bzTmp = new byte[3072 / 8];
		byte[] bzTmp1 = new byte[64];
		byte[] hashTmp;
		int i = 0, j = 0, qByteLen = 0, DigestLen = 0;
		int ret;
		BIGNUM BN_Tmp1 = null, BN_Tmp2 = null, BN_Tmp3 = null, KCDSA_s = null;
		SHA_ALG_INFO sha_algInfo = new SHA_ALG_INFO();
		
		if (HASH == SHA_224)
		{
			for (j = 0; j<32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j<4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j<64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else if (HASH == SHA_256)
		{
			for (j = 0; j<32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for (j = 0; j<4; j++)
				sha_algInfo.Count[j] = 0;
			for (j = 0; j<64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else {
			ret = CTR_INVALID_ALG_PARAMS;
			return ret;
		}
		
		if (kcdsa == null || MsgDigest == null || Signature == null)	return CTR_INVALID_POINTER;

		if (HASH == SHA_224)
			DigestLen = 28;
		else if (HASH == SHA_256)
			DigestLen = 32;
		
		qByteLen = 4 * (kcdsa.KCDSA_Q.Length);
		
		if ((SignLen != DigestLen + qByteLen) && (SignLen != qByteLen + qByteLen))	return CTR_INVALID_SIGNATURE_LEN;
		
		i = kcdsa.KCDSA_P.Length;
		BN_Tmp1 = new BIGNUM(i);
		BN_Tmp2 = new BIGNUM(i);
		BN_Tmp3 = new BIGNUM(i);
		
		i = kcdsa.KCDSA_Q.Length;
		KCDSA_s = new BIGNUM(i);
		
		for(int k=0; k<qByteLen; k++) bzTmp[k] = Signature[k];
		BIGNUM.OS2BN(Signature, qByteLen, qByteLen, KCDSA_s);
		
		ret = CTR_VERIFY_FAIL;
		if (BIGNUM.BN_Cmp(KCDSA_s, kcdsa.KCDSA_G) >= 0) return ret;
		
		hashTmp = new byte[64 + MsgDigestLen];
		i = kcdsa.KCDSA_y.Length;
		kcdsa.KCDSA_y.Length = 512 / 32;
		ret = BIGNUM.BN2OS(kcdsa.KCDSA_y, 512 / 8, bzTmp1);
		if(ret != CTR_SUCCESS) return ret;
		kcdsa.KCDSA_y.Length = i;
		for(int k=0; k<64; k++) hashTmp[k] = bzTmp1[k];
		for(int k=0; k<MsgDigestLen; k++) hashTmp[k+64] = MsgDigest[k];
		
		if (HASH == SHA_224)
		{
			SHA224.SHA224_Init(sha_algInfo);
			SHA224.SHA224_Update(sha_algInfo, hashTmp, 64 + MsgDigestLen);
			SHA224.SHA224_Final(sha_algInfo, hashTmp);
		}
		else if (HASH == SHA_256)
		{
			SHA256.SHA256_Init(sha_algInfo);
			SHA256.SHA256_Update(sha_algInfo, hashTmp, 64 + MsgDigestLen);
			SHA256.SHA256_Final(sha_algInfo, hashTmp);
		}
		
		if ((HASH == SHA_224 && qByteLen == 28) || (HASH == SHA_256 && qByteLen == 32))
			for (i = 0; i < DigestLen; i++)	bzTmp[i] ^= hashTmp[i];
		else
			for (i = 0; i < qByteLen; i++) bzTmp[i] ^= hashTmp[i + 4];
		
		BIGNUM.OS2BN(bzTmp, i, BN_Tmp1);
		ret = BIGNUM.BN_ModRed(BN_Tmp1, BN_Tmp1, kcdsa.KCDSA_Q);
		if(ret != CTR_SUCCESS) return ret;
		
		ret = BIGNUM.BN_ModExp(BN_Tmp2, kcdsa.KCDSA_y, KCDSA_s, kcdsa.KCDSA_P);
		if(ret != CTR_SUCCESS) return ret;
		ret = BIGNUM.BN_ModExp(BN_Tmp3, kcdsa.KCDSA_G, BN_Tmp1, kcdsa.KCDSA_P);
		if(ret != CTR_SUCCESS) return ret;
		ret = BIGNUM.BN_ModMul(BN_Tmp1, BN_Tmp2, BN_Tmp3, kcdsa.KCDSA_P);
		if(ret != CTR_SUCCESS) return ret;
		
		i = 4 * kcdsa.KCDSA_P.Length;
		ret = BIGNUM.BN2OS(BN_Tmp1, i, bzTmp);
		j = i;
		i = 0;
		if (HASH == SHA_224)
		{
			SHA224.SHA224_Init(sha_algInfo);
			SHA224.SHA224_Update(sha_algInfo, bzTmp, j);
			SHA224.SHA224_Final(sha_algInfo, bzTmp);

			ret = CTR_VERIFY_FAIL;
			
			for(int k=0; k<28; k++) if(bzTmp[k] != Signature[k]) return ret;
		}
		else if (HASH == SHA_256)
		{
			SHA256.SHA256_Init(sha_algInfo);
			SHA256.SHA256_Update(sha_algInfo, bzTmp, j);
			SHA256.SHA256_Final(sha_algInfo, bzTmp);

			ret = CTR_VERIFY_FAIL;
			int k;

			if (qByteLen == 28) {
				for(k=0; k<qByteLen; k++) if(bzTmp[k+4] != Signature[k]) return ret;
			}
			else {
				for(k=0; k<32; k++) if(bzTmp[k] != Signature[k]) return ret;
			}
		}
		
		ret = CTR_SUCCESS;
		
		if( BN_Tmp1 != null )  BIGNUM.DestroyBigNum(BN_Tmp1);
		if( BN_Tmp2 != null )  BIGNUM.DestroyBigNum(BN_Tmp2);
		if( BN_Tmp3 != null )  BIGNUM.DestroyBigNum(BN_Tmp3);
		if( KCDSA_s != null )  BIGNUM.DestroyBigNum(KCDSA_s);
		
		return ret;
	}
	
	public static int KISA_KCDSA_set_params(KISA_KCDSA kcdsa, int[] p, int plen, int[] q, int qlen, int[] g, int glen, int[] private_key, int private_keylen, int[] public_key, int public_keylen){
        for(int i = 0; i < plen; i ++){
            kcdsa.KCDSA_P.pData[i] = p[i];
        }
        kcdsa.KCDSA_P.Length = plen;
        kcdsa.KCDSA_P.Space = plen + 1;

        for(int i = 0; i < qlen; i ++){
            kcdsa.KCDSA_Q.pData[i] = q[i];
        }
        kcdsa.KCDSA_Q.Length = qlen;
        kcdsa.KCDSA_Q.Space = qlen + 1;

        for(int i = 0; i < glen; i ++){
            kcdsa.KCDSA_G.pData[i] = g[i];
        }
        kcdsa.KCDSA_G.Length = glen;
        kcdsa.KCDSA_G.Space = glen + 1;

        for(int i = 0; i < private_keylen; i ++){
            kcdsa.KCDSA_x.pData[i] = private_key[i];
        }
        kcdsa.KCDSA_x.Length = private_keylen;
        kcdsa.KCDSA_x.Space = private_keylen + 1;
		
		for(int i = 0; i < public_keylen; i ++){
            kcdsa.KCDSA_x.pData[i] = public_key[i];
        }
        kcdsa.KCDSA_x.Length = public_keylen;
        kcdsa.KCDSA_x.Space = public_keylen + 1;

        return 0;
    }
	
	public static int KISA_KCDSA_DestroyObject(KISA_KCDSA kcdsa){
        kcdsa.KCDSA_P = null;
        kcdsa.KCDSA_Q = null;
        kcdsa.KCDSA_G = null;
        kcdsa.KCDSA_x = null;
        kcdsa.KCDSA_y = null;

        if((kcdsa.KCDSA_P != null) || (kcdsa.KCDSA_Q != null) || (kcdsa.KCDSA_G != null) || (kcdsa.KCDSA_x != null) || (kcdsa.KCDSA_y != null))
			return -1;

        return 0;
    }
	
	private static int Generate_Random(BIGNUM XKEY, byte[] pbSrc, int dSrcByteLen, int[] X, int XBitLen, KISA_KCDSA kcdsa, int HASH) {
		int i, j;
		int ret = 0;
		byte[] bzTmp1 = null, bzTmp2 = null;
		BIGNUM VAL = null, BN_Tmp1 = null;
		SHA_ALG_INFO sha_algInfo = new SHA_ALG_INFO();
		
		if(HASH == SHA_224) {
			bzTmp1 = new byte[224 / 8 + 1];
			bzTmp2 = new byte[224 / 8 + 1];
			for(j = 0; j < 32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for(j = 0; j < 4; j++)
				sha_algInfo.Count[j] = 0;
			for(j = 0; j < 64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else if(HASH == SHA_256) {
			bzTmp1 = new byte[256 / 8 + 1];
			bzTmp2 = new byte[256 / 8 + 1];
			for(j = 0; j < 32 / 4; j++)
				sha_algInfo.ChainVar[j] = 0;
			for(j = 0; j < 4; j++)
				sha_algInfo.Count[j] = 0;
			for(j = 0; j < 64; j++)
				sha_algInfo.Buffer[j] = 0;
		}
		else {
			ret = CTR_INVALID_ALG_PARAMS;
			return ret;
		}
		
		VAL = new BIGNUM(XBitLen / 32);
		BN_Tmp1 = new BIGNUM(XBitLen / 32);
		
		for(j = 0; j < XBitLen / 32 + 1; j++) {
			VAL.pData[j] = 0;
			BN_Tmp1.pData[j] = 0;
		}
		
		if(HASH == SHA_224) {
			ret = KCDSA_PRNG_SHA_224(sha_algInfo, pbSrc, dSrcByteLen, bzTmp1, XBitLen);
			if(ret != CTR_SUCCESS) return ret;
		}
		else if(HASH == SHA_256) {
			ret = KCDSA_PRNG_SHA_256(sha_algInfo, pbSrc, dSrcByteLen, bzTmp1, XBitLen);
			if(ret != CTR_SUCCESS) return ret;
		}
		
		BIGNUM.OS2BN(bzTmp1, XBitLen / 8, BN_Tmp1);
		
		BIGNUM.BN_Add(VAL, XKEY, BN_Tmp1);
		
		if(VAL.pData[XBitLen / 32] != 0) {
			VAL.pData[XBitLen / 32] = 0;
			VAL.Length -= 1;
			VAL.Space -= 1;
		}
		
		BIGNUM.BN2OS(VAL, VAL.Length * 4, bzTmp1);
		
		if(HASH == SHA_224) {
			ret = KCDSA_PRNG_SHA_224(sha_algInfo, bzTmp1, VAL.Length*4, bzTmp2, XBitLen);
			if(ret != CTR_SUCCESS) return ret;
		}
		else if(HASH == SHA_256) {
			ret = KCDSA_PRNG_SHA_256(sha_algInfo, bzTmp1, VAL.Length*4, bzTmp2, XBitLen);
			if(ret != CTR_SUCCESS) return ret;
		}
		
		BIGNUM.OS2BN(bzTmp2, XBitLen / 8, BN_Tmp1);
		
		while(BIGNUM.BN_Cmp(BN_Tmp1, kcdsa.KCDSA_Q) >= 0)
			ret = BIGNUM.BN_Sub(BN_Tmp1, BN_Tmp1, kcdsa.KCDSA_Q);
		
		for(i=0;i<XBitLen / 32;i++) X[i] = BN_Tmp1.pData[i];
		
		if(VAL != null) BIGNUM.DestroyBigNum(VAL);
		if(BN_Tmp1 != null) BIGNUM.DestroyBigNum(BN_Tmp1);
		
		return ret;
	}
	
	private static int KCDSA_PRNG_SHA_224(SHA_ALG_INFO SHA224_AlgInfo, byte[] pbSrc, int dSrcByteLen, byte[] pbDst, int dDstBitLen) {
		int i, Count = 0;
		int tempLen = dSrcByteLen;
		byte[] tempSrc = new byte[tempLen];
		byte[] DigestValue = new byte[28];
		
		for(i=0;i<dSrcByteLen;i++) tempSrc[i] = pbSrc[i];
		
		i = ((dDstBitLen + 7) & 0xFFFFFFF8) / 8;

		for (Count = 0;; Count++) {
			SHA224.SHA224_Init(SHA224_AlgInfo);
			SHA224.SHA224_Update(SHA224_AlgInfo, tempSrc, tempLen);
			SHA224.SHA224_Update(SHA224_AlgInfo, Count, 1);
			SHA224.SHA224_Final(SHA224_AlgInfo, DigestValue);
			if(i >= 28) {
				i -= 28;
				for(int j = 0; j < 28; j++) pbDst[j + i] = DigestValue[j];
				if(i == 0) break;
			}
			else {
				for(int j = 0; j < i; j++) pbDst[j] = DigestValue[j + 28 - i];
				break;
			}
		
		}
		
		i = dDstBitLen & 0x07;
		
		if(i != 0) pbDst[0] &= (1 << i) - 1;
		
		return 0;
	}
	
	private static int KCDSA_PRNG_SHA_256(SHA_ALG_INFO SHA256_AlgInfo, byte[] pbSrc, int dSrcByteLen, byte[] pbDst, int dDstBitLen) {
		int i, Count = 0;
		int tempLen = dSrcByteLen;
		byte[] tempSrc = new byte[tempLen];
		byte[] DigestValue = new byte[32];
		
		for(i=0;i<dSrcByteLen;i++) tempSrc[i] = pbSrc[i];
		
		i = ((dDstBitLen + 7) & 0xFFFFFFF8) / 8;

		for (Count = 0;; Count++) {
			SHA256.SHA256_Init(SHA256_AlgInfo);
			SHA256.SHA256_Update(SHA256_AlgInfo, tempSrc, tempLen);
			SHA256.SHA256_Update(SHA256_AlgInfo, Count, 1);
			SHA256.SHA256_Final(SHA256_AlgInfo, DigestValue);
			if(i >= 32) {
				i -= 32;
				for(int j = 0; j < 32; j++) pbDst[j + i] = DigestValue[j];
				if(i == 0)
					break;
			}
			else {
				for(int j = 0; j < i; j++) pbDst[j] = DigestValue[j + 32 - i];
				break;
			}
		
		}
		
		i = dDstBitLen & 0x07;
		
		if(i != 0)
			pbDst[0] &= (1 << i) - 1;
		
		return 0;
	}
}
