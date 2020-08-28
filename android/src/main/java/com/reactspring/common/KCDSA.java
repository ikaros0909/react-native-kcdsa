package com.reactspring.common;

public class KCDSA {
    public static final int SHA224 = 1;
    public static final int SHA256 = 2;

    static final int BN_MAX_BITS = 3072;
    static final int MAX_SEED_LEN = 64;
    static final int BitsInDIGIT = 32;

    static {
        System.loadLibrary("KCDSA");
    }

    private native int KcdsaGenerateParameters(int plen, int qlen, int[] p_data, int[] q_data, int[] g_data, int[] kcdsa_param, int HASH);
    private static native int KcdsaGenerateKeyPair(int[] p_data, int[] q_data, int[] g_data, int[] x_data, int[] y_data, int[] kcdsa_param1, int[] kcdsa_param2, byte[] pbSrc, int dSrcByteLen, int qlen, int HASH);
    private static native int KcdsaSign(int[] p_data, int[] q_data, int[] g_data, int[] x_data, int[] kcdsa_param1, int[] kcdsa_param2, byte[] msg, int msglen, byte[] sig, int HASH, byte[] t_omgri, int omgri_len);
    private static native int KcdsaVerify(int[] p_data, int[] q_data, int[] g_data, int[] y_data, int[] kcdsa_param, byte[] msg, int msglen, byte[] sig, int siglen, int HASH);

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

    int KISA_KCDSA_GenerateParameters(int plen, int qlen, KISA_KCDSA kcdsa, int HASH){
        int[] kcdsa_param = new int[5];
        int result;

        result = KcdsaGenerateParameters(plen, qlen, kcdsa.KCDSA_P.pData, kcdsa.KCDSA_Q.pData, kcdsa.KCDSA_G.pData, kcdsa_param, HASH);
        if(result != 0) return result;

        kcdsa.KCDSA_P.Length = kcdsa_param[0];
        kcdsa.KCDSA_Q.Length = kcdsa_param[1];
        kcdsa.KCDSA_G.Length = kcdsa_param[2];
        kcdsa.Count = kcdsa_param[3];
        kcdsa.SeedLen = kcdsa_param[4];

        return result;
    }

    public static int KISA_KCDSA_GenerateKeyPair(KISA_KCDSA kcdsa, byte[] pbSrc, int dSrcByteLen, int qlen, int HASH){
		int[] kcdsa_param1 = null;
        int[] kcdsa_param2 = null;
        int result;

		if(kcdsa.KCDSA_x.Length == 0){
			kcdsa_param1 = new int[3];
			kcdsa_param2 = new int[2];
			kcdsa_param1[0] = kcdsa.KCDSA_P.Length;
			kcdsa_param1[1] = kcdsa.KCDSA_Q.Length;
			kcdsa_param1[2] = kcdsa.KCDSA_G.Length;
		}
		else{
			kcdsa_param1 = new int[4];
			kcdsa_param2 = new int[1];
			kcdsa_param1[0] = kcdsa.KCDSA_P.Length;
			kcdsa_param1[1] = kcdsa.KCDSA_Q.Length;
			kcdsa_param1[2] = kcdsa.KCDSA_G.Length;
			kcdsa_param1[3] = kcdsa.KCDSA_x.Length;
		}

        result = KcdsaGenerateKeyPair(kcdsa.KCDSA_P.pData, kcdsa.KCDSA_Q.pData, kcdsa.KCDSA_G.pData, kcdsa.KCDSA_x.pData, kcdsa.KCDSA_y.pData, kcdsa_param1, kcdsa_param2, pbSrc, dSrcByteLen, qlen, HASH);

        if(result != 0) return result;

		if(kcdsa.KCDSA_x.Length == 0){
			kcdsa.KCDSA_x.Length = kcdsa_param2[0];
			kcdsa.KCDSA_y.Length = kcdsa_param2[1];
		}
		else{
			kcdsa.KCDSA_y.Length = kcdsa_param2[0];
		}

        return result;
    }

    public static int KISA_KCDSA_sign(KISA_KCDSA kcdsa, byte[] msg, int msglen, byte[] sig, int HASH, byte[] kInput, int kInputLen){
        int[] kcdsa_param1 = new int[4];
        int[] kcdsa_param2 = new int[1];
        int result;

        kcdsa_param1[0] = kcdsa.KCDSA_P.Length;
        kcdsa_param1[1] = kcdsa.KCDSA_Q.Length;
        kcdsa_param1[2] = kcdsa.KCDSA_G.Length;
        kcdsa_param1[3] = kcdsa.KCDSA_x.Length;

        result = KcdsaSign(kcdsa.KCDSA_P.pData, kcdsa.KCDSA_Q.pData, kcdsa.KCDSA_G.pData, kcdsa.KCDSA_x.pData, kcdsa_param1, kcdsa_param2, msg, msglen, sig, HASH, kInput, kInputLen);
        if(result != 0) return -1;

        return kcdsa_param2[0];
    }

    public static int KISA_KCDSA_verify(KISA_KCDSA kcdsa, byte[] msg, int msglen, byte[] sig, int siglen, int HASH){
        int[] kcdsa_param = new int[4];
        int result;

        kcdsa_param[0] = kcdsa.KCDSA_P.Length;
        kcdsa_param[1] = kcdsa.KCDSA_Q.Length;
        kcdsa_param[2] = kcdsa.KCDSA_G.Length;
        kcdsa_param[3] = kcdsa.KCDSA_y.Length;

        result = KcdsaVerify(kcdsa.KCDSA_P.pData, kcdsa.KCDSA_Q.pData, kcdsa.KCDSA_G.pData, kcdsa.KCDSA_y.pData, kcdsa_param, msg, msglen, sig, siglen, HASH);
        if(result != 0) return result;

        return result;
    }

    static int KISA_KCDSA_DestroyObject(KISA_KCDSA kcdsa){
        kcdsa.KCDSA_P = null;
        kcdsa.KCDSA_Q = null;
        kcdsa.KCDSA_G = null;
        kcdsa.KCDSA_x = null;
        kcdsa.KCDSA_y = null;

        if((kcdsa.KCDSA_P != null) || (kcdsa.KCDSA_Q != null) || (kcdsa.KCDSA_G != null) || (kcdsa.KCDSA_x != null) || (kcdsa.KCDSA_y != null))
			return -1;

        return 0;
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
}
