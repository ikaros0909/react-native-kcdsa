package com.reactspring.common;

import java.util.Random;

public class BIGNUM {
	int Length;
    int Space;
    int[] pData;

    BIGNUM(int tt){
        Length = 0;
        Space = tt + 1;
        pData = new int[tt + 1];
    }
    
    static BIGNUM BN_Zero = new BIGNUM(1);
    static BIGNUM BN_One = new BIGNUM(1);
    static BIGNUM BN_Two = new BIGNUM(1);
    static int bn_Zero[] = {0, 0};
    static int bn_One[] = {1, 0};
    
    static int Montgo_Inv;
    static int[] Montgo_Rto2modN = new int[96+2];
    
    static int[][] Window_PreData = new int[1 << (6 - 1)][96 + 1];
    
    static final int Kara_Sqr_Length = 9632 / 100;
    static final int Kara_Mul_Length = 9632 % 100;
    
    static final int BN_MAX_BITS = 3072; 
    static final int MaxDIGIT = 96;
    
    
    static final int Max_W_size = 6;
    static int[][] Add_Chain = new int[3072/6][2];
    static final int FirstWindowMayBeEven = 0;
    static final int FirstWindowMustBeOdd = 1;
    
    public static void DestroyBigNum(BIGNUM BN_Src) {
    	BN_Src.Length = 0;
    	BN_Src.pData = null;
    	BN_Src.Space = 0;
    }
    
    public static int BN2OS(BIGNUM BN_Src, int dDstLen, byte[] pbDst) {
    	int i;
    	if(4*BN_Src.Length <= dDstLen) {
    		for( i=0; i<dDstLen; i++)
    			pbDst[i] = 0;
    		for( i=0; (dDstLen!=0) && (i<BN_Src.Length); i++) {
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]    ) & 0xFF);
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]>> 8) & 0xFF);
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]>>16) & 0xFF);
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]>>24) & 0xFF);
    		}
    	}
    	else {
    		i = (4*BN_Src.Length) - dDstLen;
    		if( i>=4 )
    			return KCDSA.CTR_BUFFER_TOO_SMALL;
    		else if( BN_Src.pData[BN_Src.Length-1]>>(8*(4-i)) != 0  )
    			return KCDSA.CTR_BUFFER_TOO_SMALL;

    		for( i=0;  ; i++) {
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]    ) & 0xFF);
    			if( dDstLen==0 )	break;
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]>> 8) & 0xFF);
    			if( dDstLen==0 )	break;
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]>>16) & 0xFF);
    			if( dDstLen==0 )	break;
    			pbDst[--dDstLen] = (byte) ((BN_Src.pData[i]>>24) & 0xFF);
    			if( dDstLen==0 )	break;
    		}
    	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN2OS(BIGNUM BN_Src, int dDstLen, byte[] pbDst, int k) {
    	int i;
    	if(4*BN_Src.Length <= dDstLen) {
    		for( i=0; i<dDstLen; i++)
    			pbDst[i+k] = 0;
    		for( i=0; (dDstLen!=0) && (i<BN_Src.Length); i++) {
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]    ) & 0xFF);
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]>> 8) & 0xFF);
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]>>16) & 0xFF);
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]>>24) & 0xFF);
    		}
    	}
    	else {
    		i = (4*BN_Src.Length) - dDstLen;
    		if( i>=4 )
    			return KCDSA.CTR_BUFFER_TOO_SMALL;
    		else if( BN_Src.pData[BN_Src.Length-1]>>(8*(4-i)) != 0  )
    			return KCDSA.CTR_BUFFER_TOO_SMALL;

    		for( i=0;  ; i++) {
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]    ) & 0xFF);
    			if( dDstLen==0 )	break;
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]>> 8) & 0xFF);
    			if( dDstLen==0 )	break;
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]>>16) & 0xFF);
    			if( dDstLen==0 )	break;
    			pbDst[--dDstLen+k] = (byte) ((BN_Src.pData[i]>>24) & 0xFF);
    			if( dDstLen==0 )	break;
    		}
    	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static void OS2BN(byte[] pbSrc, int dSrcLen, BIGNUM BN_Dst) {
    	BN_Dst.Length = 0;
    	BN_Dst.pData[0] = 0;
    	
    	for(int i = 0; i < dSrcLen; i++) {
    		BN_SHL(BN_Dst, BN_Dst, 8);
    		BN_Dst.pData[0] ^= pbSrc[i] & 0xff;
    		if(BN_Dst.Length == 0)
    			BN_Dst.Length = 1;
    	}
    }
    
    public static void OS2BN(byte[] pbSrc, int s, int dSrcLen, BIGNUM BN_Dst) {
    	BN_Dst.Length = 0;
    	BN_Dst.pData[0] = 0;
    	
    	for(int i = 0; i < dSrcLen; i++) {
    		BN_SHL(BN_Dst, BN_Dst, 8);
    		BN_Dst.pData[0] ^= pbSrc[i+s] & 0xff;
    		if(BN_Dst.Length == 0)
    			BN_Dst.Length = 1;
    	}
    }
    
    public static int BN_Rand(BIGNUM BN_Dst, int BitLen) {
    	int	i, j;
    	int temp_rand;
    	Random random = new Random();
    	
    	for( i=0; i<BitLen/32; i++){
    		temp_rand = random.nextInt();
    		BN_Dst.pData[i] = random.nextInt() ^ (temp_rand<<11) ^ (temp_rand<<19);
    	}
    	
    	j = BitLen % 32;
    	if( j != 0 ) {
    		temp_rand = random.nextInt();
    		BN_Dst.pData[i] = random.nextInt() ^ (temp_rand<<11) ^ (temp_rand<<19);
    		BN_Dst.pData[i] &= ((1)<<j) - 1;
    		i++;
    	}
    	
    	BN_Dst.Length = (BitLen-1)/32 + 1;

    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_SHL(BIGNUM BN_Dst, BIGNUM BN_Src, int NumOfShift) {
    	int i, t;
    	
    	if(BN_Src.Length == 0)
    		return BN_Copy(BN_Dst, BN_Zero);
    	
    	t = NumOfShift % 32;
    	if(t!=0) {
    		BN_Dst.Length = BN_Src.Length;
    		t = bn_SHL(BN_Dst.pData, BN_Src.pData, BN_Src.Length, t);
    		if(t!=0)
    			BN_Dst.pData[BN_Dst.Length++] = t;
    	}
    	
    	t = NumOfShift / 32;
    	if(t!=0) {
    		BN_Dst.Length = BN_Src.Length + t;
    		for(i = BN_Dst.Length-t-1; i != -1; i--)
    			BN_Dst.pData[t+i] = BN_Src.pData[i];
    		for(i=0; i<t; i++)
    			BN_Dst.pData[i] = 0;
    	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_SHR(BIGNUM BN_Dst, BIGNUM BN_Src, int NumOfShift) {
    	int i, t;
    	
    	t = NumOfShift / 32;
    	if(t!=0) {
    		if(t>=BN_Src.Length)
    			return BN_Copy(BN_Dst, BN_Zero);
    		
    		for(i=0; i<BN_Src.Length-t; i++)
    			BN_Dst.pData[i] = BN_Src.pData[i+t];
    		BN_Dst.Length = BN_Src.Length - t;
    	}
    	else
    		BN_Copy(BN_Dst, BN_Src);
    	
    	t = NumOfShift % 32;
    	if(t!=0)
    		bn_SHR(BN_Dst.pData, BN_Dst.pData, BN_Dst.Length, t);
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static void BN_Add(BIGNUM BN_Dst, BIGNUM BN_Src1, BIGNUM BN_Src2) {
    	int tmp, carry;
    	
    	if(BN_Src1.Length == 0)
    		BN_Copy(BN_Dst, BN_Src2);
    	if(BN_Src2.Length == 0)
    		BN_Copy(BN_Dst, BN_Src1);
    	
    	if(BN_Src1.Length >= BN_Src2.Length) {
    		tmp = BN_Src2.Length;
    		BN_Dst.Length = BN_Src1.Length;
    		carry = bn_Add(BN_Dst.pData, BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, tmp);
    	}
    	else {
    		tmp = BN_Src1.Length;
    		BN_Dst.Length = BN_Src2.Length;
    		carry = bn_Add(BN_Dst.pData, BN_Src2.pData, BN_Src2.Length, BN_Src1.pData, tmp);
    	}
    	
    	if(carry != 0)
    		BN_Dst.pData[BN_Dst.Length++] = carry;
    }
    
    public static int BN_Sub(BIGNUM BN_Dst, BIGNUM BN_Src1, BIGNUM BN_Src2) {
    	int tmp, carry;
    	
    	if( bn_Cmp(BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, BN_Src2.Length)<0 )
    		return KCDSA.CTR_BN_NEGATIVE_RESULT;

	 	tmp = BN_Src2.Length;
	 	BN_Dst.Length = BN_Src1.Length;
	 	carry = bn_Sub(BN_Dst.pData, BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, tmp);
	
	 	if( carry != 0 )
	 		BN_Dst.pData[BN_Dst.Length++] = carry;
	
	 	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_Mul(BIGNUM BN_Dst, BIGNUM BN_Multiplicand, BIGNUM BN_Multiplier) {
    	BN_Dst.Length = BN_Multiplicand.Length + BN_Multiplier.Length;
    	if( (BN_Multiplicand.Length==0) || (BN_Multiplier.Length==0) ) {
    		return KCDSA.CTR_SUCCESS;
    	}
    	else if( BN_Multiplicand.Length>BN_Multiplier.Length ) {
    		bn_Mul(BN_Dst.pData, BN_Multiplicand.pData, BN_Multiplicand.Length, BN_Multiplier.pData, BN_Multiplier.Length);
    	}
    	else {
    		bn_Mul(BN_Dst.pData, BN_Multiplier.pData, BN_Multiplier.Length, BN_Multiplicand.pData, BN_Multiplicand.Length);
    	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_Copy(BIGNUM BN_Dst, BIGNUM BN_Src) {
    	if(BN_Dst != BN_Src) {
    		BN_Dst.Length = BN_Src.Length;
    		for(int i = 0; i < BN_Dst.Length; i++)
    			BN_Dst.pData[i] = BN_Src.pData[i];
    	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_Cmp(BIGNUM BN_Src1, BIGNUM BN_Src2) {
    	if( BN_Src1.Length >= BN_Src2.Length )
    		return  bn_Cmp(BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, BN_Src2.Length);
    	else
    		return -bn_Cmp(BN_Src2.pData, BN_Src2.Length, BN_Src1.pData, BN_Src1.Length);
    }
    
    public static int BN_ModSub(BIGNUM BN_Dst, BIGNUM BN_Src1, BIGNUM BN_Src2, BIGNUM BN_Modulus) {
    	if( (BN_Cmp(BN_Src1, BN_Modulus)>=0) || (BN_Cmp(BN_Src2, BN_Modulus)>=0) )
    		return KCDSA.ERROR_OverModulus;
    	
    	if( bn_Cmp(BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, BN_Src2.Length)>=0 ) {
    		BN_Dst.Length = BN_Src1.Length;
    		bn_Sub(BN_Dst.pData, BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, BN_Src2.Length);
	 	}
	 	else {
	 		BN_Dst.Length = BN_Modulus.Length;
	 		bn_Add(BN_Dst.pData, BN_Modulus.pData, BN_Modulus.Length, BN_Src1.pData, BN_Src1.Length);
	 		bn_Sub(BN_Dst.pData, BN_Dst.pData, BN_Dst.Length, BN_Src2.pData, BN_Src2.Length);
	 	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_ModMul(BIGNUM BN_Dst, BIGNUM BN_Src1, BIGNUM BN_Src2, BIGNUM BN_Modulus) {
    	int i, ret;
    	int[] Value = new int[2*(MaxDIGIT+2)];
    	
    	bn_Mul(Value, BN_Src1.pData, BN_Src1.Length, BN_Src2.pData, BN_Src2.Length);

    	ret = Classical_REDC(Value, BN_Src1.Length+BN_Src2.Length, BN_Modulus.pData, BN_Modulus.Length);
		if( ret!=KCDSA.CTR_SUCCESS )	return ret;
	
		BN_Dst.Length = BN_Modulus.Length;
		for( i=0; i<BN_Modulus.Length; i++)	BN_Dst.pData[i] = Value[i];
		
		return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_ModRed(BIGNUM BN_Dst, BIGNUM BN_Src, BIGNUM BN_Modulus) {
    	int i, ret;
    	int[] Value = new int[2*(MaxDIGIT+2)];
    	
    	if( BN_Cmp(BN_Src, BN_Modulus)<0 )
    		return BN_Copy(BN_Dst, BN_Src);
    	
    	for( i=0; i<BN_Src.Length; i++)	Value[i] = BN_Src.pData[i];

    	ret = Classical_REDC(Value, BN_Src.Length, BN_Modulus.pData, BN_Modulus.Length);
    	if( ret!=KCDSA.CTR_SUCCESS )	return ret;
    	
    	for( i=0; i<BN_Modulus.Length; i++)	BN_Dst.pData[i] = Value[i];
    	
    	BN_Dst.Length = BN_Modulus.Length;
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int BN_ModInv(BIGNUM BN_Dst, BIGNUM BN_Src, BIGNUM BN_Modulus) {
    	int i, ret;
    	int[] BN_Temp = new int[MaxDIGIT+2];
    	
    	for( i=0; i<BN_Src.Length; i++)		BN_Temp[i] = BN_Src.pData[i];
    	for(  ; i<BN_Modulus.Length; i++)		BN_Temp[i] = 0;
    	
    	BN_Dst.Length = BN_Modulus.Length;
    	ret = bn_Euclid(BN_Dst.pData, BN_Temp, BN_Modulus.pData, BN_Modulus.Length);
    	
    	return ret;
    }
    
    public static int BN_ModExp(BIGNUM BN_Dst, BIGNUM BN_Base, BIGNUM BN_Exponent, BIGNUM BN_Modulus) {
    	int ret;
    	ret = bn_ModExp(BN_Dst.pData, BN_Base.pData, BN_Base.Length, BN_Exponent.pData, BN_Exponent.Length, BN_Modulus.pData, BN_Modulus.Length);
    	
    	if(ret!=KCDSA.CTR_SUCCESS) return ret;
    	
    	BN_Dst.Length = BN_Modulus.Length;
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static void bn_Copy(int[] L_Dst, int[] L_Src, int SrcLen) {
    	int i;
    	
    	for(i=0; i<SrcLen; i++)
    		L_Dst[i] = L_Src[i];
    }
    
    public static void bn_Copy(int[] L_Dst, int[] L_Src, int n, int SrcLen) {
    	int i;
    	
    	for(i=0; i<SrcLen; i++)
    		L_Dst[i] = L_Src[i+n];
    }
    
    public static int bn_SHL(int[] L_Dst, int[] L_Src, int SrcLen, int NumOfShift) {
    	int i = SrcLen - 1;
    	int ret;
    	
    	ret = L_Src[i] >>> (32 - NumOfShift);
   		for(; i!=0; i--)
   			L_Dst[i] = (L_Src[i]<<NumOfShift) ^ (L_Src[i-1]>>>(32-NumOfShift));
   		L_Dst[i] = L_Src[i] << NumOfShift;
    	
    	return ret;
    }
    
    public static int bn_SHL(int[] L_Dst, int s, int[] L_Src, int n, int SrcLen, int NumOfShift) {
    	int i = SrcLen - 1;
    	int ret;
    	
    	ret = L_Src[i+n] >>> (32 - NumOfShift);
   		for(; i!=0; i--)
   			L_Dst[i+s] = (L_Src[i+n]<<NumOfShift) ^ (L_Src[i-1+n]>>>(32-NumOfShift));
   		L_Dst[i+s] = L_Src[i+n] << NumOfShift;
    	
    	return ret;
    }
    
    public static int bn_SHR(int[] L_Dst, int[] L_Src, int SrcLen, int NumOfShift) {
    	int i = 0;
    	int ret;
    	
    	ret = L_Src[i] << (32 - NumOfShift);
   		for(i=0 ; i<SrcLen-1; i++)
   			L_Dst[i] = (L_Src[i]>>>NumOfShift) ^ (L_Src[i+1]<<(32-NumOfShift));
   		L_Dst[i] = L_Src[i] >>> NumOfShift;
    	
    	return ret;
    }
    
    public static int bn_Add(int[] L_Dst, int[] L_Src1, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( (L_Src2[i]==-1) && (carry==1) )
    			L_Dst[i] = L_Src1[i];
    		else {
    			tmp = L_Src2[i] + carry;
    			L_Dst[i] = L_Src1[i] + tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(tmp);
    			carry = tmp1 < tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i];
    		return 0;
    	}

    	for(  ; i<SrcLen1; i++)
    		if( (++L_Dst[i])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_Add(int[] L_Dst, int[] L_Src1, int k, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( (L_Src2[i]==-1) && (carry==1) )
    			L_Dst[i+k] = L_Src1[i+k];
    		else {
    			tmp = L_Src2[i] + carry;
    			L_Dst[i+k] = L_Src1[i+k] + tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i+k]);
        		tmp2 = Unsigned32(tmp);
    			carry = tmp1 < tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i+k] = L_Src1[i+k];
    		return 0;
    	}

    	for(  ; i<SrcLen1; i++)
    		if( (++L_Dst[i+k])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_Add(int[] L_Dst, int[] L_Src1, int SrcLen1, int[] L_Src2, int s, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( (L_Src2[i+s]==-1) && (carry==1) )
    			L_Dst[i] = L_Src1[i];
    		else {
    			tmp = L_Src2[i+s] + carry;
    			L_Dst[i] = L_Src1[i] + tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(tmp);
    			carry = tmp1 < tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i];
    		return 0;
    	}

    	for(  ; i<SrcLen1; i++)
    		if( (++L_Dst[i])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_Add(int[] L_Dst, int n1, int[] L_Src1, int n2, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( (L_Src2[i]==-1) && (carry==1) )
    			L_Dst[i+n1] = L_Src1[i+n2];
    		else {
    			tmp = L_Src2[i] + carry;
    			L_Dst[i+n1] = L_Src1[i+n2] + tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i+n1]);
        		tmp2 = Unsigned32(tmp);
    			carry = tmp1 < tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i+n1] = L_Src1[i+n2];
    		return 0;
    	}

    	for(  ; i<SrcLen1; i++)
    		if( (++L_Dst[i+n1])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_Add(int[] L_Dst, int[] L_Src1, int n1, int SrcLen1, int[] L_Src2, int n2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( (L_Src2[i+n2]==-1) && (carry==1) )
    			L_Dst[i] = L_Src1[i+n1];
    		else {
    			tmp = L_Src2[i+n2] + carry;
    			L_Dst[i] = L_Src1[i+n1] + tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(tmp);
    			carry = tmp1 < tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i+n1];
    		return 0;
    	}

    	for(  ; i<SrcLen1; i++)
    		if( (++L_Dst[i])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int[] L_Src1, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i]+carry==0 )
    			L_Dst[i] = L_Src1[i];
    		else {
    			tmp = L_Src2[i] + carry;
    			L_Dst[i] = L_Src1[i] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i]--)!=0 )	return 0;

    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int[] L_Src1, int n, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i]+carry==0 )
    			L_Dst[i] = L_Src1[i+n];
    		else {
    			tmp = L_Src2[i] + carry;
    			L_Dst[i] = L_Src1[i+n] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i+n];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i]--)!=0 )	return 0;

    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int[] L_Src1, int SrcLen1, int[] L_Src2, int n, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i+n]+carry==0 )
    			L_Dst[i] = L_Src1[i];
    		else {
    			tmp = L_Src2[i+n] + carry;
    			L_Dst[i] = L_Src1[i] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i]--)!=0 )	return 0;

    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int t, int[] L_Src1, int n, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i]+carry==0 )
    			L_Dst[i+t] = L_Src1[i+n];
    		else {
    			tmp = L_Src2[i] + carry;
    			L_Dst[i+t] = L_Src1[i+n] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i+t]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i+t] = L_Src1[i+n];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i+t]--)!=0 )	return 0;

    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int t, int[] L_Src1, int SrcLen1, int[] L_Src2, int n, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i+n]+carry==0 )
    			L_Dst[i+t] = L_Src1[i];
    		else {
    			tmp = L_Src2[i+n] + carry;
    			L_Dst[i+t] = L_Src1[i] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i+t]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i+t] = L_Src1[i];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i+t]--)!=0 )	return 0;

    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int t1, int[] L_Src1, int n, int SrcLen1, int[] L_Src2, int t2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i+t2]+carry==0 )
    			L_Dst[i+t1] = L_Src1[i+n];
    		else {
    			tmp = L_Src2[i+t2] + carry;
    			L_Dst[i+t1] = L_Src1[i+n] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i+t1]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i+t1] = L_Src1[i+n];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i+t1]--)!=0 )	return 0;

    	return 1;
    }
    
    public static int bn_Sub(int[] L_Dst, int[] L_Src1, int t1, int SrcLen1, int[] L_Src2, int t2, int SrcLen2) {
    	int i, carry, tmp;
    	
    	for( carry=i=0; i<SrcLen2; i++) {
    		if( L_Src2[i+t2]+carry==0 )
    			L_Dst[i] = L_Src1[i+t1];
    		else {
    			tmp = L_Src2[i+t2] + carry;
    			L_Dst[i] = L_Src1[i+t1] - tmp;
    			long tmp1, tmp2;
        		tmp1 = Unsigned32(L_Dst[i]);
        		tmp2 = Unsigned32(~tmp);
    			carry = tmp1 > tmp2 ? 1 : 0;
    		}
    	}

    	if( carry==0 ) {
    		if( L_Dst!=L_Src1 )
    			for(  ; i<SrcLen1; i++)
    				L_Dst[i] = L_Src1[i+t1];
    		return 0;
    	}
    	
    	for(  ; i<SrcLen1; i++)
    		if( (L_Dst[i]--)!=0 )	return 0;

    	return 1;
    }
    
    public static void bn_Sqr(int[] L_Dst, int[] L_Src, int SrcLen) {
    	int i, j, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	L_Dst[0] = L_Dst[SrcLen+SrcLen-1] = 0;

    	L_Dst[SrcLen] = bn_MulD( L_Dst, 1, L_Src, 1, SrcLen-1, L_Src[0]);
    	for( i=1; i<=SrcLen-2; i++)
    		L_Dst[SrcLen+i] = bn_MulAdd(L_Dst, 1+i+i, SrcLen-1-i, L_Src, 1+i, SrcLen-1-i, L_Src[i]);

    	bn_SHL(L_Dst, L_Dst, SrcLen+SrcLen, 1);

    	for( tmp=i=j=0; i<SrcLen; i++,j+=2 ) {
    		D_Mul_D(La, L_Src[i], L_Src[i]);
    		tmp1 = Unsigned32(La[0]+=tmp);
    		tmp2 = Unsigned32(tmp); 
    		if( tmp1<tmp2 )			La[1]++;
    		tmp1 = Unsigned32(L_Dst[j]+=La[0]);
    		tmp2 = Unsigned32(La[0]);
    		if( tmp1<tmp2 )	La[1]++;
    		tmp1 = Unsigned32(L_Dst[j+1]+=La[1]);
    		tmp2 = Unsigned32(La[1]);
    		if( tmp1<tmp2 )		tmp = 1;
    		else				tmp = 0;
    	}
    }
    
    public static void bn_Sqr(int[] L_Dst, int s, int[] L_Src, int n, int SrcLen) {
    	int i, j, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	L_Dst[0+s] = L_Dst[SrcLen+SrcLen-1+s] = 0;

    	L_Dst[SrcLen+s] = bn_MulD( L_Dst, 1+s, L_Src, 1+n, SrcLen-1, L_Src[0+n]);
    	for( i=1; i<=SrcLen-2; i++)
    		L_Dst[SrcLen+i+s] = bn_MulAdd(L_Dst, 1+i+i+s, SrcLen-1-i, L_Src, 1+i+n, SrcLen-1-i, L_Src[i+n]);

    	bn_SHL(L_Dst, s, L_Dst, s, SrcLen+SrcLen, 1);

    	for( tmp=i=j=0; i<SrcLen; i++,j+=2 ) {
    		D_Mul_D(La, L_Src[i+n], L_Src[i+n]);
    		tmp1 = Unsigned32(La[0]+=tmp);
    		tmp2 = Unsigned32(tmp); 
    		if( tmp1<tmp2 )			La[1]++;
    		tmp1 = Unsigned32(L_Dst[j+s]+=La[0]);
    		tmp2 = Unsigned32(La[0]);
    		if( tmp1<tmp2 )	La[1]++;
    		tmp1 = Unsigned32(L_Dst[j+1+s]+=La[1]);
    		tmp2 = Unsigned32(La[1]);
    		if( tmp1<tmp2 )		tmp = 1;
    		else				tmp = 0;
    	}
    }
    
    public static void bn_Mul(int[] L_Dst, int[] L_Src1, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int i, j, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	for( i=0; i<SrcLen1+SrcLen2; i++)
    		L_Dst[i] = 0;

    	for( j=0; j<SrcLen2; j++) {
    		for( tmp=0,i=0; i<SrcLen1; i++) {
    			D_Mul_D(La, L_Src1[i], L_Src2[j]);
    			tmp1 = Unsigned32(tmp+=La[0]);
        		tmp2 = Unsigned32(La[0]); 
    			if( tmp1<tmp2 )	La[1]++;
    			tmp1 = Unsigned32(L_Dst[i+j]+=tmp);
        		tmp2 = Unsigned32(tmp);
    			if( tmp1<tmp2 )	La[1]++;
    			tmp = La[1];
    		}
    		L_Dst[i+j] = tmp;
    	}
    }
    
    public static void bn_Mul(int[] L_Dst, int[] L_Src1, int SrcLen1, int[] L_Src2, int t, int SrcLen2) {
    	int i, j, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	for( i=0; i<SrcLen1+SrcLen2; i++)
    		L_Dst[i] = 0;

    	for( j=0; j<SrcLen2; j++) {
    		for( tmp=0,i=0; i<SrcLen1; i++) {
    			D_Mul_D(La, L_Src1[i], L_Src2[j+t]);
    			tmp1 = Unsigned32(tmp+=La[0]);
        		tmp2 = Unsigned32(La[0]); 
    			if( tmp1<tmp2 )	La[1]++;
    			tmp1 = Unsigned32(L_Dst[i+j]+=tmp);
        		tmp2 = Unsigned32(tmp);
    			if( tmp1<tmp2 )	La[1]++;
    			tmp = La[1];
    		}
    		L_Dst[i+j] = tmp;
    	}
    }
    
    public static void bn_Mul(int[] L_Dst, int s, int[] L_Src1, int t1, int SrcLen1, int[] L_Src2, int t2, int SrcLen2) {
    	int i, j, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	for( i=0; i<SrcLen1+SrcLen2; i++)
    		L_Dst[i+s] = 0;

    	for( j=0; j<SrcLen2; j++) {
    		for( tmp=0,i=0; i<SrcLen1; i++) {
    			D_Mul_D(La, L_Src1[i+t1], L_Src2[j+t2]);
    			tmp1 = Unsigned32(tmp+=La[0]);
        		tmp2 = Unsigned32(La[0]); 
    			if( tmp1<tmp2 )	La[1]++;
    			tmp1 = Unsigned32(L_Dst[i+j+s]+=tmp);
        		tmp2 = Unsigned32(tmp);
    			if( tmp1<tmp2 )	La[1]++;
    			tmp = La[1];
    		}
    		L_Dst[i+j+s] = tmp;
    	}
    }
    
    public static int bn_Cmp(int[] L_Src1, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int	i;

    	if( SrcLen1>=SrcLen2 ) {
    		for( i=SrcLen1-1; i!=SrcLen2-1; i--)
    			if( L_Src1[i] != 0 )		return +1;
    	}
    	else {
    		for( i=SrcLen2-1; i!=SrcLen1-1; i--)
    			if( L_Src2[i] != 0 )		return -1;
    	}

    	for(  ; i!=-1; i--) {
    		long tmp1, tmp2;
    		tmp1 = Unsigned32(L_Src1[i]);
    		tmp2 = Unsigned32(L_Src2[i]);
    		if( tmp1==tmp2 )		continue;
    		else if( tmp1 > tmp2 )	return +1;
    		else	return -1;
    	}
    	
    	return 0;
    }
    
    public static int bn_Cmp(int[] L_Src1, int n, int SrcLen1, int[] L_Src2, int SrcLen2) {
    	int	i;

    	if( SrcLen1>=SrcLen2 ) {
    		for( i=SrcLen1-1; i!=SrcLen2-1; i--)
    			if( L_Src1[i+n] != 0 )		return +1;
    	}
    	else {
    		for( i=SrcLen2-1; i!=SrcLen1-1; i--)
    			if( L_Src2[i] != 0 )		return -1;
    	}

    	for(  ; i!=-1; i--) {
    		long tmp1, tmp2;
    		tmp1 = Unsigned32(L_Src1[i+n]);
    		tmp2 = Unsigned32(L_Src2[i]);
    		if( tmp1==tmp2 )		continue;
    		else if( tmp1 > tmp2 )	return +1;
    		else	return -1;
    	}
    	
    	return 0;
    }
    
    public static int bn_Cmp(int[] L_Src1, int n, int SrcLen1, int[] L_Src2, int t, int SrcLen2) {
    	int	i;

    	if( SrcLen1>=SrcLen2 ) {
    		for( i=SrcLen1-1; i!=SrcLen2-1; i--)
    			if( L_Src1[i+n] != 0 )		return +1;
    	}
    	else {
    		for( i=SrcLen2-1; i!=SrcLen1-1; i--)
    			if( L_Src2[i+t] != 0 )		return -1;
    	}

    	for(  ; i!=-1; i--) {
    		long tmp1, tmp2;
    		tmp1 = Unsigned32(L_Src1[i+n]);
    		tmp2 = Unsigned32(L_Src2[i+t]);
    		if( tmp1==tmp2 )		continue;
    		else if( tmp1 > tmp2 )	return +1;
    		else	return -1;
    	}
    	
    	return 0;
    }
    
    public static int bn_Euclid(int[] L_Dst, int[] L_Src, int[] L_Modulus, int ModLen) {
    	int i, ret, make_ODD, Len_1=ModLen+1;
    	int[] Temp, U1, U2, U3, T1, T2, T3;
    	int[] Value1 = new int[MaxDIGIT+2];
    	int[] Value2 = new int[MaxDIGIT+2];
    	int[] Value3 = new int[MaxDIGIT+2];
    	int[] Value4 = new int[MaxDIGIT+2];
    	int[] Value5 = new int[MaxDIGIT+2];
    	int[] Value6 = new int[MaxDIGIT+2];
    	
    	U1 = Value1;
    	U2 = Value2;
    	U3 = Value3;
    	T1 = Value4;
    	T2 = Value5;
    	T3 = Value6;
    	
    	for ( make_ODD=0;  ; make_ODD++)
    		if( (CheckBitDIGIT(L_Src, make_ODD) != 0) || (CheckBitDIGIT(L_Modulus, make_ODD) != 0) )
    			break;
    	if( make_ODD!=0 ) {
    		if( make_ODD>=32 ) {
    			assert( 1==0 );
    		}
    		else {
    			ret = bn_SHR(L_Src, L_Src, ModLen, make_ODD);
    			assert( ret==0 );
    			ret = bn_SHR(L_Modulus, L_Modulus, ModLen, make_ODD);
    			assert( ret==0 );
    		}
    	}
    	
    	for( i=0; i<ModLen; i++) {
    		U1[i] = U2[i] = 0;
    		U3[i] = T2[i] = L_Modulus[i];
    		T1[i] = T3[i] = L_Src[i];
    	}
    	U1[i] = U2[i] = U3[i] = T2[i] = T1[i] = T3[i] = 0;
    	U1[0] = 1;
    	if( T2[0]!=0 )	T2[0] -= 1;
    	else			bn_Sub(T2, T2, ModLen, bn_One, 1);
     	
    	do {
    		do {
    			if( isEven0(U3) ) {
    				if( isOdd0(U1) || isOdd0(U2) ) {
    					bn_Add(U1, U1, Len_1, L_Src, ModLen);
    					bn_Add(U2, U2, Len_1, L_Modulus, ModLen);
    				}
    				bn_SHR(U1, U1, Len_1, 1);
    				bn_SHR(U2, U2, Len_1, 1);
    				bn_SHR(U3, U3, Len_1, 1);
    			}

    			if( isEven0(T3) || bn_Cmp(U3, Len_1, T3, Len_1)<0 ) {
    				Temp = U1;	U1 = T1;	T1 = Temp;
    				Temp = U2;	U2 = T2;	T2 = Temp;
    				Temp = U3;	U3 = T3;	T3 = Temp;
    			}
    		} while( isEven0(U3) );

    		while( (bn_Cmp(U1, Len_1, T1, Len_1)<0) || (bn_Cmp(U2, Len_1, T2, Len_1)<0) ) {
    			bn_Add(U1, U1, Len_1, L_Src, ModLen);
    			bn_Add(U2, U2, Len_1, L_Modulus, ModLen);
    		}
    		
    		bn_Sub(U1, U1, Len_1, T1, Len_1);
    		bn_Sub(U2, U2, Len_1, T2, Len_1);
    		bn_Sub(U3, U3, Len_1, T3, Len_1);
    	} while( bn_Cmp(T3, Len_1, bn_Zero, 1)>0 );
    	
    	while( (bn_Cmp(U1, Len_1, L_Src, ModLen)>=0) && (bn_Cmp(U2, Len_1, L_Modulus, ModLen)>=0) ) {
    		bn_Sub(U1, U1, Len_1, L_Src, ModLen);
    		bn_Sub(U2, U2, Len_1, L_Modulus, ModLen);
    	}
    	
    	if( make_ODD!=0 ) {
    		if( make_ODD>=32 ) {
    			assert( 1==0 );
    		}
    		else {
    			ret = bn_SHL(L_Src, L_Src, ModLen, make_ODD);
    			assert( ret==0 );
    			ret = bn_SHL(L_Modulus, L_Modulus, ModLen, make_ODD);
    			assert( ret==0 );
    			ret = bn_SHL(U3, U3, ModLen, make_ODD);
    			assert( ret==0 );
    		}
    	}
    	
    	if(bn_Cmp(U3, ModLen, bn_One, 1) == 0) {
    		bn_Sub(L_Dst, L_Modulus, ModLen, U2, ModLen);
    		return KCDSA.CTR_SUCCESS;
    	}
    	else {
    		for(i=0;i<ModLen;i++)
    			L_Dst[i] = U3[i];
    		return KCDSA.CTR_VERIFY_FAIL;
    	}
    }
    
    public static int MakeAddChain(int[][] AddChain, int WindowSize, int[] L_Exponent, int msb, int Type) {
    	int i=msb, j, SubExp, idx=0;

    	for( i=msb; i>=0; i--)
    		if( CheckBitDIGIT(L_Exponent, i) != 0 )	break;
    	if( i==-1 ) {
    		AddChain[idx][0] = -1;
    		AddChain[idx][1] = -1;
    		return 0;
    	}
    	
    	if( Type==FirstWindowMayBeEven ) {
    		j = ( i-(int)WindowSize+1>=0 ) ? i-(int)WindowSize+1 : 0;
    		for( SubExp=0; i>=j; i--) {
    			SubExp <<= 1;
    			if( CheckBitDIGIT(L_Exponent, i) != 0 )
    				SubExp ^= 1;
    		}
    		AddChain[idx][0] = i+1;
    		AddChain[idx][1] = SubExp;
    		idx++;
    	}
    	
    	for(  ; i>=0;  ) {
    		if( CheckBitDIGIT(L_Exponent, i)==0 ) {
    			i--;
    			continue;
    		}

    		j = i - (int)WindowSize + 1;
    		if( j<0 )	j = 0;
    		for(  ; j<=i; j++)
    			if( CheckBitDIGIT(L_Exponent, j) != 0 )
    				break;

    		for( SubExp=0; i>=j; i--) {
    			SubExp <<= 1;
    			if( CheckBitDIGIT(L_Exponent, i) != 0 )
    				SubExp ^= 1;
    		}
    		AddChain[idx][0] = i+1;
    		AddChain[idx][1] = SubExp;
    		idx++;
    	}

    	AddChain[idx][0] = -1;
    	AddChain[idx][1] = -1;
    	return idx;
    }
    
    static int bn_ModD(int[] L_Src, int SrcLen, int D_Divisor)
    {
    	int	i, xx=0;
    	long tmp1, tmp2, tmp3;

    	for( i=SrcLen-1; i!=-1; i--) {
    		tmp1 = Unsigned32(xx);
    		tmp2 = Unsigned32(L_Src[i]);
    		tmp3 = Unsigned32(D_Divisor);
    		xx = DD_Mod_D(tmp1, tmp2, tmp3);
    	}

    	return xx;
    }
    
    public static int bn_ModExp(int[] L_Dst, int[] L_Base, int BaseLen, int[] L_Exponent, int ExpLen, 
    		int[] L_Modulus, int ModLen) {
    	int i, j, ret;
    	int WindowSize;
    	int[] P1, P2, P3;
    	int[] L_Temp1 = new int[2*(MaxDIGIT+2)];
    	int[] L_Temp2 = new int[2*(MaxDIGIT+2)];
    	
    	i = ExpLen * 32 - 1;
    	for(  ; i!=-1; i--)
    		if( CheckBitDIGIT(L_Exponent, i) != 0 )
    			break;
    	
    	if( i==-1 ) {
    		L_Dst[0] = 1;
    		for( j=1; j<ModLen; j++)	L_Dst[j] = 0;
    	}
    	if( i==0 ) {
    		for( j=0; j<(int)BaseLen; j++)	L_Dst[j] = L_Base[j];
    		for(    ; j<(int)ModLen; j++)	L_Dst[j] = 0;
    	}
    	
    	if	   ( i<32 )		WindowSize = 1;
    	else if( i<60 )		WindowSize = 3;
    	else if( i<220 )	WindowSize = 4;
    	else if( i<636 )	WindowSize = 5;
    	else if( i<1758 )	WindowSize = 6;
    	else				WindowSize = 7;
    	if( WindowSize>6 )		WindowSize = 6;
    	
    	for( j=0; j<(int)BaseLen; j++)	L_Temp2[j] = L_Base[j];
    	for(    ; j<(int)ModLen; j++)	L_Temp2[j] = 0;
    	
    	ret = Montgomery_Init(L_Modulus, ModLen);
    	
    	ret = Montgomery_Zn2RZn(L_Temp1, L_Temp2, L_Modulus, ModLen);
    	
    	if( WindowSize==1 ) {
    		bn_Copy(L_Dst, L_Temp1, ModLen);
    		P1 = L_Temp1;
    		P2 = L_Temp2;
    		for( i--; i!=-1; i--) {
    			bn_KaraSqr(P2, P1, ModLen);
    			ret = Montgomery_REDC(P2, 2*ModLen, L_Modulus, ModLen);
    			if( CheckBitDIGIT(L_Exponent, i) != 0 ) {
    				bn_KaraMul(P1, P2, L_Dst, ModLen);
    				ret = Montgomery_REDC(P1, 2*ModLen, L_Modulus, ModLen);
    			}
    			else {
    				P3 = P1;	P1 = P2;	P2 = P3;
    			}
    		}
    	}
    	else 
    	{
    		bn_KaraSqr(L_Temp2, L_Temp1, ModLen);
    		ret = Montgomery_REDC(L_Temp2, 2*ModLen, L_Modulus, ModLen);
    		
    		bn_Copy(Window_PreData[0], L_Temp1, ModLen);
    		for( j=1; j<1<<(WindowSize-1); j++) {
    			bn_KaraMul(L_Temp1, Window_PreData[j-1], L_Temp2, ModLen);
    			ret = Montgomery_REDC(L_Temp1, 2*ModLen, L_Modulus, ModLen);
    			bn_Copy(Window_PreData[j], L_Temp1, ModLen);
    		}
    		 
    		i = MakeAddChain(Add_Chain, WindowSize, L_Exponent, i, FirstWindowMayBeEven);
    		if( i>=BN_MAX_BITS/Max_W_size ) {
    			ret = KCDSA.CTR_FATAL_ERROR;
    			return ret;
    		}

    		if( (Add_Chain[0][1]&1) != 0 )
    			bn_Copy(L_Temp2, Window_PreData[Add_Chain[0][1]/2], ModLen);
    		else {
    			bn_KaraMul(L_Temp2, Window_PreData[0], Window_PreData[Add_Chain[0][1]/2-1], ModLen);
    			ret = Montgomery_REDC(L_Temp2, 2*ModLen, L_Modulus, ModLen);
    			if(ret != KCDSA.CTR_SUCCESS) return ret;
    		}
    		i = Add_Chain[0][0] - 1;
    		j = 1;
    		
    		P1 = L_Temp2;
    		P2 = L_Temp1;
    		for(  ; i!=-1; i--) {
    			bn_KaraSqr(P2, P1, ModLen);
    			ret = Montgomery_REDC(P2, 2*ModLen, L_Modulus, ModLen);
    			if(ret != KCDSA.CTR_SUCCESS) return ret;
    			P3 = P1;	P1 = P2;	P2 = P3;

    			if( i==Add_Chain[j][0] ) {
    				bn_KaraMul(P2, P1, Window_PreData[Add_Chain[j][1]>>1], ModLen);
    				ret = Montgomery_REDC(P2, 2*ModLen, L_Modulus, ModLen);
    				if(ret != KCDSA.CTR_SUCCESS) return ret;
    				P3 = P1;	P1 = P2;	P2 = P3;
    				j++;
    			}
    		}
    	}
    	
    	ret = Montgomery_REDC(P1, ModLen, L_Modulus, ModLen);
    	if(ret != KCDSA.CTR_SUCCESS) return ret;
    	
    	bn_Copy(L_Dst, P1, ModLen);
    	
    	ret = KCDSA.CTR_SUCCESS;
    	
    	return ret;
    }
    
    public static int bn_MulD(int[] L_Dst, int s, int[] L_Src, int n, int SrcLen, int D_Multiplier) {
    	int i, tmp = 0;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	for( i=0; i<SrcLen; i++) {
    		D_Mul_D(La, D_Multiplier, L_Src[i+n]);
    		La[0] += tmp;
    		tmp1 = Unsigned32(La[0]);
    		tmp2 = Unsigned32(tmp);
    		if( tmp1<tmp2 )	La[1]++;
    		L_Dst[i+s] = La[0];
    		tmp = La[1];
    	}

    	return tmp;
    }
    
    public static int bn_MulAdd(int[] L_Dst, int k, int DstLen, int[] L_Src, int SrcLen, int D_Multiplier) {
    	int i, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	for( tmp=0, i=0; i<SrcLen; i++) {
    		D_Mul_D(La, D_Multiplier, L_Src[i]);
    		tmp1 = Unsigned32(tmp += La[0]);
    		tmp2 = Unsigned32(La[0]);
    		if( tmp1<tmp2 )	La[1]++;
    		tmp1 = Unsigned32(L_Dst[i+k]+=tmp);
    		tmp2 = Unsigned32(tmp);
    		if( tmp1<tmp2 )	La[1]++;
    		tmp = La[1];
    	}
    	
    	if( i==DstLen )				return tmp;
    	tmp1 = Unsigned32(L_Dst[i+k]+=tmp);
		tmp2 = Unsigned32(tmp);
    	if( tmp1 >= tmp2 )	return 0;
    	
    	for( i++; i<DstLen; i++)
    		if( (++L_Dst[i+k])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_MulAdd(int[] L_Dst, int k1, int DstLen, int[] L_Src, int k2, int SrcLen, int D_Multiplier) {
    	int i, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;
    	
    	for( tmp=0, i=0; i<SrcLen; i++) {
    		D_Mul_D(La, D_Multiplier, L_Src[i+k2]);
    		tmp1 = Unsigned32(tmp += La[0]);
    		tmp2 = Unsigned32(La[0]);
    		if( tmp1<tmp2 )	La[1]++;
    		tmp1 = Unsigned32(L_Dst[i+k1]+=tmp);
    		tmp2 = Unsigned32(tmp);
    		if( tmp1<tmp2 )	La[1]++;
    		tmp = La[1];
    	}
    	
    	if( i==DstLen )				return tmp;
    	tmp1 = Unsigned32(L_Dst[i+k1]+=tmp);
		tmp2 = Unsigned32(tmp);    	
    	if( tmp1>=tmp2 )	return 0;
    	
    	for( i++; i<DstLen; i++)
    		if( (++L_Dst[i+k1])!=0 )	return 0;
    	
    	return 1;
    }
    
    public static int bn_MulSub(int[] L_Dst, int k, int DstLen, int[] L_Src, int SrcLen, int D_Multiplier) {
    	int i, tmp;
    	int[] La = new int[2];
    	long tmp1, tmp2;

    	for( tmp=0, i=0; i<SrcLen; i++) {
    		D_Mul_D(La, D_Multiplier, L_Src[i]);
    		tmp1 = Unsigned32(tmp += La[0]);
    		tmp2 = Unsigned32(La[0]);    		
    		if( tmp1<tmp2 ) La[1]++;
    		tmp1 = Unsigned32(L_Dst[i+k]);
    		tmp2 = Unsigned32(tmp);
    		if( tmp1<tmp2 )  La[1]++;
    		L_Dst[i+k] -= tmp;
    		tmp = La[1];
    	}

    	if( i==DstLen )				return tmp;
    	tmp1 = Unsigned32(L_Dst[i+k]);
		tmp2 = Unsigned32(tmp);
    	if( tmp1>=tmp2 ) {
    		L_Dst[i+k] -= tmp;
    		return 0;
    	}
    	else
    		L_Dst[i+k] -= tmp;

    	for( i++; i<DstLen; i++)
    		if( (L_Dst[i+k]--)!=0 )	return 0;
    	
    	return 1;
    }
    
    public static void bn_KaraSqr(int[] L_Dst, int[] L_Src, int SrcLen) {
    	int	FLAG=0;
    	int n2 = (SrcLen+1)/2, tmp=0;
    	int[] S = new int[MaxDIGIT+2];
    	int[] T = new int[MaxDIGIT+2];
    	
    	if(SrcLen == 1) {
    		D_Mul_D(L_Dst, L_Src[0], L_Src[0]);
    		return;
    	}
    	
    	if(SrcLen < Kara_Sqr_Length) {
    		bn_Sqr(L_Dst, L_Src, SrcLen);
    		return;
    	}
    	
    	if( (SrcLen&1) != 0 ) {
    		tmp = L_Src[SrcLen];
    		L_Src[SrcLen] = 0;
    		FLAG = 1;
    		SrcLen++;
    	}
    	
    	if( bn_Cmp(L_Src, n2, n2, L_Src, n2)==1 )
    		bn_Sub(S, L_Src, n2, n2, L_Src, n2);
    	else
    		bn_Sub(S, L_Src, n2, L_Src, n2, n2);
    	
    	bn_KaraSqr(T, S, n2);
    	bn_KaraSqr(L_Dst, L_Src, n2);
    	bn_KaraSqr(L_Dst, SrcLen, L_Src, n2, n2);
    	
    	S[SrcLen] = bn_Add(S, L_Dst, SrcLen, L_Dst, SrcLen, SrcLen);
    	bn_Sub(S, S, SrcLen+1, T, SrcLen);
    	bn_Add(L_Dst, n2, L_Dst, n2, SrcLen+n2, S, SrcLen+1);
    	
    	if( FLAG != 0 ) {
    		SrcLen --;
    		L_Src[SrcLen] = tmp;
    	}
    }
    
    public static void bn_KaraSqr(int[] L_Dst, int s, int[] L_Src, int n, int SrcLen) {
    	int	FLAG=0;
    	int n2 = (SrcLen+1)/2, tmp=0;
    	int[] S = new int[MaxDIGIT+2];
    	int[] T = new int[MaxDIGIT+2];
    	
    	if(SrcLen == 1) {
    		D_Mul_D(L_Dst, s, L_Src[0+n], L_Src[0+n]);
    		return;
    	}
    	
    	if(SrcLen < Kara_Sqr_Length) {
    		bn_Sqr(L_Dst, s, L_Src, n, SrcLen);
    		return;
    	}
    	
    	if( (SrcLen&1) != 0 ) {
    		tmp = L_Src[SrcLen+n];
    		L_Src[SrcLen+n] = 0;
    		FLAG = 1;
    		SrcLen++;
    	}
    	
    	if( bn_Cmp(L_Src, n2+n, n2, L_Src, n, n2)==1 )
    		bn_Sub(S, L_Src, n2+n, n2, L_Src, n, n2);
    	else
    		bn_Sub(S, L_Src, n2, L_Src, n2+n, n2);
    	
    	bn_KaraSqr(T, S, n2);
    	bn_KaraSqr(L_Dst, s, L_Src, n, n2);
    	bn_KaraSqr(L_Dst, SrcLen+s, L_Src, n2+n, n2);
    	
    	S[SrcLen] = bn_Add(S, L_Dst, s, SrcLen, L_Dst, SrcLen+n, SrcLen);
    	bn_Sub(S, S, SrcLen+1, T, SrcLen);
    	bn_Add(L_Dst, n2+s, L_Dst, n2+s, SrcLen+n2, S, SrcLen+1);
    	
    	if( FLAG != 0 ) {
    		SrcLen --;
    		L_Src[SrcLen+n] = tmp;
    	}
    }
    
    public static void bn_KaraMul(int[] L_Dst, int[] L_Src1, int[] L_Src2, int SrcLen) {
    	int	FLAG=0, SIGN=0;
    	int tmp1=0, tmp2=0;
    	int n2 = (SrcLen + 1) / 2;
    	int[] S = new int[MaxDIGIT+2];
    	int[] T = new int[MaxDIGIT+2];
    	final int TempHalf = (MaxDIGIT + 2) / 2;
    	
    	if(SrcLen == 1) {
    		D_Mul_D(L_Dst, L_Src1[0], L_Src2[0]);
    		return;
    	}
    	
    	if(SrcLen < Kara_Mul_Length) {
    		bn_Mul( L_Dst, L_Src1, SrcLen, L_Src2, SrcLen);
    		return;
    	}
    	
    	if( (SrcLen&1) != 0 ) {
    		tmp1 = L_Src1[SrcLen];
    		L_Src1[SrcLen] = 0;
    		tmp2 = L_Src2[SrcLen];
    		L_Src2[SrcLen] = 0;
    		FLAG = 1;
    		SrcLen++;
    	}
    	
    	if( bn_Cmp(L_Src1, n2, n2, L_Src1, n2)==1 )
    		bn_Sub(S, L_Src1, n2, n2, L_Src1, n2);
    	else {
    		bn_Sub(S, L_Src1, n2, L_Src1, n2, n2);
    		SIGN++;
    	}
    	if( bn_Cmp(L_Src2, n2, n2, L_Src2, n2)==1 )
    		bn_Sub(S, TempHalf, L_Src2, n2, n2, L_Src2, n2);
    	else {
    		bn_Sub(S, TempHalf, L_Src2, n2, L_Src2, n2, n2);
    		SIGN++;
    	}
    	
    	bn_KaraMul(T, S, S, TempHalf, n2);
    	bn_KaraMul(L_Dst, L_Src1, L_Src2, n2);
    	bn_KaraMul(L_Dst, SrcLen, L_Src1, n2, L_Src2, n2, n2);
    	
    	S[SrcLen] = bn_Add(S, L_Dst, SrcLen, L_Dst, SrcLen, SrcLen);
    	if( SIGN==1 )
    		bn_Add(S, S, SrcLen+1, T, SrcLen);
    	else
    		bn_Sub(S, S, SrcLen+1, T, SrcLen);
    	bn_Add(L_Dst, n2, L_Dst, n2, SrcLen+n2, S, SrcLen+1);
    	
    	if( FLAG != 0 ) {
    		SrcLen --;
    		L_Src1[SrcLen] = tmp1;
    		L_Src2[SrcLen] = tmp2;
    	}
    }
    
    public static void bn_KaraMul(int[] L_Dst, int[] L_Src1, int[] L_Src2, int t, int SrcLen) {
    	int	FLAG=0, SIGN=0;
    	int tmp1=0, tmp2=0;
    	int n2 = (SrcLen + 1) / 2;
    	int[] S = new int[MaxDIGIT+2];
    	int[] T = new int[MaxDIGIT+2];
    	final int TempHalf = (MaxDIGIT + 2) / 2;
    	
    	if(SrcLen == 1) {
    		D_Mul_D(L_Dst, L_Src1[0], L_Src2[0 + t]);
    		return;
    	}
    	
    	if(SrcLen < Kara_Mul_Length) {
    		bn_Mul( L_Dst, L_Src1, SrcLen, L_Src2, t, SrcLen);
    		return;
    	}
    	
    	if( (SrcLen&1) != 0 ) {
    		tmp1 = L_Src1[SrcLen];
    		L_Src1[SrcLen] = 0;
    		tmp2 = L_Src2[SrcLen + t];
    		L_Src2[SrcLen + t] = 0;
    		FLAG = 1;
    		SrcLen++;
    	}
    	
    	if( bn_Cmp(L_Src1, n2, n2, L_Src1, n2)==1 )
    		bn_Sub(S, L_Src1, n2, n2, L_Src1, n2);
    	else {
    		bn_Sub(S, L_Src1, n2, L_Src1, n2, n2);
    		SIGN++;
    	}
    	if( bn_Cmp(L_Src2, t+n2, n2, L_Src2, t, n2)==1 )
    		bn_Sub(S, TempHalf, L_Src2, t+n2, n2, L_Src2, t, n2);
    	else {
    		bn_Sub(S, TempHalf, L_Src2, t, n2, L_Src2, t+n2, n2);
    		SIGN++;
    	}
    	
    	bn_KaraMul(T, S, S, TempHalf, n2);
    	bn_KaraMul(L_Dst, L_Src1, L_Src2, t, n2);
    	bn_KaraMul(L_Dst, SrcLen, L_Src1, n2, L_Src2, t+n2, n2);
    	
    	S[SrcLen] = bn_Add(S, L_Dst, SrcLen, L_Dst, SrcLen, SrcLen);
    	if( SIGN==1 )
    		bn_Add(S, S, SrcLen+1, T, SrcLen);
    	else
    		bn_Sub(S, S, SrcLen+1, T, SrcLen);
    	bn_Add(L_Dst, n2, L_Dst, n2, SrcLen+n2, S, SrcLen+1);
    	
    	if( FLAG != 0 ) {
    		SrcLen --;
    		L_Src1[SrcLen] = tmp1;
    		L_Src2[SrcLen+t] = tmp2;
    	}
    }
    
    public static void bn_KaraMul(int[] L_Dst, int s, int[] L_Src1, int t1, int[] L_Src2, int t2, int SrcLen) {
    	int	FLAG=0, SIGN=0;
    	int tmp1=0, tmp2=0;
    	int n2 = (SrcLen + 1) / 2;
    	int[] S = new int[MaxDIGIT+2];
    	int[] T = new int[MaxDIGIT+2];
    	final int TempHalf = (MaxDIGIT + 2) / 2;
    	
    	if(SrcLen == 1) {
    		D_Mul_D(L_Dst, s, L_Src1[0+t1], L_Src2[0+t2]);
    		return;
    	}
    	
    	if(SrcLen < Kara_Mul_Length) {
    		bn_Mul( L_Dst, s, L_Src1, t1, SrcLen, L_Src2, t2, SrcLen);
    		return;
    	}
    	
    	if( (SrcLen&1) != 0 ) {
    		tmp1 = L_Src1[SrcLen+t1];
    		L_Src1[SrcLen+t1] = 0;
    		tmp2 = L_Src2[SrcLen+t2];
    		L_Src2[SrcLen+t2] = 0;
    		FLAG = 1;
    		SrcLen++;
    	}
    	
    	if( bn_Cmp(L_Src1, t1+n2, n2, L_Src1, t1, n2)==1 )
    		bn_Sub(S, L_Src1, t1+n2, n2, L_Src1, t1, n2);
    	else {
    		bn_Sub(S, L_Src1, t1, n2, L_Src1, t1+n2, n2);
    		SIGN++;
    	}
    	if( bn_Cmp(L_Src2, t2+n2, n2, L_Src2, t2, n2)==1 )
    		bn_Sub(S, TempHalf, L_Src2, t2+n2, n2, L_Src2, t2, n2);
    	else {
    		bn_Sub(S, TempHalf, L_Src2, t2, n2, L_Src2, t2+n2, n2);
    		SIGN++;
    	}
    	
    	bn_KaraMul(T, S, S, TempHalf, n2);
    	bn_KaraMul(L_Dst, s, L_Src1, t1, L_Src2, t2, n2);
    	bn_KaraMul(L_Dst, s+SrcLen, L_Src1, t1+n2, L_Src2, t2+n2, n2);
    	
    	S[SrcLen] = bn_Add(S, L_Dst, s, SrcLen, L_Dst, s+SrcLen, SrcLen);
    	if( SIGN==1 )
    		bn_Add(S, S, SrcLen+1, T, SrcLen);
    	else
    		bn_Sub(S, S, SrcLen+1, T, SrcLen);
    	bn_Add(L_Dst, s+n2, L_Dst, s+n2, SrcLen+n2, S, SrcLen+1);
    	
    	if( FLAG != 0 ) {
    		SrcLen --;
    		L_Src1[SrcLen+t1] = tmp1;
    		L_Src2[SrcLen+t2] = tmp2;
    	}
    }
    
    public static int Montgomery_Init(int[] L_Modulus, int ModLen) {
    	int i;
    	int[] T = new int[2*(MaxDIGIT+2)];
    	
    	Montgo_Inv = D_Inv(0-L_Modulus[0]);
    	
    	for( i=0; i<2*ModLen; i++) T[i] = 0;
    	T[i] = 1;
    	Classical_REDC(T, 2*ModLen+1, L_Modulus, ModLen);
    	bn_Copy(Montgo_Rto2modN, T, ModLen);
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int Montgomery_REDC(int[] L_Dst, int DstLen, int[] L_Modulus, int ModLen) {
    	int i;
    	
    	if( DstLen!=ModLen+ModLen ) {
    		for( i=DstLen; i<ModLen+ModLen+1; i++)
    			L_Dst[i] = 0;
    		DstLen = ModLen + ModLen;
    	}
    	
    	L_Dst[DstLen] = 0;

    	if( Montgo_Inv==1 ) {
    		int j;

    		for( j=0;  ; j++)
    			if( (++L_Modulus[j])!=0 )	break;
    		for( i=0; i<ModLen; i++)
    			bn_MulAdd(L_Dst, i+j, ModLen+ModLen+2-i-j, L_Modulus, j, ModLen-j, L_Dst[i]);
    		for(  ; j!=-1; j--)
    			L_Modulus[j]--;
    	}
    	else
    		for( i=0; i<ModLen; i++) {
    			bn_MulAdd(L_Dst, i, ModLen+ModLen+2-i, L_Modulus, ModLen, L_Dst[i]*Montgo_Inv);
    		}
    	
    	if( bn_Cmp(L_Dst, ModLen, ModLen+1, L_Modulus, ModLen)>=0 )
    		bn_Sub(L_Dst, L_Dst, ModLen, ModLen+1, L_Modulus, ModLen);
    	else
    		bn_Copy(L_Dst, L_Dst, ModLen, ModLen);
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    public static int Montgomery_Zn2RZn(int[] L_Dst, int[] L_Src, int[] L_Modulus, int ModLen) {
    	int ret = 0;
    	int[] T = new int[2*(MaxDIGIT+2)];
    	
    	bn_KaraMul(T, L_Src, Montgo_Rto2modN, ModLen);
    	
    	ret = Montgomery_REDC(T, 2*ModLen, L_Modulus, ModLen);
    	
    	bn_Copy(L_Dst, T, ModLen);
    	
    	return ret;
    }
    
    public static int D_Inv(int D_Src) {
    	int F, G, d, B, C;
    	long tmp1, tmp2;
    	
    	C = 1;
    	B = 0 - C;
    	G = D_Src;
    	F = 0 - G;
    	
    	for(  ;  ;  ) {
    		if( G==1 )
    			break;
    		
    		tmp1 = Unsigned32(F>>>3);
    		tmp2 = Unsigned32(G);

    		if( tmp1>tmp2 ) {
    			tmp1 = Unsigned32(F);
        		tmp2 = Unsigned32(G);
    			d = (int)(tmp1 / tmp2);
    			F -= d * G;
    			B -= d * C;
    		}
    		else {
    			do {
    				F -= G;
    				B -= C;
    				tmp1 = Unsigned32(F);
    	    		tmp2 = Unsigned32(G);
    			} while( tmp1>tmp2 );
    		}

    		if( F==1 ) {
    			C = B;
    			break;
    		}
    		
    		tmp1 = Unsigned32(G>>>3);
    		tmp2 = Unsigned32(F);

    		if( tmp1>tmp2 ) {
    			tmp1 = Unsigned32(G);
        		tmp2 = Unsigned32(F);
    			d = (int)(tmp1 / tmp2);
    			G -= d * F;
    			C -= d * B;
    		}
    		else {
    			do {
    				G -= F;
    				C -= B;
    				tmp1 = Unsigned32(G);
    	    		tmp2 = Unsigned32(F);
    			} while( tmp1>tmp2 );
    		}
    	}
    	
    	return C;
    }
    
    public static int D_Gcd(int D_Src1, int D_Src2) {
    	int	tmp;
    	long tmp1, tmp2;
    	tmp1 = Unsigned32(D_Src1);
    	tmp2 = Unsigned32(D_Src2);

    	if( tmp1<tmp2 ) {
    		tmp=D_Src1;
    		D_Src1=D_Src2;
    		D_Src2=tmp;
    	}

    	while( D_Src2!=0 ) {
    		tmp = (int) (tmp1 % tmp2);
    		D_Src1 = D_Src2;
    		D_Src2 = tmp;
    		tmp1 = Unsigned32(D_Src1);
        	tmp2 = Unsigned32(D_Src2);
    	}
    	
    	return D_Src1;
    }
    
    public static void D_Mul_D(int[] D_Res, int D_Multiplicand, int D_Multiplier) {
    	long tmp;
    	
    	tmp = (((long)D_Multiplicand & 0x00000000ffffffffL) * (D_Multiplier & 0x00000000ffffffffL));
    	D_Res[0] = (int) tmp;
    	D_Res[1] = (int) (tmp >>> 32);
    }
    
    public static void D_Mul_D(int[] D_Res, int s, int D_Multiplicand, int D_Multiplier) {
    	long tmp;
    	
    	tmp = (((long)D_Multiplicand & 0x00000000ffffffffL) * (D_Multiplier & 0x00000000ffffffffL));
    	D_Res[0+s] = (int) tmp;
    	D_Res[1+s] = (int) (tmp >>> 32);
    }
    
    public static int DD_Div_D(long D_Dividend1, long D_Dividend2, long D_Divisor) {
    	long tmp = ((D_Dividend1)<<32) + D_Dividend2;
    	if((tmp >>> 63) == 1) {
    		long tmp1, tmp2;
    		int tmp_1;
    		
    		tmp1 = tmp + 0x7538dcfb76180000L;
    		tmp_1 = (int) (tmp1 % 10);
    		tmp2 = (tmp1 / 10) + 0xde0b6b3a7640000L;
    		    		
    		return (int) (((tmp2 / D_Divisor) * 10) + ((((tmp2 % D_Divisor) * 10) + tmp_1) / D_Divisor));
    	}
    	else {
        	return (int)(( ((D_Dividend1)<<32) + D_Dividend2 ) / D_Divisor);	
    	}
    }
    
    static int DD_Mod_D(long D_Dividend1, long D_Dividend2, long D_Divisor)
    {
    	long tmp = ((D_Dividend1)<<32) + D_Dividend2;
    	if((tmp >>> 63) == 1) {
    		long tmp1, tmp2;
    		int tmp_1;
    		tmp1 = tmp + 0x7538dcfb76180000L;
    		tmp_1 = (int) (tmp1 % 10);
    		tmp2 = (tmp1 / 10) + 0xde0b6b3a7640000L;
    		
     		return (int) ((((tmp2 % D_Divisor) * 10) + tmp_1) % D_Divisor);
    	}
    	else
    		return (int)(( ((D_Dividend1)<<32) + D_Dividend2 ) % D_Divisor);
    }
    
    public static int Classical_REDC(int[] L_Dst, int DstLen, int[] L_Modulus, int ModLen) {
    	int i;
    	int MSB = 0, TTTT = 0, FLAG = 0, D_Quotient, MSD_Modulus;
    	long tmp1, tmp2, tmp3;
    	
    	if( DstLen<ModLen )
    		return KCDSA.CTR_SUCCESS;
    	
		tmp1 = Unsigned32(L_Dst[DstLen-1]);
		tmp2 = Unsigned32(L_Modulus[ModLen-1]);

    	if( tmp1>=tmp2 ) {
    		FLAG++;
    		TTTT = L_Dst[DstLen];
    		L_Dst[DstLen++] = 0;
    	}

    	for( i=32-1; i!=-1; i--) {
    		if( (L_Modulus[ModLen-1]&(1<<i)) != 0 )
    			break;
    		MSB++;
    	}
    	if( MSB != 0 ) {
    		bn_SHL(L_Modulus, L_Modulus, ModLen, MSB);
    		bn_SHL(L_Dst, L_Dst, DstLen, MSB);
    	}
    	
    	MSD_Modulus = L_Modulus[ModLen-1];	
    	for( i=DstLen-ModLen-1; i!=-1; i--) {
    		tmp1 = Unsigned32(L_Dst[ModLen+i]);
    		tmp2 = Unsigned32(L_Dst[ModLen+i-1]);
    		tmp3 = Unsigned32(MSD_Modulus);
     		if( L_Dst[ModLen+i]==MSD_Modulus )
    			D_Quotient = -1;
    		else
    			D_Quotient = DD_Div_D(tmp1, tmp2, tmp3);

    		if( bn_MulSub(L_Dst, i, ModLen+1, L_Modulus, ModLen, D_Quotient) != 0 )
    			if(bn_Add(L_Dst, L_Dst, i, ModLen+1, L_Modulus, ModLen)==0)
    				bn_Add(L_Dst, L_Dst, i, ModLen+1, L_Modulus, ModLen);
    	}

    	if( MSB != 0 ) {
    		bn_SHR(L_Modulus, L_Modulus, ModLen, MSB);
    		bn_SHR(L_Dst, L_Dst, ModLen, MSB);
    	}

    	if( FLAG != 0 ) {
    		DstLen--;
    		L_Dst[DstLen] = TTTT;
    	}
    	
    	return KCDSA.CTR_SUCCESS;
    }
    
    static int SmallPrimes[ ]={
    	0xC8E15F2A, 0x16FA4227, 0x87B81DA9, 0xDA38C071, 0xFDB17C23, 0xFE5E796B,
    	0xC7E4CBF5, 0x7EB0F0B1, 0xB72EFC93, 0xF46CEE57, 0x80B2C2BB, 0x34A77199,
    	0x447D1BD5, 0xEA4C7C31, 0xF046D45B, 0xFF55A7BF, 0x9B287041, 0x85663BEF,
    	0x7856625B, 0,
    	0xF53CB8EF, 0x0BF8B47B, 0x302F3B45, 0xF7889105, 0xAEB9C343, 0xE4703BE3,
    	0x7E15A86D, 0x8DFBFF6D, 0xE3FF5767, 0xF4DC76E3, 0xFFDEB1BB, 0xF1CCD229,
    	0xAD97C169, 0x44655D23, 0xD39EFD0F, 0x39E3CD4D, 0xE049D915, 0xF9CD1761,
    	0xF7B3D683, 0x5170C36F, 0xC22F6765, 0x81779DA7, 0x76EC6BF5, 0
    };
    
    static int	IterNo[][]={
    	{ 100, 27},
    	{ 150, 18},
    	{ 200, 15},
    	{ 250, 12},
    	{ 500,  9},
    	{ 500,  6},
    	{ 600,  5},
    	{ 800,  4},
    	{1250,  40},
    	{2048,  56},
    	{3072,	 64},
    	{9999,  1},
    };
    
    public static int MillerRabin(BIGNUM BN_Num) {
    	int i, j, s, NoTest, ret, tmp, DigitLen=BN_Num.Length;
    	
    	BIGNUM BN_Num_1 = null, BN_Tmp = null, T = null, M = null;
    	
    	ret = KCDSA.CTR_VERIFY_FAIL;
    	if( BN_Num.Length==0 ) return ret;
    	if( isEven0(BN_Num.pData) ) return ret;

    	for( i=0; SmallPrimes[i]!=0; i++) {
    		tmp = bn_ModD(BN_Num.pData, DigitLen, SmallPrimes[i]);
    		tmp = D_Gcd(SmallPrimes[i], tmp);
    		if( tmp!=1 ) return ret;
    	}
    	
    	j = 32 * DigitLen;
    	for( i=0;  ; i++) {
    		NoTest = IterNo[i][1];
    		if( j<=IterNo[i][0] )	break;
    	}

    	ret = KCDSA.CTR_MEMORY_ALLOC_ERROR;
    	
    	BN_Num_1 = new BIGNUM(DigitLen+1);
    	BN_Tmp = new BIGNUM(DigitLen+1);
    	T = new BIGNUM(DigitLen+1);
    	M = new BIGNUM(DigitLen+1);
    	
    	BN_One.Length = 1;
    	BN_One.pData[0] = 1;
    	
    	BN_Two.Length = 1;
    	BN_Two.pData[0] = 2;

    	ret = BN_Sub(BN_Num_1, BN_Num, BN_One);
    	if(ret != KCDSA.CTR_SUCCESS ) return ret;
    	
    	ret = BN_Copy(T, BN_Num_1);
    	if(ret != KCDSA.CTR_SUCCESS ) return ret;
    	
    	for( s=0; isEven0(T.pData); s++) {
    		ret = BN_SHR(T, T, 1);
    		if(ret != KCDSA.CTR_SUCCESS ) return ret;
    	}

    	for( i=0; i<=NoTest; i++) {
    		if( i==0 ) {
    			ret = BN_Copy(BN_Tmp, BN_Two);
    			if(ret != KCDSA.CTR_SUCCESS ) return ret;
    		}
    		else {
    			ret = BN_Rand(BN_Tmp, 32*DigitLen-1);
    			if(ret != KCDSA.CTR_SUCCESS ) return ret;
    		}
    		
    		ret = BN_ModExp(M, BN_Tmp, T, BN_Num);
    		if(ret != KCDSA.CTR_SUCCESS ) return ret;
    		
    		if( (BN_Cmp(M, BN_One)==0) || (BN_Cmp(M, BN_Num_1)==0) )	continue;

    		for( j=0; j<s; j++) {
    			ret = BN_ModMul(M, M, M, BN_Num);
    			if(ret != KCDSA.CTR_SUCCESS ) return ret;

    			ret = KCDSA.CTR_VERIFY_FAIL;
    			if( BN_Cmp(M, BN_One)==0 )
    				return ret;

    			if( BN_Cmp(M, BN_Num_1)==0 )	break;
    		}

    		ret = KCDSA.CTR_VERIFY_FAIL;
    		if( s==j )	return ret;
    	}
    	
    	ret = KCDSA.CTR_SUCCESS;
    	if( BN_Num_1!=null )	DestroyBigNum(BN_Num_1);
    	if( BN_Tmp!=null )		DestroyBigNum(BN_Tmp);
    	if( T!=null )			DestroyBigNum(T);
    	if( M!=null )			DestroyBigNum(M);
    	
    	return ret;
    }
    
    public static int CheckBitDIGIT(int[] A, int k) {
    	return (1 & ( (A)[(k)>>5] >> ((k) & (32-1)) ));
    }
    
    public static void SetBitDIGIT(int[] A, int k) {
    	(A)[(k)>>5] |= (1 << ((k) & (32-1)) );
    }
    
    public static boolean isEven0(int[] A) {
    	return ( ( (A)[0]&1 )==0 );
    }
    
    public static boolean isOdd0(int[] A) {
    	return ( ( (A)[0]&1 )==1 );
    }
    
    public static long Unsigned32(int A) {
    	return (A & 0xffffffffL);
    }
    
    public static int BIG_W2B(int W) {
    	return ((W << 8 & 0x00ff00ff) | ((W >> 24 & 0xff) | (W >> 8 & 0xff00) | (W << 8 & 0xff0000) | (W << 24 & 0xff000000))); 
    }
}