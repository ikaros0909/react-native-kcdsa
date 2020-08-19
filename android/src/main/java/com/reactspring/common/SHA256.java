package com.reactspring.common;

public class SHA256 {
	public final static int SHA256_K[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
			0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
			0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
			0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	
	public static void SHA256_Init(SHA_ALG_INFO AlgInfo) {
		AlgInfo.ChainVar[0] = 0x6a09e667;
		AlgInfo.ChainVar[1] = 0xbb67ae85;
		AlgInfo.ChainVar[2] = 0x3c6ef372;
		AlgInfo.ChainVar[3] = 0xa54ff53a;
		AlgInfo.ChainVar[4] = 0x510e527f;
		AlgInfo.ChainVar[5] = 0x9b05688c;
		AlgInfo.ChainVar[6] = 0x1f83d9ab;
		AlgInfo.ChainVar[7] = 0x5be0cd19;

		AlgInfo.Count[0] = AlgInfo.Count[1] = 0;
	}
	
	public static void SHA256_Update(SHA_ALG_INFO AlgInfo, byte[] Message, int MessageLen) {
		int Message_offset = 0;
		
		if ((AlgInfo.Count[0] += (MessageLen << 3)) < 0)
			AlgInfo.Count[1]++;
		
		AlgInfo.Count[1] += (MessageLen >> 29);
		
		while( MessageLen>=64 ) {
			for(int i=0;i<64;i++)
				AlgInfo.Buffer[i] = Message[i + Message_offset];
			SHA256_Transform(AlgInfo.Buffer, AlgInfo.ChainVar);
			Message_offset += 64;
			MessageLen -= 64;
		}
		
		for(int i=0;i<MessageLen;i++)
			AlgInfo.Buffer[i] = Message[i + Message_offset];
	}
	
	public static void SHA256_Update(SHA_ALG_INFO AlgInfo, int Message, int MessageLen) {
		int RemainedLen;
		
		RemainedLen = (AlgInfo.Count[0] >> 3) % 64;
		
		if ((AlgInfo.Count[0] += (MessageLen << 3)) < 0)
			AlgInfo.Count[1]++;
		
		AlgInfo.Count[1] += (MessageLen >> 29);
		
		for(int i=0;i<MessageLen;i++)
			AlgInfo.Buffer[i + RemainedLen] = (byte)Message;
	}
	
	public static void SHA256_Final(SHA_ALG_INFO AlgInfo, byte[] Digest) {
		int CountL, CountH, Index;
		CountL = AlgInfo.Count[0];
		CountH = AlgInfo.Count[1];
		
		Index = (CountL >> 3) % 64;
		AlgInfo.Buffer[Index++] = (byte) 0x80;

		if(Index > 64 - 8) {
			for(int i = 0; i < 64 - Index; i++)
				AlgInfo.Buffer[i + Index] = 0;
			SHA256_Transform(AlgInfo.Buffer, AlgInfo.ChainVar);
			for(int i = 0; i < 64 - 8; i++)
				AlgInfo.Buffer[i] = 0;
		}
		else {
			for(int i = 0; i < 64 - Index - 8; i++)
				AlgInfo.Buffer[i + Index] = 0;
		}
		
		int_to_byte(AlgInfo.Buffer, (64 / 4 - 2)*4, CountH);
		int_to_byte(AlgInfo.Buffer, (64 / 4 - 1)*4, CountL);
		
		SHA256_Transform(AlgInfo.Buffer, AlgInfo.ChainVar);
		
		for(int i = 0; i < 32; i += 4)
			BIG_D2B(AlgInfo.ChainVar[i / 4], Digest, i);
	}
	
	public static void SHA256_Transform(byte[] Message, int[] ChainVar) {
		int j;
		int[] X = new int[64];
		int[] abcdefgh = new int[8];
		
		for(j = 0; j < 16; j++)
			X[j] = byte_to_int(Message, j*4);
		for(j = 16; j < 64; j++)
			X[j] = RHO1(X[j - 2]) + X [j - 7] + RHO0(X[j - 15]) + X[j - 16];
		
		abcdefgh[0] = ChainVar[0];
		abcdefgh[1] = ChainVar[1];
		abcdefgh[2] = ChainVar[2];
		abcdefgh[3] = ChainVar[3];
		abcdefgh[4] = ChainVar[4];
		abcdefgh[5] = ChainVar[5];
		abcdefgh[6] = ChainVar[6];
		abcdefgh[7] = ChainVar[7];
		
		for(j = 0; j < 64; j+=8) {
			FF(abcdefgh, 0, 1, 2, 3, 4, 5, 6, 7, X, j + 0);
			FF(abcdefgh, 7, 0, 1, 2, 3, 4, 5, 6, X, j + 1);
			FF(abcdefgh, 6, 7, 0, 1, 2, 3, 4, 5, X, j + 2);
			FF(abcdefgh, 5, 6, 7, 0, 1, 2, 3, 4, X, j + 3);
			FF(abcdefgh, 4, 5, 6, 7, 0, 1, 2, 3, X, j + 4);
			FF(abcdefgh, 3, 4, 5, 6, 7, 0, 1, 2, X, j + 5);
			FF(abcdefgh, 2, 3, 4, 5, 6, 7, 0, 1, X, j + 6);
			FF(abcdefgh, 1, 2, 3, 4, 5, 6, 7, 0, X, j + 7);
		}
		
		ChainVar[0] += abcdefgh[0];
		ChainVar[1] += abcdefgh[1];
		ChainVar[2] += abcdefgh[2];
		ChainVar[3] += abcdefgh[3];
		ChainVar[4] += abcdefgh[4];
		ChainVar[5] += abcdefgh[5];
		ChainVar[6] += abcdefgh[6];
		ChainVar[7] += abcdefgh[7];
	}
	
	public static void BIG_D2B(int D, byte[] B, int B_offset) {
		int_to_byte(B, B_offset, D);
	}
	
	public static int byte_to_int(byte[] src, int src_offset) {
		return ((0x0ff&src[src_offset]) << 24) | ((0x0ff&src[src_offset+1]) << 16) | ((0x0ff&src[src_offset+2]) << 8) | ((0x0ff&src[src_offset+3]));
	}
	
	public static void int_to_byte(byte[] dst, int dst_offset, int src) {
		dst[dst_offset] = (byte) ((src >> 24) & 0xff);
		dst[dst_offset+1] = (byte) ((src >> 16) & 0xff);
		dst[dst_offset+2] = (byte) ((src >> 8) & 0xff);
		dst[dst_offset+3] = (byte) (src & 0xff);
	}
	
	public static int Ch(int x, int y, int z) {
		return ((x & y) ^ ((~x) & z));
	}
	
	public static int Maj(int x, int y, int z) {
		return ((x & y) ^ (x & z) ^ (y & z));
	}
	
	public static int Sigma0(int x) {
		return (RR(x,  2) ^ RR(x, 13) ^ RR(x, 22));
	}
	
	public static int Sigma1(int x) {
		return (RR(x,  6) ^ RR(x, 11) ^ RR(x, 25));
	}
	
	public static int RHO0(int x) {
		return (RR(x, 7) ^ RR(x, 18) ^ SS(x, 3));
	}
	
	public static int RHO1(int x) {
		return (RR(x, 17) ^ RR(x, 19) ^ SS(x, 10));
	}
	
	public static int RR(int x, int n) {
		return (((x) >>> (n)) | ((x) << (32-(n))));
	}
	
	public static int SS(int x, int n) {
		return (x >>> n);
	}
	
	public static void FF(int[] abcdefgh, int a, int b, int c, int d, int e, int f, int g, int h, int[] X, int j) {
		int T1;
		T1 = abcdefgh[h] + Sigma1(abcdefgh[e]) + Ch(abcdefgh[e], abcdefgh[f], abcdefgh[g]) + SHA256_K[j] + X[j];
		
		abcdefgh[d] += T1;
		abcdefgh[h] = T1 + Sigma0(abcdefgh[a]) + Maj(abcdefgh[a], abcdefgh[b], abcdefgh[c]);
	}
}
