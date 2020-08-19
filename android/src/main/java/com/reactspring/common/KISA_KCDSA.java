package com.reactspring.common;

public class KISA_KCDSA {
    BIGNUM KCDSA_P;		//	prime(1024 + 128i bits i=0..8)
    BIGNUM KCDSA_Q;		//	subprime(128 + 32j bits j=0..4)
    BIGNUM KCDSA_G;		//	Base
    BIGNUM KCDSA_x;		//
    BIGNUM KCDSA_y;		//
    int	Count;			//	Prime Type ID
    int	SeedLen;		//	in BYTEs
}
