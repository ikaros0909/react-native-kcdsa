package com.reactspring.common;

public class SHA_ALG_INFO {
	int[] ChainVar = null;
    int[] Count = null;
    byte[] Buffer = null;
    
    SHA_ALG_INFO(){
        ChainVar = new int[32 / 4];
        Count = new int[4];
        Buffer = new byte[64];
    }
}
