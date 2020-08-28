package com.reactspring.common;

public class BIGNUM {
    int Length;
    int Space;
    int[] pData;

    BIGNUM(int tt){
        Length = 0;
        Space = tt + 1;
        pData = new int[tt + 1];
    }
}
