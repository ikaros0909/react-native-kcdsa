declare module '@reactspring/react-native-kcdsa' {
    function KISA_KCDSA_GenerateKeyPair(hash:number): Promise<number>;
    function KISA_KCDSA_sign(msg:string, hash:number): Promise<string>;
    function KISA_KCDSA_verify(msg:string, sign:string, hash:number): Promise<number>;    
}
