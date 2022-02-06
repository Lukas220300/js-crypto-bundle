export interface Cryptolsable {
    init(storageTerminatedCallBack: Function):Promise<void>
    newSalt():Uint8Array
    generateKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey>
    generateAndSaveKeyFromPassword(password: string, salt: Uint8Array, userIdentifier: string): Promise<CryptoKey>
    isPasswordKeySaved(aliceIdentifier: string):Promise<boolean>
    getSavedPasswordKey(userIdentifier: string): Promise<CryptoKey>
    generateECDHKeyPair(): Promise<CryptoKeyPair>
    generateAndSaveECDHKeyPair(userIdentifier: string, key:CryptoKey): Promise<CryptoKeyPair>
    getSavedECDHPrivateKey(userIdentifier: string, key:CryptoKey): Promise<CryptoKey>
    getSavedECDHPublicKey(userIdentifier: string): Promise<CryptoKey>
    generateSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey>
    generateSharedSecretFromSavedKey(identifierAlice: string, identifierBob:string): Promise<CryptoKey>
    saveSharedSecret(key: CryptoKey, aliceIdentifier: string, bobIdentifier: string): Promise<void>
    getSavedShareSecret(aliceIdentifier: string, bobIdentifier: string): Promise<CryptoKey>
}