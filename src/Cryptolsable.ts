export interface Cryptolsable {
    init(storageTerminatedCallBack: Function):Promise<void>
    newSalt():Uint8Array
    generateKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey>
    generateAndSaveKeyFromPassword(password: string, salt: Uint8Array, userIdentifier: string): Promise<CryptoKey>
    getSavedPasswordKey(userIdentifier: string): Promise<CryptoKey>
    generateECDHKeyPair(): Promise<CryptoKeyPair>
    generateAndSaveECDHKeyPair(userIdentifier: string, key:CryptoKey): Promise<CryptoKeyPair>
    getSavedECDHPrivateKey(userIdentifier: string, key:CryptoKey): Promise<CryptoKey>
    getSavedECDHPublicKey(userIdentifier: string): Promise<CryptoKey>
}