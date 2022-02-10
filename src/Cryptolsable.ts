import {KeyTypes} from 'js-crypto-local-storer/src/enums/KeyTypes'
import {AesEncryption} from "./AesEncryption";

export interface Cryptolsable {
    // init and general functions
    init(storageTerminatedCallBack: Function, storageName:string):Promise<void>
    newSalt():Uint8Array
    exportKeyToJWKString(key:CryptoKey): Promise<string>
    importKeyFromJWKString(key:string, keyType: KeyTypes.PBKDF2_KEY | KeyTypes.ECDH_PRIVATE_KEY | KeyTypes.ECDH_PUBLIC_KEY | KeyTypes.RSA_PRIVATE_KEY | KeyTypes.RSA_PUBLIC_KEY | KeyTypes.AES_KEY): Promise<CryptoKey>
    // PBKDF2
    generateKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey>
    generateAndSaveKeyFromPassword(password: string, salt: Uint8Array, userIdentifier: string): Promise<CryptoKey>
    isPasswordKeySaved(aliceIdentifier: string):Promise<boolean>
    getSavedPasswordKey(userIdentifier: string): Promise<CryptoKey>
    // ECDH
    generateECDHKeyPair(): Promise<CryptoKeyPair>
    generateAndSaveECDHKeyPair(userIdentifier: string, key:CryptoKey): Promise<CryptoKeyPair>
    getSavedECDHPrivateKey(userIdentifier: string, key:CryptoKey): Promise<CryptoKey>
    getSavedECDHPublicKey(userIdentifier: string): Promise<CryptoKey>
    generateSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey>
    generateSharedSecretFromSavedKey(identifierAlice: string, identifierBob:string): Promise<CryptoKey>
    saveSharedSecret(key: CryptoKey, aliceIdentifier: string, bobIdentifier: string): Promise<void>
    getSavedShareSecret(aliceIdentifier: string, bobIdentifier: string): Promise<CryptoKey>
    saveECDHPublicKey(identifier: string, key:CryptoKey): Promise<boolean>
    saveECDHPrivateKey(identifier: string, key: CryptoKey, encryptionKey: CryptoKey): Promise<boolean>
    saveECDHKeyPair(identifier: string, publicKey: CryptoKey, privateKey: CryptoKey, encryptionKey: CryptoKey): Promise<boolean>
    // RSA
    generateNewRsaKeyPair(): Promise<CryptoKeyPair>
    generateAndSaveNewRsaKeyPair(identifier: string, key: CryptoKey): Promise<CryptoKeyPair>
    getSavedRsaPublicKey(identifier: string): Promise<CryptoKey>
    getSavedRsaPrivateKey(identifier: string, key: CryptoKey): Promise<CryptoKey>
    getSavedRsaKeyPair(identifier: string, key: CryptoKey): Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>
    saveRsaPublicKey(identifier: string, publicKey: CryptoKey): Promise<boolean>
    saveRsaPrivateKey(identifier: string, privateKey: CryptoKey, encryptionKey: CryptoKey): Promise<boolean>
    saveRsaKeyPair(identifier: string, publicKey: CryptoKey, privateKey: CryptoKey, encryptionKey: CryptoKey): Promise<boolean>
    encryptDataWithRsa(publicKey: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>
    encryptStringWithRsa(publicKey: CryptoKey, data: string, convertToBase64String: boolean): Promise<ArrayBuffer | string>
    encryptKeyWithRsa(publicKey: CryptoKey, keyToEncrypt: CryptoKey, convertToBase64String: boolean): Promise<ArrayBuffer | string>
    decryptDataWithRsa(privateKey: CryptoKey, data: Uint8Array|ArrayBuffer): Promise<ArrayBuffer>
    decryptStringWithRsa(privateKey: CryptoKey, data: Uint8Array|ArrayBuffer|string, isBase64Encoded: boolean): Promise<string>
    decryptKeyWithRsa(privateKey: CryptoKey, data: Uint8Array|ArrayBuffer|string, keyType: KeyTypes.AES_KEY|KeyTypes.RSA_PRIVATE_KEY|KeyTypes.RSA_PUBLIC_KEY|KeyTypes.ECDH_PRIVATE_KEY|KeyTypes.ECDH_PUBLIC_KEY, isBase64Encoded: boolean): Promise<CryptoKey>
    // AES
    generateNewAesKey(): Promise<CryptoKey>
    generateAndSaveNewAesKey(identifier: string, key: CryptoKey): Promise<CryptoKey>
    getSavedAesKey(identifier: string, key: CryptoKey): Promise<CryptoKey>
    saveAesKey(identifier: string, key: CryptoKey, encryptionKey: CryptoKey): Promise<boolean>
    encryptDataWithAes(key: CryptoKey, data: Uint8Array, base64Encoded: boolean, iv?:Uint8Array): Promise<AesEncryption>
    encryptStringWithAes(key: CryptoKey, data: string, base64Encoded: boolean, iv?:Uint8Array): Promise<AesEncryption>
    encryptKeyWithAes(key: CryptoKey, keyToEncrypt: CryptoKey, base64Encoded: boolean, iv?:Uint8Array): Promise<AesEncryption>
    encryptObjectWithAes<T>(key:CryptoKey, data:T, base64Encoded: boolean, iv?:Uint8Array): Promise<AesEncryption>
    decryptDataWithAes(key: CryptoKey, data: Uint8Array|ArrayBuffer|string, iv:Uint8Array, base64Encoded: boolean): Promise<ArrayBuffer>
    decryptStringWithAes(key: CryptoKey, data:string|ArrayBuffer|Uint8Array, iv:Uint8Array, base64Encoded: boolean): Promise<string>
    decryptKeyWithAes(key: CryptoKey, data: string|ArrayBuffer|Uint8Array, keyType: KeyTypes.AES_KEY|KeyTypes.RSA_PRIVATE_KEY|KeyTypes.RSA_PUBLIC_KEY|KeyTypes.ECDH_PRIVATE_KEY|KeyTypes.ECDH_PUBLIC_KEY, iv:Uint8Array, base64Encoded:boolean): Promise<CryptoKey>
    decryptObjectWithAes<T>(key:CryptoKey, data:string|ArrayBuffer|Uint8Array, iv:Uint8Array, base64Encoded: boolean): Promise<T>
}