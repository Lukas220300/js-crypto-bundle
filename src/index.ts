import {AES} from 'js-crypto-core/src/AES'
import {ECDH} from 'js-crypto-core/src/ECDH'
import {PBKDF2} from 'js-crypto-core/src/PBKDF2'
import {RSA} from 'js-crypto-core/src/RSA'
import {KeyStorage} from 'js-crypto-local-storer/src/interfaces/KeyStorage'
import {KeyTypes} from 'js-crypto-local-storer/src/enums/KeyTypes'
import IndexedDBBuilder from 'js-crypto-local-storer/src/builder/IndexedDBBuilder'
import {KeyWithMaterial} from 'js-crypto-local-storer/src/interfaces/KeyWithMaterial'
import {Cryptolsable} from "./Cryptolsable";
import {ByteConverter} from 'js-crypto-converter/src/ByteConverter'
import {KeyConverter} from 'js-crypto-converter/src/KeyConverter'
import {AesEncryption} from "./AesEncryption";

export default class Cryptols implements Cryptolsable {

    protected aes: AES
    protected ecdh: ECDH
    protected pbkdf2: PBKDF2
    protected rsa: RSA
    protected storage: KeyStorage | undefined

    static IDENTIFIER_SPLITTER = '{(##)}'
    static SHARED_SECRET_IDENTIFIER_PREFIX = '8c13c5a9-1b80-4449-9383-22fddce8b7c3'

    constructor(storageTerminatedCallBack: Function) {
        this.aes = new AES()
        this.ecdh = new ECDH()
        this.pbkdf2 = new PBKDF2()
        this.rsa = new RSA()
        this.storage = undefined

        /*
        todo: talk about init function
        todo: change name to cryptols
         */

        /*
        new IndexedDBBuilder().buildStorage('js-crypto-key-storage', 1, storageTerminatedCallBack).then((keyStorage: KeyStorage) => {
            this.storage = keyStorage
        })
         */
    }

    // @ts-ignore
    async init(storageTerminatedCallBack: Function): Promise<void> {
        this.storage = await new IndexedDBBuilder().buildStorage('js-crypto-key-storage', 1, storageTerminatedCallBack)
    }

    newSalt(): Uint8Array {
        return this.pbkdf2.getNewSalt()
    }

    /*
        PBKDF2
     */

    generateKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const encodedPassword = ByteConverter.encodeString(password)
        return this.pbkdf2.getKeyFromPassword(encodedPassword, salt)
    }

    // @ts-ignore
    async generateAndSaveKeyFromPassword(password: string, salt: Uint8Array, userIdentifier: string): Promise<CryptoKey> {
        const pbkdfKey = await this.generateKeyFromPassword(password, salt)
        const exportedKey = await this.pbkdf2.exportKey('jwk', pbkdfKey)
        await this.storage.savePBKDFKey(KeyTypes.PBKDF2_KEY, userIdentifier, exportedKey as JsonWebKey, salt)
        return pbkdfKey
    }

    // @ts-ignore
    async isPasswordKeySaved(aliceIdentifier: string): Promise<boolean> {
        const dbEntry = await this.storage.getKey(KeyTypes.PBKDF2_KEY, aliceIdentifier)
        if (dbEntry === undefined) {
            return false
        } else {
            return true
        }
    }

    // @ts-ignore
    async getSavedPasswordKey(userIdentifier: string): Promise<CryptoKey> {
        const dbEntry = await this.storage.getKey(KeyTypes.PBKDF2_KEY, userIdentifier)
        if (dbEntry === undefined) {
            // @ts-ignore
            return new Promise(((resolve, reject) => {
                reject('Key Not available')
            }))
        }
        return this.pbkdf2.importKey((dbEntry as KeyWithMaterial).key as JsonWebKey)
    }

    /*
        ECDH
     */

    generateECDHKeyPair(): Promise<CryptoKeyPair> {
        return this.ecdh.generateNewKePair()
    }

    // @ts-ignore
    async generateAndSaveECDHKeyPair(userIdentifier: string, key: CryptoKey): Promise<CryptoKeyPair> {
        const keyPair = await this.generateECDHKeyPair()
        const exportedPrivateKey = await this.ecdh.exportKey('jwk', keyPair.privateKey)
        const encodedPrivateKey = KeyConverter.JWKToByte(exportedPrivateKey as JsonWebKey)
        const exportedPublicKey = await this.ecdh.exportKey('jwk', keyPair.publicKey)
        const iv = this.aes.generateNewInitializeVector()
        const encryptedPrivateKey = await this.aes.encrypt(iv, key, encodedPrivateKey)
        await this.storage.saveAsymmetricKey(KeyTypes.ECDH_PRIVATE_KEY, userIdentifier, {
            material: iv,
            key: ByteConverter.ArrayBufferToBase64String(encryptedPrivateKey)
        })
        await this.storage.saveAsymmetricKey(KeyTypes.ECDH_PUBLIC_KEY, userIdentifier, exportedPublicKey as JsonWebKey)
        return keyPair
    }

    // @ts-ignore
    async getSavedECDHPrivateKey(userIdentifier: string, key: CryptoKey): Promise<CryptoKey> {
        const dbEntry = await this.storage.getKey(KeyTypes.ECDH_PRIVATE_KEY, userIdentifier)
        const iv = (dbEntry as KeyWithMaterial).material
        const encodedKey = ByteConverter.base64StringToUint8Array((dbEntry as KeyWithMaterial).key as string)
        const decodedKey = await this.aes.decrypt(iv, key, encodedKey)
        const deserializedKey = KeyConverter.ByteToJWK(new Uint8Array(decodedKey))
        return this.ecdh.importKeyFordDrive(deserializedKey, true)
    }

    // @ts-ignore
    async getSavedECDHPublicKey(userIdentifier: string): Promise<CryptoKey> {
        const dbEntry = await this.storage.getKey(KeyTypes.ECDH_PUBLIC_KEY, userIdentifier)
        return this.ecdh.importKeyFordDrive(dbEntry as JsonWebKey, false)
    }

    generateSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
        return this.ecdh.generateSharedSecret(privateKey, publicKey)
    }

    // @ts-ignore
    async generateSharedSecretFromSavedKey(identifierAlice: string, identifierBob: string): Promise<CryptoKey> {
        const passwordKey = await this.getSavedPasswordKey(identifierAlice)
        const alicePrivateKey = await this.getSavedECDHPrivateKey(identifierAlice, passwordKey)
        const bobPublicKey = await this.getSavedECDHPublicKey(identifierBob)
        return this.generateSharedSecret(
            alicePrivateKey,
            bobPublicKey
        )
    }

    private static getECDHSharedSecretIdentifier(identifierAlice: string, identifierBob: string): string {
        return Cryptols.SHARED_SECRET_IDENTIFIER_PREFIX
            + Cryptols.IDENTIFIER_SPLITTER
            + identifierAlice
            + Cryptols.IDENTIFIER_SPLITTER
            + identifierBob;
    }

    // @ts-ignore
    async saveSharedSecret(key: CryptoKey, aliceIdentifier: string, bobIdentifier: string): Promise<void> {
        const passwordKey = await this.getSavedPasswordKey(aliceIdentifier)
        const exportedKey = await this.ecdh.exportKey('jwk', key)
        const serializedKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
        const iv = this.aes.generateNewInitializeVector()
        const encryptedKey = await this.aes.encrypt(iv, passwordKey, serializedKey)
        const base64Key = ByteConverter.ArrayBufferToBase64String(encryptedKey)
        await this.storage.saveAESKey(KeyTypes.AES_KEY, Cryptols.getECDHSharedSecretIdentifier(aliceIdentifier, bobIdentifier), base64Key, iv)
        return;
    }

    // @ts-ignore
    async getSavedShareSecret(aliceIdentifier: string, bobIdentifier: string): Promise<CryptoKey> {
        const passwordKey = await this.getSavedPasswordKey(aliceIdentifier)
        const dbEntry = await this.storage.getKey(KeyTypes.AES_KEY, Cryptols.getECDHSharedSecretIdentifier(aliceIdentifier, bobIdentifier))
        const iv = (dbEntry as KeyWithMaterial).material
        const base64Key = (dbEntry as KeyWithMaterial).key
        const encryptedKey = ByteConverter.base64StringToUint8Array(base64Key as string)
        const decryptedKey = await this.aes.decrypt(iv, passwordKey, encryptedKey)
        const formattedKey = KeyConverter.ByteToJWK(new Uint8Array(decryptedKey))
        return await this.ecdh.importSharedSecret(formattedKey)
    }

    // @ts-ignore
    async saveECDHPublicKey(identifier: string, key: CryptoKey): Promise<boolean> {
        try {
            const exportedKey = await this.ecdh.exportKey('jwk', key)
            await this.storage.saveAsymmetricKey(KeyTypes.ECDH_PUBLIC_KEY, identifier, exportedKey as JsonWebKey)
            return true
        } catch (error) {
            console.error(error)
            return false
        }
    }

    // @ts-ignore
    async saveECDHPrivateKey(identifier: string, key: CryptoKey, encryptionKey: CryptoKey): Promise<boolean> {
        try {
            const exportedKey = await this.ecdh.exportKey('jwk', key)
            const iv = this.aes.generateNewInitializeVector()
            const byteKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
            const encryptedKey = await this.aes.encrypt(iv, encryptionKey, byteKey)
            const base64Key = ByteConverter.ArrayBufferToBase64String(encryptedKey)
            await this.storage.saveAsymmetricKey(KeyTypes.ECDH_PRIVATE_KEY, identifier, {material: iv, key: base64Key})
            return true
        } catch (e) {
            console.error(e)
            return false
        }
    }

    // @ts-ignore
    async saveECDHKeyPair(identifier: string, publicKey: CryptoKey, privateKey: CryptoKey, encryptionKey: CryptoKey): Promise<boolean> {
        try {
            if (!await this.saveECDHPublicKey(identifier, publicKey)) {
                return false
            }
            if (!await this.saveECDHPrivateKey(identifier, privateKey, encryptionKey)) {
                return false
            }
            return true
        } catch (e) {
            console.error(e)
            return false
        }
    }

    /*
        RSA
     */

    generateNewRsaKeyPair(): Promise<CryptoKeyPair> {
        return this.rsa.generateNewKePair()
    }

    // @ts-ignore
    async generateAndSaveNewRsaKeyPair(identifier: string, key: CryptoKey): Promise<CryptoKeyPair> {
        const keyPair = await this.generateNewRsaKeyPair()
        const exportedPrivateKey = await this.rsa.exportKey('jwk', keyPair.privateKey) // 1. export key
        const exportedPublicKey = await this.rsa.exportKey('jwk', keyPair.publicKey)
        // public Key
        await this.storage.saveAsymmetricKey(KeyTypes.RSA_PUBLIC_KEY, identifier, exportedPublicKey as JsonWebKey)
        // private Key
        const formattedKey = KeyConverter.JWKToByte(exportedPrivateKey as JsonWebKey) // 2. JsonWebKey to String and then to byte
        const ivMaterial = this.aes.generateNewInitializeVector() // 3. build new iv
        const encryptedKey = await this.aes.encrypt(ivMaterial, key, formattedKey) // 4. encrypt key with aes and key
        const encryptedKeyAsBase64 = ByteConverter.ArrayBufferToBase64String(encryptedKey) // 5. convert ArrayBuffer to base 64 string
        await this.storage.saveAsymmetricKey(KeyTypes.RSA_PRIVATE_KEY, identifier, {
            material: ivMaterial,
            key: encryptedKeyAsBase64
        }) // 6. save key in indexedDB
        return keyPair
    }

    // @ts-ignore
    async getSavedRsaPublicKey(identifier: string): Promise<CryptoKey> {
        const dbEntry = await this.storage.getKey(KeyTypes.RSA_PUBLIC_KEY, identifier)
        return this.rsa.importKey(dbEntry as JsonWebKey, false)
    }

    // @ts-ignore
    async getSavedRsaPrivateKey(identifier: string, key: CryptoKey): Promise<CryptoKey> {
        const dbEntry = await this.storage.getKey(KeyTypes.RSA_PRIVATE_KEY, identifier)
        const iv = (dbEntry as KeyWithMaterial).material
        const encryptedBase64Key = (dbEntry as KeyWithMaterial).key
        const encryptedKey = ByteConverter.base64StringToUint8Array(encryptedBase64Key as string)
        const decryptedKey = await this.aes.decrypt(iv, key, encryptedKey)
        return this.rsa.importKey(KeyConverter.ByteToJWK(new Uint8Array(decryptedKey)), true)
    }

    // @ts-ignore
    async getSavedRsaKeyPair(identifier: string, key: CryptoKey): Promise<{ privateKey: CryptoKey, publicKey: CryptoKey }> {
        const publicKey = await this.getSavedRsaPublicKey(identifier)
        const privateKey = await this.getSavedRsaPrivateKey(identifier, key)
        return {privateKey, publicKey}
    }

    // @ts-ignore
    async saveRsaPublicKey(identifier: string, publicKey: CryptoKey): Promise<boolean> {
        try {
            const exportedKey = await this.rsa.exportKey('jwk', publicKey)
            await this.storage.saveAsymmetricKey(KeyTypes.RSA_PUBLIC_KEY, identifier, exportedKey as JsonWebKey)
            return true
        } catch (e) {
            console.error(e)
            return false
        }
    }

    // @ts-ignore
    async saveRsaPrivateKey(identifier: string, privateKey: CryptoKey, encryptionKey: CryptoKey): Promise<boolean> {
        try {
            const exportedKey = await this.rsa.exportKey('jwk', privateKey)
            const byteKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
            const iv = this.aes.generateNewInitializeVector()
            const encryptedKey = await this.aes.encrypt(iv, encryptionKey, byteKey)
            const base64Key = ByteConverter.ArrayBufferToBase64String(encryptedKey)
            await this.storage.saveAsymmetricKey(KeyTypes.RSA_PRIVATE_KEY, identifier, {material: iv, key: base64Key})
            return true
        } catch (e) {
            console.error(e)
            return false
        }
    }

    // @ts-ignore
    async saveRsaKeyPair(identifier: string, publicKey: CryptoKey, privateKey: CryptoKey, encryptionKey: CryptoKey): Promise<boolean> {
        try {
            if (!await this.saveRsaPublicKey(identifier, publicKey) || !await this.saveRsaPrivateKey(identifier, privateKey, encryptionKey)) {
                return false
            }
            return true
        } catch (e) {
            console.error(e)
            return false
        }
    }

    encryptDataWithRsa(publicKey: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
        return this.rsa.encrypt(publicKey, data);
    }

    // @ts-ignore
    async encryptStringWithRsa(publicKey: CryptoKey, data: string, convertToBase64String: boolean = true): Promise<ArrayBuffer | string> {
        const encodedData = ByteConverter.encodeString(data)
        let encryptedData:ArrayBuffer|string = await this.encryptDataWithRsa(publicKey, encodedData)
        if (convertToBase64String) {
            encryptedData = ByteConverter.ArrayBufferToBase64String(encryptedData)
        }
        return encryptedData
    }

    // @ts-ignore
    async encryptKeyWithRsa(publicKey: CryptoKey, keyToEncrypt: CryptoKey, convertToBase64String: boolean = true): Promise<ArrayBuffer | string> {
        const exportedKey = await this.rsa.exportKey('jwk', keyToEncrypt)
        const encodedKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
        let encryptedKey:ArrayBuffer|string = await this.encryptDataWithRsa(publicKey, encodedKey)
        if (convertToBase64String) {
            encryptedKey = ByteConverter.ArrayBufferToBase64String(encryptedKey)
        }
        return encryptedKey
    }

    decryptDataWithRsa(privateKey: CryptoKey, data: Uint8Array | ArrayBuffer): Promise<ArrayBuffer> {
        return this.rsa.decrypt(privateKey, data)
    }

    // @ts-ignore
    async decryptStringWithRsa(privateKey: CryptoKey, data: Uint8Array | ArrayBuffer | string, isBase64Encoded: boolean = true): Promise<string> {
        let decodedData = data // extract to function
        if(isBase64Encoded) {
            decodedData = ByteConverter.base64StringToUint8Array(decodedData as string)
        }
        const decryptedData = await this.decryptDataWithRsa(privateKey, decodedData as Uint8Array|ArrayBuffer)
        return ByteConverter.byteArrayToString(decryptedData)
    }

    // @ts-ignore
    async decryptKeyWithRsa(privateKey: CryptoKey, data: Uint8Array | ArrayBuffer | string, keyType: KeyTypes.AES_KEY|KeyTypes.RSA_PRIVATE_KEY|KeyTypes.RSA_PUBLIC_KEY|KeyTypes.ECDH_PRIVATE_KEY|KeyTypes.ECDH_PUBLIC_KEY, isBase64Encoded: boolean = true): Promise<CryptoKey> {
        let decodedData = data
        if(isBase64Encoded) {
            decodedData = ByteConverter.base64StringToUint8Array(decodedData as string)
        }
        const decryptedKey = await this.decryptDataWithRsa(privateKey, decodedData as Uint8Array | ArrayBuffer)
        const parsedKey = KeyConverter.ByteToJWK(new Uint8Array(decryptedKey))
        switch (keyType) {
            case KeyTypes.AES_KEY:
                return this.aes.importKey(parsedKey, 'jwk')
            case KeyTypes.ECDH_PRIVATE_KEY:
                return this.ecdh.importKeyFordDrive(parsedKey, true)
            case KeyTypes.ECDH_PUBLIC_KEY:
                return this.ecdh.importKeyFordDrive(parsedKey, false)
            case KeyTypes.RSA_PRIVATE_KEY:
                return this.rsa.importKey(parsedKey, true)
            case KeyTypes.RSA_PUBLIC_KEY:
                return this.rsa.importKey(parsedKey, false)
            default:
                throw new Error('KeyType not supported')
        }
    }

    /*
        AES
     */

    generateNewAesKey(): Promise<CryptoKey> {
        return this.aes.generateNewKey()
    }

    // @ts-ignore
    async generateAndSaveNewAesKey(identifier: string, key: CryptoKey): Promise<CryptoKey> {
        const aesKey = await this.generateNewAesKey()
        const exportedKey = await this.aes.exportKey('jwk', aesKey)
        const encodedKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
        const ivMaterial = this.aes.generateNewInitializeVector()
        const encryptedKey = await this.aes.encrypt(ivMaterial, key, encodedKey)
        const base64Key = ByteConverter.ArrayBufferToBase64String(encryptedKey)
        await this.storage.saveAESKey(KeyTypes.AES_KEY, identifier, base64Key, ivMaterial)
        return aesKey
    }

    // @ts-ignore
    async getSavedAesKey(identifier: string, key: CryptoKey): Promise<CryptoKey> {
        const dbEntry = await this.storage.getKey(KeyTypes.AES_KEY, identifier)
        const base64Key = (dbEntry as KeyWithMaterial).key
        const iv = (dbEntry as KeyWithMaterial).material
        const encryptedKey = ByteConverter.base64StringToUint8Array(base64Key as string)
        const decryptedKey = await this.aes.decrypt(iv, key, encryptedKey)
        const jwk = KeyConverter.ByteToJWK(new Uint8Array(decryptedKey))
        return this.aes.importKey(jwk)
    }

    // @ts-ignore
    async saveAesKey(identifier: string, key: CryptoKey, encryptionKey: CryptoKey): Promise<boolean> {
        try {
            const exportedKey = await this.aes.exportKey('jwk', key)
            const byteKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
            const iv = this.aes.generateNewInitializeVector()
            const encryptedKey = await this.aes.encrypt(iv, encryptionKey, byteKey)
            const base64Key = ByteConverter.ArrayBufferToBase64String(encryptedKey)
            await this.storage.saveAESKey(KeyTypes.AES_KEY, identifier, base64Key, iv)
            return true
        } catch (e) {
            console.error(e)
            return false
        }
    }

    // @ts-ignore
    async encryptDataWithAes(key: CryptoKey, data: Uint8Array,base64Encoded: boolean = false, iv?:Uint8Array): Promise<AesEncryption> {
        if(iv === undefined) {
            iv = this.aes.generateNewInitializeVector()
        }
        let encryption:ArrayBuffer|string = await this.aes.encrypt(iv, key, data)
        if(base64Encoded) {
            encryption = ByteConverter.ArrayBufferToBase64String(encryption)
        }
        return {
            iv,
            data: encryption
        } as AesEncryption
    }

    // @ts-ignore
    async encryptStringWithAes(key: CryptoKey, data: string, base64Encoded: boolean = true, iv?:Uint8Array): Promise<AesEncryption> {
        const encodedString = ByteConverter.encodeString(data)
        return await this.encryptDataWithAes(key, encodedString, base64Encoded, iv)
    }

    // @ts-ignore
    async encryptKeyWithAes(key: CryptoKey, keyToEncrypt: CryptoKey, base64Encoded: boolean = true, iv?:Uint8Array): Promise<AesEncryption> {
        const exportedKey = await this.aes.exportKey('jwk', keyToEncrypt)
        const encodedKey = KeyConverter.JWKToByte(exportedKey as JsonWebKey)
        return await this.encryptDataWithAes(key, encodedKey,base64Encoded,iv)
    }

    // @ts-ignore
    async encryptObjectWithAes<T>(key:CryptoKey, data:T, base64Encoded: boolean = true, iv?:Uint8Array): Promise<AesEncryption> {
        const serializedObject = JSON.stringify(data)
        const encodedObject = ByteConverter.encodeString(serializedObject)
        return await this.encryptDataWithAes(key, encodedObject, base64Encoded, iv)
    }

    // @ts-ignore
    async decryptDataWithAes(key: CryptoKey, data: Uint8Array|ArrayBuffer|string, iv:Uint8Array, base64Encoded: boolean = false): Promise<ArrayBuffer> {
        let decodedData = data
        if(base64Encoded) {
            decodedData = ByteConverter.base64StringToUint8Array(data as string)
        }
        return await this.aes.decrypt(iv, key, decodedData as Uint8Array|ArrayBuffer)
    }

    // @ts-ignore
    async decryptStringWithAes(key: CryptoKey, data:string|ArrayBuffer|Uint8Array, iv:Uint8Array, base64Encoded: boolean = true): Promise<string> {
        const decryptedData = await this.decryptDataWithAes(key, data, iv, base64Encoded)
        return ByteConverter.byteArrayToString(decryptedData)
    }

    // @ts-ignore
    async decryptKeyWithAes(key: CryptoKey, data: string|ArrayBuffer|Uint8Array, keyType: KeyTypes.AES_KEY|KeyTypes.RSA_PRIVATE_KEY|KeyTypes.RSA_PUBLIC_KEY|KeyTypes.ECDH_PRIVATE_KEY|KeyTypes.ECDH_PUBLIC_KEY, iv:Uint8Array, base64Encoded:boolean = true): Promise<CryptoKey> {
        const decryptedKey = await this.decryptDataWithAes(key, data, iv, base64Encoded)
        const decodedKey = KeyConverter.ByteToJWK(new Uint8Array(decryptedKey))
        switch (keyType) {
            case KeyTypes.AES_KEY:
                return this.aes.importKey(decodedKey)
            case KeyTypes.RSA_PUBLIC_KEY:
                return this.rsa.importKey(decodedKey, false)
            case KeyTypes.RSA_PRIVATE_KEY:
                return this.rsa.importKey(decodedKey, true)
            case KeyTypes.ECDH_PUBLIC_KEY:
                return this.ecdh.importKeyFordDrive(decodedKey, false)
            case KeyTypes.ECDH_PRIVATE_KEY:
                return this.ecdh.importKeyFordDrive(decodedKey, true)
            default:
                throw new Error('KeyType not supported')
        }
    }
    // @ts-ignore
    async decryptObjectWithAes<T>(key:CryptoKey, data:string|ArrayBuffer|Uint8Array, iv:Uint8Array, base64Encoded: boolean = true): Promise<T> {
        const decryptedObject = await this.decryptDataWithAes(key, data, iv, base64Encoded)
        const decodedObject = ByteConverter.byteArrayToString(decryptedObject)
        return JSON.parse(decodedObject) as T
    }

}