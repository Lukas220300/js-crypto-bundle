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
    async isPasswordKeySaved(aliceIdentifier: string):Promise<boolean> {
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
    async getSavedECDHPrivateKey(userIdentifier: string, key:CryptoKey): Promise<CryptoKey> {
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
        await this.storage.saveAESKey(KeyTypes.AES_KEY, Cryptols.getECDHSharedSecretIdentifier(aliceIdentifier,bobIdentifier),base64Key, iv)
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

}