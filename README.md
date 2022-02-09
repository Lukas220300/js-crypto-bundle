# js-crypto-bundle aka CRYPTOLS

## Install
`npm install js-crypto-bundle`
### Includes following packages
- `js-crypto-core` [See Package](https://www.npmjs.com/package/js-crypto-core)
- `js-crypto-converter` [See Package](https://www.npmjs.com/package/js-crypto-converter)
- `js-crypto-local-storer` [See Package](https://www.npmjs.com/package/js-crypto-local-storer)

## IMPORTANT
### !!! Feel free to contribute and to give feedback !!!

## Usage
Please note that up to every function only returns a Promis.

```js
const cryptols = new Cryptols()
cryptols.init(()=>{
    console.log('IndexedDB was terminiated.')
})
// ... Use defined functions
```

### API
To see the full in TypeScript specified api see the file `src/Cryptolsable.ts`.

#### PBKDF2
- `generateKeyFromPassword`
- `generateAndSaveKeyFromPassword`
- `isPasswordKeySaved`
- `getSavedPasswordKey`

#### ECDH
- `generateECDHKeyPair`
- `generateAndSaveECDHKeyPair`
- `getSavedECDHPrivateKey`
- `getSavedECDHPublicKey`
- `generateSharedSecret`
- `generateSharedSecretFromSavedKey`
- `saveSharedSecret`
- `getSavedShareSecret`
- `saveECDHPublicKey`
- `saveECDHPrivateKey`
- `saveECDHKeyPair`

#### RSA
- `generateNewRsaKeyPair`
- `generateAndSaveNewRsaKeyPair`
- `getSavedRsaPublicKey`
- `getSavedRsaPrivateKey`
- `getSavedRsaKeyPair`
- `saveRsaPublicKey`
- `saveRsaPrivateKey`
- `saveRsaKeyPair`
- `encryptDataWithRsa`
- `encryptStringWithRsa`
- `encryptKeyWithRsa`
- `decryptDataWithRsa`
- `decryptStringWithRsa`
- `decryptKeyWithRsa`

#### AES
- `generateNewAesKey`
- `generateAndSaveNewAesKey`
- `getSavedAesKey`
- `saveAesKey`
- `encryptDataWithAes`
- `encryptStringWithAes`
- `encryptKeyWithAes`
- `encryptObjectWithAes`
- `decryptDataWithAes`
- `decryptStringWithAes`
- `decryptKeyWithAes`
- `decryptObjectWithAes`

## Cumming soon
Something like tests ;-)