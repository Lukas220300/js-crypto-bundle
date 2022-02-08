export interface AesEncryption {
    iv:Uint8Array,
    data: string|JsonWebKey|Uint8Array|ArrayBuffer
}