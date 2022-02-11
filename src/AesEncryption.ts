export interface AesEncryption {
    iv:Uint8Array|string,
    data: string|JsonWebKey|Uint8Array|ArrayBuffer
}