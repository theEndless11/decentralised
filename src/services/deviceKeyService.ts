import { StorageService } from './storageService';

interface StoredDeviceEncryptionKeyPair {
  publicKey: string; // spki base64
  privateKey: string; // pkcs8 base64
  createdAt: number;
}

export class DeviceKeyService {
  private static readonly META_KEY = 'device-encryption-keypair';
  private static cachedPair: CryptoKeyPair | null = null;
  private static cachedPublicKey: string | null = null;

  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  private static base64ToUint8Array(base64: string): Uint8Array {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }

  private static async generateAndStoreKeyPair(): Promise<CryptoKeyPair> {
    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt'],
    );

    const [exportedPublic, exportedPrivate] = await Promise.all([
      crypto.subtle.exportKey('spki', pair.publicKey),
      crypto.subtle.exportKey('pkcs8', pair.privateKey),
    ]);

    const stored: StoredDeviceEncryptionKeyPair = {
      publicKey: this.arrayBufferToBase64(exportedPublic),
      privateKey: this.arrayBufferToBase64(exportedPrivate),
      createdAt: Date.now(),
    };

    await StorageService.setMetadata(this.META_KEY, stored);
    this.cachedPair = pair;
    this.cachedPublicKey = stored.publicKey;
    return pair;
  }

  static async getKeyPair(): Promise<CryptoKeyPair> {
    if (this.cachedPair) return this.cachedPair;

    const stored = await StorageService.getMetadata(this.META_KEY) as StoredDeviceEncryptionKeyPair | undefined;
    if (!stored?.publicKey || !stored?.privateKey) {
      return this.generateAndStoreKeyPair();
    }

    try {
      const [publicKey, privateKey] = await Promise.all([
        crypto.subtle.importKey(
          'spki',
          this.base64ToUint8Array(stored.publicKey),
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          true,
          ['encrypt'],
        ),
        crypto.subtle.importKey(
          'pkcs8',
          this.base64ToUint8Array(stored.privateKey),
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          true,
          ['decrypt'],
        ),
      ]);

      this.cachedPair = { publicKey, privateKey };
      this.cachedPublicKey = stored.publicKey;
      return this.cachedPair;
    } catch {
      return this.generateAndStoreKeyPair();
    }
  }

  static async getPublicKeyBase64(): Promise<string> {
    if (this.cachedPublicKey) return this.cachedPublicKey;

    const pair = await this.getKeyPair();
    const exported = await crypto.subtle.exportKey('spki', pair.publicKey);
    this.cachedPublicKey = this.arrayBufferToBase64(exported);
    return this.cachedPublicKey;
  }

  static async encryptForDevice(publicKeyBase64: string, plaintext: string): Promise<string> {
    const publicKey = await crypto.subtle.importKey(
      'spki',
      this.base64ToUint8Array(publicKeyBase64),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt'],
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      new TextEncoder().encode(plaintext),
    );
    return this.arrayBufferToBase64(encrypted);
  }

  static async decryptForCurrentDevice(ciphertextBase64: string): Promise<string> {
    const pair = await this.getKeyPair();
    const decrypted = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      pair.privateKey,
      this.base64ToUint8Array(ciphertextBase64),
    );
    return new TextDecoder().decode(decrypted);
  }
}
