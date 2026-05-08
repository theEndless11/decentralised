// src/services/userService.ts
import { GunService } from './gunService';
import { VoteTrackerService } from './voteTrackerService';
import { KeyService } from './keyService';
import { CryptoService } from './cryptoService';
import { DeviceKeyService } from './deviceKeyService';
import type { DeviceApprovalRecord, DeviceApprovalRequest } from '../types/encryption';

export interface UserProfile {
  id: string;
  username: string;
  displayName: string;
  customUsername?: string;
  showRealName?: boolean;
  avatarIPFS?: string;
  avatarThumbnail?: string;
  bio: string;
  createdAt: number;
  karma: number;
  postCount: number;
  commentCount: number;
  publicKey?: string; // Schnorr public key
  deviceEncryptionPublicKey?: string; // RSA-OAEP key for community-key envelopes
  approvedDevices?: Record<string, DeviceApprovalRecord>;
}

export interface UserStats {
  totalPosts: number;
  totalComments: number;
  totalUpvotes: number;
  totalDownvotes: number;
  karma: number;
  joinedCommunities: number;
}

export class UserService {
  private static currentUser: UserProfile | null = null;

  private static approvalPayload(payload: {
    userId: string;
    devicePublicKey: string;
    deviceEncryptionPublicKey: string;
    approvedBy: string;
    approvedAt: number;
  }): string {
    return JSON.stringify({
      approvedAt: payload.approvedAt,
      approvedBy: payload.approvedBy,
      deviceEncryptionPublicKey: payload.deviceEncryptionPublicKey,
      devicePublicKey: payload.devicePublicKey,
      userId: payload.userId,
    });
  }

  private static signApprovalPayload(payload: {
    userId: string;
    devicePublicKey: string;
    deviceEncryptionPublicKey: string;
    approvedBy: string;
    approvedAt: number;
  }, privateKeyHex: string): string {
    const hash = CryptoService.hash(this.approvalPayload(payload));
    return CryptoService.sign(hash, privateKeyHex);
  }

  private static requestPayload(payload: {
    userId: string;
    devicePublicKey: string;
    deviceEncryptionPublicKey: string;
    requestedAt: number;
    method: DeviceApprovalRequest['method'];
  }): string {
    return JSON.stringify({
      deviceEncryptionPublicKey: payload.deviceEncryptionPublicKey,
      devicePublicKey: payload.devicePublicKey,
      method: payload.method,
      requestedAt: payload.requestedAt,
      userId: payload.userId,
    });
  }

  static verifyDeviceApproval(
    userId: string,
    record: DeviceApprovalRecord,
    currentlyApproved: Set<string>,
  ): boolean {
    if (record.status !== 'approved') return false;
    const payload = {
      userId,
      devicePublicKey: record.devicePublicKey,
      deviceEncryptionPublicKey: record.deviceEncryptionPublicKey,
      approvedBy: record.approvedBy,
      approvedAt: record.approvedAt,
    };
    const hash = CryptoService.hash(this.approvalPayload(payload));
    const validSignature = CryptoService.verify(hash, record.signature, record.approvedBy);
    if (!validSignature) return false;
    if (record.approvedBy === record.devicePublicKey) {
      return currentlyApproved.size <= 1 && currentlyApproved.has(record.devicePublicKey);
    }
    return true;
  }

  private static async ensureCurrentDeviceApproved(existingProfile: UserProfile): Promise<UserProfile> {
    const [identityKeys, deviceEncryptionPublicKey] = await Promise.all([
      KeyService.getKeyPair(),
      DeviceKeyService.getPublicKeyBase64(),
    ]);

    const approvedDevices = { ...(existingProfile.approvedDevices || {}) };
    const now = Date.now();
    const currentRecord = approvedDevices[identityKeys.publicKey];
    let shouldWrite = false;
    const isBootstrapProfile = Object.keys(approvedDevices).length === 0;

    if (isBootstrapProfile) {
      const signature = this.signApprovalPayload({
        userId: existingProfile.id,
        devicePublicKey: identityKeys.publicKey,
        deviceEncryptionPublicKey,
        approvedBy: identityKeys.publicKey,
        approvedAt: now,
      }, identityKeys.privateKey);
      approvedDevices[identityKeys.publicKey] = {
        devicePublicKey: identityKeys.publicKey,
        deviceEncryptionPublicKey,
        approvedBy: identityKeys.publicKey,
        approvedAt: now,
        signature,
        status: 'approved',
      };
      shouldWrite = true;
    } else if (currentRecord && currentRecord.status === 'approved' && currentRecord.approvedBy === identityKeys.publicKey && currentRecord.deviceEncryptionPublicKey !== deviceEncryptionPublicKey) {
      const signature = this.signApprovalPayload({
        userId: existingProfile.id,
        devicePublicKey: identityKeys.publicKey,
        deviceEncryptionPublicKey,
        approvedBy: identityKeys.publicKey,
        approvedAt: now,
      }, identityKeys.privateKey);
      approvedDevices[identityKeys.publicKey] = {
        ...currentRecord,
        deviceEncryptionPublicKey,
        approvedAt: now,
        signature,
      };
      shouldWrite = true;
    }

    const nextProfile: UserProfile = {
      ...existingProfile,
      publicKey: identityKeys.publicKey,
      deviceEncryptionPublicKey,
      approvedDevices,
    };

    if (shouldWrite || !existingProfile.publicKey || !existingProfile.deviceEncryptionPublicKey || !existingProfile.approvedDevices) {
      const gun = GunService.getGun();
      await gun.get('users').get(existingProfile.id).put(nextProfile);
    }

    return nextProfile;
  }

  static async getCurrentUser(forceRefresh = false): Promise<UserProfile> {
    if (this.currentUser && !forceRefresh) return this.currentUser;

    const deviceId = await VoteTrackerService.getDeviceId();
    const gun = GunService.getGun();

    const existingProfile = await new Promise<UserProfile | null>((resolve) => {
      let resolved = false;
      let listener: any;
      listener = gun.get('users').get(deviceId).on((data: any) => {
        if (!resolved && data && !data._ && data.id) {
          resolved = true;
          listener?.off?.();
          resolve(data as UserProfile);
        }
      });
      setTimeout(() => {
        if (!resolved) {
          resolved = true;
          listener?.off?.();
          resolve(null);
        }
      }, 3000);
    });

    const [publicKey, deviceEncryptionPublicKey] = await Promise.all([
      KeyService.getPublicKeyHex(),
      DeviceKeyService.getPublicKeyBase64(),
    ]);

    if (existingProfile) {
      const upgraded = await this.ensureCurrentDeviceApproved({
        ...existingProfile,
        publicKey: existingProfile.publicKey || publicKey,
        deviceEncryptionPublicKey: existingProfile.deviceEncryptionPublicKey || deviceEncryptionPublicKey,
      });
      this.currentUser = upgraded;
      return upgraded;
    }

    if (this.currentUser) {
      const upgraded = await this.ensureCurrentDeviceApproved(this.currentUser);
      this.currentUser = upgraded;
      return upgraded;
    }

    const keyPair = await KeyService.getKeyPair();
    const approvedAt = Date.now();
    const signature = this.signApprovalPayload({
      userId: deviceId,
      devicePublicKey: keyPair.publicKey,
      deviceEncryptionPublicKey,
      approvedBy: keyPair.publicKey,
      approvedAt,
    }, keyPair.privateKey);

    const newProfile: UserProfile = {
      id: deviceId,
      username: `user_${deviceId.substring(0, 8)}`,
      displayName: `User ${deviceId.substring(0, 8)}`,
      bio: '',
      createdAt: Date.now(),
      karma: 0,
      postCount: 0,
      commentCount: 0,
      publicKey,
      deviceEncryptionPublicKey,
      approvedDevices: {
        [keyPair.publicKey]: {
          devicePublicKey: keyPair.publicKey,
          deviceEncryptionPublicKey,
          approvedBy: keyPair.publicKey,
          approvedAt,
          signature,
          status: 'approved',
        },
      },
    };

    await gun.get('users').get(deviceId).put(newProfile);
    this.currentUser = newProfile;
    return newProfile;
  }

  static async isCurrentDeviceApproved(userId: string): Promise<boolean> {
    const [profile, keyPair] = await Promise.all([
      this.getUser(userId),
      KeyService.getKeyPair(),
    ]);
    if (!profile?.approvedDevices) return false;
    const record = profile.approvedDevices[keyPair.publicKey];
    if (!record) return false;
    const approvedSet = new Set(
      Object.values(profile.approvedDevices)
        .filter((entry) => entry.status === 'approved')
        .map((entry) => entry.devicePublicKey),
    );
    return this.verifyDeviceApproval(userId, record, approvedSet);
  }

  static async createDeviceApprovalRequest(
    userId: string,
    method: DeviceApprovalRequest['method'],
  ): Promise<DeviceApprovalRequest> {
    const [identity, deviceEncryptionPublicKey] = await Promise.all([
      KeyService.getKeyPair(),
      DeviceKeyService.getPublicKeyBase64(),
    ]);
    const requestedAt = Date.now();
    const requestSignature = CryptoService.sign(
      CryptoService.hash(this.requestPayload({
        userId,
        devicePublicKey: identity.publicKey,
        deviceEncryptionPublicKey,
        requestedAt,
        method,
      })),
      identity.privateKey,
    );
    const request: DeviceApprovalRequest = {
      userId,
      devicePublicKey: identity.publicKey,
      deviceEncryptionPublicKey,
      requestedAt,
      method,
      signature: requestSignature,
    };
    const gun = GunService.getGun();
    await gun
      .get('users')
      .get(userId)
      .get('deviceApprovalRequests')
      .get(identity.publicKey)
      .put(request);
    return request;
  }

  static async approveDevice(
    userId: string,
    targetDevicePublicKey: string,
    targetDeviceEncryptionPublicKey: string,
  ): Promise<DeviceApprovalRecord> {
    const [approverIdentity, profile] = await Promise.all([
      KeyService.getKeyPair(),
      this.getUser(userId),
    ]);
    if (!profile) throw new Error('User profile not found');
    const approvedDevices = { ...(profile.approvedDevices || {}) };
    const approverRecord = approvedDevices[approverIdentity.publicKey];
    if (!approverRecord || approverRecord.status !== 'approved') {
      throw new Error('Current device is not approved to approve new devices');
    }

    const approvedAt = Date.now();
    const signature = this.signApprovalPayload({
      userId,
      devicePublicKey: targetDevicePublicKey,
      deviceEncryptionPublicKey: targetDeviceEncryptionPublicKey,
      approvedBy: approverIdentity.publicKey,
      approvedAt,
    }, approverIdentity.privateKey);

    const record: DeviceApprovalRecord = {
      devicePublicKey: targetDevicePublicKey,
      deviceEncryptionPublicKey: targetDeviceEncryptionPublicKey,
      approvedBy: approverIdentity.publicKey,
      approvedAt,
      signature,
      status: 'approved',
    };

    approvedDevices[targetDevicePublicKey] = record;
    const nextProfile: UserProfile = { ...profile, approvedDevices };
    const gun = GunService.getGun();
    await gun.get('users').get(userId).put(nextProfile);
    if (this.currentUser?.id === userId) {
      this.currentUser = nextProfile;
    }
    return record;
  }

  static async revokeDevice(userId: string, targetDevicePublicKey: string): Promise<void> {
    const profile = await this.getUser(userId);
    if (!profile?.approvedDevices?.[targetDevicePublicKey]) return;
    const nextProfile: UserProfile = {
      ...profile,
      approvedDevices: {
        ...profile.approvedDevices,
        [targetDevicePublicKey]: {
          ...profile.approvedDevices[targetDevicePublicKey],
          status: 'revoked',
        },
      },
    };
    const gun = GunService.getGun();
    await gun.get('users').get(userId).put(nextProfile);
    if (this.currentUser?.id === userId) {
      this.currentUser = nextProfile;
    }
  }

  static async getApprovedDevicePublicKeys(userId: string): Promise<string[]> {
    const profile = await this.getUser(userId);
    if (!profile?.approvedDevices) return [];
    const approvedSet = new Set(
      Object.values(profile.approvedDevices)
        .filter((record) => record.status === 'approved')
        .map((record) => record.devicePublicKey),
    );
    const verified: string[] = [];
    for (const pubkey of approvedSet) {
      const record = profile.approvedDevices[pubkey];
      if (!record) continue;
      if (this.verifyDeviceApproval(userId, record, approvedSet)) {
        verified.push(pubkey);
      }
    }
    return verified;
  }

  static async getDeviceEncryptionPublicKey(userId: string, devicePublicKey: string): Promise<string | null> {
    const profile = await this.getUser(userId);
    const record = profile?.approvedDevices?.[devicePublicKey];
    if (!record || record.status !== 'approved') return null;
    return record.deviceEncryptionPublicKey;
  }

  static async updateProfile(updates: Partial<UserProfile>): Promise<UserProfile> {
    const gun = GunService.getGun();
    const currentUser = await this.getCurrentUser();

    const updatedProfile = { ...currentUser, ...updates };
    await gun.get('users').get(currentUser.id).put(updatedProfile);

    this.currentUser = updatedProfile;
    return updatedProfile;
  }

  static async getUser(userId: string): Promise<UserProfile | null> {
    const gun = GunService.getGun();
    return await gun.get('users').get(userId).once().then();
  }

  static async incrementPostCount() {
    const user = await this.getCurrentUser(true);
    await this.updateProfile({ postCount: (user.postCount || 0) + 1 });
  }

  static async incrementCommentCount() {
    const user = await this.getCurrentUser(true);
    await this.updateProfile({ commentCount: (user.commentCount || 0) + 1 });
  }

  static async incrementKarma(authorId: string, points: number = 1) {
    const gun = GunService.getGun();
    const user = await this.getUser(authorId);
    if (user) {
      await gun.get('users').get(authorId).get('karma').put(user.karma + points);
    }
  }

  static async getUserStats(userId: string): Promise<UserStats> {
    const user = await this.getUser(userId);
    if (!user) {
      return { totalPosts: 0, totalComments: 0, totalUpvotes: 0, totalDownvotes: 0, karma: 0, joinedCommunities: 0 };
    }
    return {
      totalPosts: user.postCount,
      totalComments: user.commentCount,
      totalUpvotes: user.karma,
      totalDownvotes: 0,
      karma: user.karma,
      joinedCommunities: 0,
    };
  }

  static async searchUsers(query: string): Promise<UserProfile[]> {
    const gun = GunService.getGun();
    const users: UserProfile[] = [];
    return new Promise((resolve) => {
      gun.get('users').map().once((user: any) => {
        if (user && !user._ && user.username?.includes(query)) {
          users.push(user);
        }
      });
      setTimeout(() => resolve(users), 1000);
    });
  }
}
