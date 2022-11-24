import * as fs from 'fs';
import {IJwtCertStore} from './interfaces/IJwtCertStore';

export type CertSymmetricIssuer = {
	_ts: number;
	type: 'symmetric';
	keys: Record<string, string | undefined>;
};

export type CertAsymmetricIssuer = {
	_ts: number;
	type: 'asymmetric';
	keys: Record<string, Buffer | undefined>;
};

export type CertAsymmetricIssuerFile = {
	_ts: number;
	type: 'asymmetric';
	keys: Record<string, string | undefined>;
};

export type CertStore = {
	_ts: number;
	issuers: Record<string, CertSymmetricIssuer | CertAsymmetricIssuer>;
};

export type CertStoreFile = {
	_ts: number;
	issuers: Record<string, CertSymmetricIssuer | CertAsymmetricIssuerFile>;
};

type Props = {
	cacheFileName?: string;
	cachePretty?: boolean;
};

export class JwtCertStore implements IJwtCertStore {
	private store: CertStore;
	private props: Props | undefined;

	constructor(props?: Props) {
		this.props = props;
	}

	public async init() {
		if (!this.store) {
			if (this.props?.cacheFileName && fs.existsSync(this.props?.cacheFileName)) {
				this.store = JSON.parse((await fs.promises.readFile(this.props?.cacheFileName)).toString());
				this.restoreStore();
			} else {
				this.store = {_ts: 0, issuers: {}};
			}
		}
	}

	public async addCert(issuerUrl: string, keyId: string, type: 'symmetric' | 'asymmetric', cert: string | Buffer): Promise<void> {
		this.isInitialized();
		const now = Date.now();
		if (!this.store.issuers[issuerUrl]) {
			this.store.issuers[issuerUrl] = {
				_ts: now,
				type,
				keys: {},
			};
		}
		if (this.store.issuers[issuerUrl].type !== type) {
			throw new TypeError('Issuer type mismatch');
		}
		this.store.issuers[issuerUrl].keys[keyId] = cert;
		return this.saveStore();
	}

	public getCert(issuerUrl: string, keyId: string): Promise<Buffer | string | undefined> {
		this.isInitialized();
		if (!issuerUrl || !keyId) {
			return Promise.resolve(undefined);
		}
		return Promise.resolve(this.store.issuers?.[issuerUrl]?.keys[keyId]);
	}

	public async deleteCert(issuerUrl: string, keyId: string): Promise<boolean> {
		this.isInitialized();
		if (this.store.issuers[issuerUrl] && this.store.issuers[issuerUrl].keys[keyId]) {
			delete this.store.issuers[issuerUrl].keys[keyId];
			await this.saveStore();
			return true;
		}
		return false;
	}

	public updateIssuerCerts(issuerUrl: string, type: 'symmetric' | 'asymmetric', keys: Record<string, string | Buffer>): Promise<void> {
		this.isInitialized();
		if (type === 'asymmetric') {
			this.store.issuers[issuerUrl] = {
				_ts: Date.now(),
				type: 'asymmetric',
				keys: keys as Record<string, Buffer>,
			};
		} else {
			this.store.issuers[issuerUrl] = {
				_ts: Date.now(),
				type: 'symmetric',
				keys: keys as Record<string, string>,
			};
		}
		return this.saveStore();
	}

	public isEmpty(): Promise<boolean> {
		this.isInitialized();
		return Promise.resolve(this.store._ts === 0);
	}

	public haveIssuer(issuerUrl: string): Promise<boolean> {
		this.isInitialized();
		return Promise.resolve(!!this.store.issuers[issuerUrl]);
	}

	public toJSON() {
		return this.buildJsonOutput();
	}

	/**
	 * Restore Buffer instances from JSON payload
	 */
	private restoreStore() {
		for (const issuer of Object.values(this.store.issuers)) {
			if (issuer.type === 'asymmetric' && issuer.keys) {
				issuer.keys = Object.entries(issuer.keys).reduce((last, [key, value]) => {
					if (typeof value === 'string') {
						last[key] = Buffer.from(value, 'base64');
					}
					return last;
				}, issuer.keys);
			}
		}
	}

	private isInitialized() {
		if (!this.store) {
			throw new Error('JwtCertManager not initialized');
		}
	}

	/**
	 * Save the store to the cache file
	 */
	private async saveStore(): Promise<void> {
		this.store._ts = Date.now();
		if (this.props?.cacheFileName) {
			await fs.promises.writeFile(this.props.cacheFileName, JSON.stringify(this, undefined, this.props.cachePretty ? 2 : 0));
		}
	}

	private buildJsonOutput() {
		const output: CertStoreFile = {_ts: this.store._ts, issuers: {}};
		for (const [issuerKey, issuer] of Object.entries(this.store.issuers)) {
			output.issuers[issuerKey] = {_ts: issuer._ts, type: issuer.type, keys: {}};
			if (issuer.type === 'asymmetric') {
				for (const [key, cert] of Object.entries(issuer.keys)) {
					output.issuers[issuerKey].keys[key] = cert?.toString('base64');
				}
			} else {
				output.issuers[issuerKey].keys = issuer.keys;
			}
		}
		return output;
	}
}
