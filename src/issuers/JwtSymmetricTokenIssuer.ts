import {CertSymmetricIssuer} from '../interfaces/IJwtCertStore';
import {IJwtTokenSymmetricIssuer} from '../interfaces/IJwtTokenIssuer';

export class JwtSymmetricTokenIssuer implements IJwtTokenSymmetricIssuer {
	public readonly type = 'symmetric';
	private store: Record<string, CertSymmetricIssuer>;
	constructor(issuerUrl: string[]) {
		this.store = issuerUrl.reduce<Record<string, CertSymmetricIssuer>>((last, issuer) => {
			last[issuer] = {
				_ts: 0,
				type: this.type,
				keys: {},
			};
			return last;
		}, {});
	}

	public listKeyIds(issuerUrl: string): Promise<string[]> {
		this.checkIssuer(issuerUrl);
		return Promise.resolve(Object.keys(this.store[issuerUrl].keys));
	}

	public issuerMatch(issuerUrl: string) {
		return issuerUrl in this.store;
	}

	public add(issuerUrl: string, keyId: string, cert: string) {
		this.checkIssuer(issuerUrl);
		this.store[issuerUrl].keys[keyId] = cert;
		this.store[issuerUrl]._ts = Date.now();
	}

	public get(issuerUrl: string, keyId: string) {
		this.checkIssuer(issuerUrl);
		return Promise.resolve(this.store[issuerUrl].keys[keyId]);
	}

	public import() {
		// ignore the data
	}

	public toJSON(): Record<string, CertSymmetricIssuer> {
		return Object.entries(this.store).reduce<Record<string, CertSymmetricIssuer>>((last, [issuerUrl, issuer]) => {
			last[issuerUrl] = {
				_ts: issuer._ts,
				type: issuer.type,
				keys: {}, // we don't want to save the symmetric private keys
			};
			return last;
		}, {});
	}

	private checkIssuer(issuerUrl: string) {
		if (!this.issuerMatch(issuerUrl)) {
			throw new Error('Issuer does not match');
		}
	}
}
