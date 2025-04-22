import {type ILoggerLike} from '@avanio/logger-like';
import {type CertAsymmetricIssuer, type CertAsymmetricIssuerFile, type CertSymmetricIssuer} from '../interfaces/IJwtCertStore';
import {type IJwtTokenAsymmetricIssuer} from '../interfaces/IJwtTokenIssuer';

/**
 * Returns a function that takes a string or RegExp and returns true if the
 * issuerUrl matches the rule.
 * @param issuerUrl - The issuerUrl to match
 * @returns A function that takes a string or RegExp and returns true if the
 * issuerUrl matches the rule.
 */
function buildStringOrRegExpMatch(issuerUrl: string): (issuerUrlRule: string | RegExp) => boolean {
	return function stringOrRegExpMatch(issuerUrlRule: string | RegExp): boolean {
		if (typeof issuerUrlRule === 'string') {
			return issuerUrlRule === issuerUrl;
		} else {
			return issuerUrlRule.test(issuerUrl);
		}
	};
}

export interface IJwtAsymmetricTokenIssuerProps {
	logger?: ILoggerLike;
}

export class JwtAsymmetricTokenIssuer implements IJwtTokenAsymmetricIssuer {
	readonly name = 'JwtAsymmetricTokenIssuer';
	public readonly type = 'asymmetric';

	protected store: Record<string, CertAsymmetricIssuer> = {};
	protected logger?: ILoggerLike;
	protected issuerUrls: (string | RegExp)[] = [];
	constructor(issuerUrlRules: (string | RegExp)[], {logger}: IJwtAsymmetricTokenIssuerProps = {}) {
		this.issuerUrls = issuerUrlRules;
		this.logger = logger;
		this.logger?.info(`${this.name} created for ${issuerUrlRules.length.toString()} issuers rules`);
	}

	public listKeyIds(issuerUrl: string): Promise<string[]> {
		this.logger?.debug(`${this.name} listKeyIds ${issuerUrl}`);
		this.checkIssuer(issuerUrl);
		if (!this.store[issuerUrl]) {
			return Promise.resolve([]);
		}
		return Promise.resolve(Object.keys(this.store[issuerUrl].keys));
	}

	public issuerMatch(issuerUrl: string) {
		this.logger?.debug(`${this.name} issuerMatch ${issuerUrl}`);
		const isMatch = this.issuerUrls.some(buildStringOrRegExpMatch(issuerUrl));
		// create empty store entry for issuer url not yet in store
		if (isMatch && !this.store[issuerUrl]) {
			this.store[issuerUrl] = {
				_ts: 0,
				type: 'asymmetric',
				keys: {},
			};
		}
		return isMatch;
	}

	public add(issuerUrl: string, keyId: string, cert: Buffer) {
		this.logger?.debug(`${this.name} add ${issuerUrl} ${keyId}`);
		this.checkIssuer(issuerUrl);
		this.store[issuerUrl] ??= {
			_ts: 0,
			type: this.type,
			keys: {},
		};
		this.store[issuerUrl].keys[keyId] = cert;
		this.store[issuerUrl]._ts = Date.now();
	}

	public get(issuerUrl: string, keyId: string) {
		this.logger?.debug(`${this.name} get ${issuerUrl} ${keyId}`);
		this.checkIssuer(issuerUrl);
		return Promise.resolve(this.store[issuerUrl]?.keys[keyId]);
	}

	public import(issuers: Record<string, CertSymmetricIssuer | CertAsymmetricIssuerFile>) {
		Object.entries(issuers).forEach(([issuerUrl, issuer]) => {
			if (issuer.type === 'asymmetric' && this.issuerMatch(issuerUrl)) {
				this.store[issuerUrl] = {
					_ts: issuer._ts,
					type: issuer.type,
					keys: Object.entries(issuer.keys).reduce<Record<string, Buffer | undefined>>((last, [key, cert]) => {
						if (cert) {
							last[key] = Buffer.from(cert, 'base64'); // convert base64 to buffer
						}
						return last;
					}, {}),
				};
			}
		});
	}

	public toJSON(): Record<string, CertAsymmetricIssuerFile> {
		return Object.entries(this.store).reduce<Record<string, CertAsymmetricIssuerFile>>((last, [issuerUrl, issuer]) => {
			last[issuerUrl] = {
				_ts: issuer._ts,
				type: issuer.type,
				keys: Object.entries(issuer.keys).reduce<Record<string, string | undefined>>((last, [keyId, cert]) => {
					last[keyId] = cert?.toString('base64'); // convert buffer to base64
					return last;
				}, {}),
			};
			return last;
		}, {});
	}

	public toString() {
		return `JwtAsymmetricTokenIssuer`;
	}

	protected checkIssuer(issuerUrl: string) {
		if (!this.issuerMatch(issuerUrl)) {
			throw new Error('Issuer does not match');
		}
	}
}
