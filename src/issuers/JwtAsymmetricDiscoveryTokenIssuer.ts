import * as path from 'path';
import {ExpireCache} from '@avanio/expire-cache';
import {type IAsyncCache} from '@luolapeikko/cache-types';
import {type IJwtKeys} from '../interfaces/JwtKeys';
import {type IOpenIdConfigCache} from '../interfaces/OpenIdConfig';
import {buildCertFrame, rsaPublicKeyPem} from '../lib/rsaPublicKeyPem';
import {type IJwtAsymmetricTokenIssuerProps, JwtAsymmetricTokenIssuer} from './JwtAsymmetricTokenIssuer';

export interface IJwtAsymmetricDiscoveryTokenIssuerProps extends IJwtAsymmetricTokenIssuerProps {
	discoveryCache?: IAsyncCache<IOpenIdConfigCache>;
}

export class JwtAsymmetricDiscoveryTokenIssuer extends JwtAsymmetricTokenIssuer {
	public override readonly type = 'asymmetric';
	private discoveryCache: IAsyncCache<IOpenIdConfigCache>;

	constructor(issuerUrlRules: (string | RegExp)[], {discoveryCache, ...props}: IJwtAsymmetricDiscoveryTokenIssuerProps = {}) {
		super(issuerUrlRules, props);
		this.discoveryCache = discoveryCache ?? new ExpireCache<IOpenIdConfigCache>(undefined, undefined, 86400000); // 24h
	}

	public override async get(issuerUrl: string, keyId: string) {
		this.checkIssuer(issuerUrl);
		let cert = this.store[issuerUrl]?.keys[keyId];
		if (cert) {
			return cert;
		}
		await this.loadIssuerCerts(issuerUrl);
		// try again after loading certs
		cert = this.store[issuerUrl]?.keys[keyId];
		if (cert) {
			return cert;
		}
		return undefined;
	}

	public load(issuerUrl: string): Promise<void> {
		this.checkIssuer(issuerUrl);
		return this.loadIssuerCerts(issuerUrl);
	}

	public override toString() {
		return `JwtAsymmetricDiscoveryTokenIssuer`;
	}

	private async loadIssuerCerts(issuerUrl: string): Promise<void> {
		this.logger?.debug(`JwtSymmetricDiscoveryTokenIssuer loadIssuerCerts ${issuerUrl}`);
		const config = await this.getConfiguration(issuerUrl);
		const req = new Request(config.jwks_uri);
		const res = await fetch(req);
		if (!res.ok) {
			throw new Error(`fetch error: ${res.statusText}`);
		}
		this.store[issuerUrl] ??= {
			_ts: 0,
			type: 'asymmetric',
			keys: {},
		};
		const certList = (await res.json()) as IJwtKeys;
		for (const key of certList.keys) {
			if (key.n && key.e) {
				this.store[issuerUrl].keys[key.kid] = buildCertFrame(rsaPublicKeyPem(key.n, key.e));
			} else if (key.x5c && key.x5c.length > 0) {
				if (!key.x5c[0]) {
					throw new Error(`JwtSymmetricDiscoveryTokenIssuer ${issuerUrl} x5c[0] is empty`);
				}
				this.store[issuerUrl].keys[key.kid] = buildCertFrame(key.x5c[0]);
			} else {
				this.logger?.warn(`JwtSymmetricDiscoveryTokenIssuer loadIssuerCerts ${issuerUrl} unknown key type`);
			}
		}
	}

	private async getConfiguration(issuerUrl: string): Promise<IOpenIdConfigCache> {
		const now = new Date().getDate();
		const currentConfig = await this.discoveryCache.get(issuerUrl);
		if (currentConfig && currentConfig.expires > now) {
			return currentConfig;
		}
		this.logger?.debug(`JwtSymmetricDiscoveryTokenIssuer load JWT Configuration ${issuerUrl}`);
		const url = new URL(issuerUrl);
		url.pathname = path.join(url.pathname, '/.well-known/openid-configuration');
		const req = new Request(url.toString());
		this.logger?.debug('fetch openid-configuration: ' + req.url);
		const res = await fetch(req);
		if (!res.ok) {
			this.logger?.error('fetch error: ' + res.statusText);
			throw new Error('fetch error: ' + res.statusText);
		}
		const configCache = (await res.json()) as IOpenIdConfigCache;
		await this.discoveryCache.set(issuerUrl, configCache);
		return configCache;
	}
}
