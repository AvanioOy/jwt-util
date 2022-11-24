import * as path from 'path';
import 'cross-fetch/polyfill';
import {IJwtCertStore} from './interfaces/IJwtCertStore';
import {ILoggerLike} from './interfaces/ILoggerLike';
import {IJwtKeys} from './interfaces/JwtKeys';
import {IOpenIdConfigCache} from './interfaces/OpenIdConfig';
import {buildCertFrame, rsaPublicKeyPem} from './rsaPublicKeyPem';

interface Props {
	logger?: ILoggerLike;
	/**
	 * limit valid issuers to be loaded for asymmetric keys
	 */
	validIssuers?: string[];
	notValidIssuerThrows: boolean;
}

export class JwtCertManager {
	private manager: IJwtCertStore;
	private configCache: {[key: string]: IOpenIdConfigCache} = {};
	private props: Props;
	constructor(manager: IJwtCertStore, props: Props = {notValidIssuerThrows: false}) {
		this.manager = manager;
		this.props = props;
	}

	/**
	 * this wraps the JwtCertStore.getCert method and adds the logic to fetch the certs from the issuer if they are not in the store
	 */
	public async getCert(issuerUrl: string, kid: string): Promise<Buffer | string> {
		await this.manager.init();
		let cert = await this.manager.getCert(issuerUrl, kid);
		// not found, try to load issuer certs
		if (!cert) {
			await this.loadIssuerCerts(issuerUrl);
		}
		cert = await this.manager.getCert(issuerUrl, kid);
		// not found, throw error
		if (!cert) {
			// after issuer certs update, we still don't have cert for kid, throw out
			throw new Error(`no key Id '${kid}' found for issuer '${issuerUrl}'`);
		}
		return cert;
	}

	public async deleteCert(issuerUrl: string, kid: string): Promise<boolean> {
		await this.manager.init();
		return this.manager.deleteCert(issuerUrl, kid);
	}

	/**
	 * Get the issuer asymmetric certs from the issuer and update the store.
	 * This method can be called on service restart to pre-load the certs from the issuer.
	 */
	public async loadIssuerCerts(issuerUrl: string): Promise<void> {
		await this.manager.init();
		if (!this.isValidIssuer(issuerUrl)) {
			if (this.props?.notValidIssuerThrows) {
				throw new Error(`Issuer '${issuerUrl}' is not in validIssuers list`);
			}
			return;
		}
		this.props?.logger?.debug(`JwtCertManager loadIssuerCerts ${issuerUrl}`);
		const config = await this.getConfiguration(issuerUrl);
		const req = new Request(config.jwks_uri);
		const res = await fetch(req);
		if (!res.ok) {
			throw new Error('fetch error: ' + res.statusText);
		}
		const certList = (await res.json()) as IJwtKeys;
		for (const key of certList.keys) {
			if (key.n && key.e) {
				await this.manager.addCert(issuerUrl, key.kid, 'asymmetric', buildCertFrame(rsaPublicKeyPem(key.n, key.e)));
			} else if (key.x5c && key.x5c.length > 0) {
				await this.manager.addCert(issuerUrl, key.kid, 'asymmetric', buildCertFrame(key.x5c[0]));
			} else {
				this.props?.logger?.warn(`jwt-util getCertList ${issuerUrl} unknown key type`);
			}
		}
	}

	/**
	 * get OpenID configuration from cache or fetch directly from issuer
	 */
	private async getConfiguration(issuerUrl: string): Promise<IOpenIdConfigCache> {
		const now = new Date().getDate();
		if (!this.configCache[issuerUrl] || now > this.configCache[issuerUrl].expires) {
			this.props.logger?.debug(`JwtCertManager load JWT Configuration ${issuerUrl}`);
			const url = new URL(issuerUrl);
			url.pathname = path.join(url.pathname, '/.well-known/openid-configuration');
			const req = new Request(url.toString());
			this.props.logger?.debug('fetch openid-configuration: ' + req.url);
			const res = await fetch(req);
			if (!res.ok) {
				this.props.logger?.error('fetch error: ' + res.statusText);
				throw new Error('fetch error: ' + res.statusText);
			}
			this.configCache[issuerUrl] = {
				...(await res.json()),
				expires: now + 86400000, // cache OpenId config for 24h
			};
		}
		return this.configCache[issuerUrl];
	}

	private isValidIssuer(issuerUrl: string): boolean {
		if (!this.props?.validIssuers) {
			return true;
		}
		return this.props?.validIssuers.includes(issuerUrl);
	}

	public async haveIssuer(issuerUrl: string): Promise<boolean> {
		await this.manager.init();
		return this.manager.haveIssuer(issuerUrl);
	}
}
