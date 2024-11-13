import {type CertAsymmetricIssuerFile, type CertSymmetricIssuer} from '../interfaces/IJwtCertStore';
import {JwtAsymmetricDiscoveryTokenIssuer, type JwtAsymmetricDiscoveryTokenIssuerProps} from './JwtAsymmetricDiscoveryTokenIssuer';
import {type IJwtTokenAsymmetricIssuer} from '../interfaces/IJwtTokenIssuer';

interface JwtAzureMultitenantTokenIssuerProps extends JwtAsymmetricDiscoveryTokenIssuerProps {
	allowedIssuers?: string[];
}

export class JwtAzureMultitenantTokenIssuer implements IJwtTokenAsymmetricIssuer {
	public readonly type = 'asymmetric';
	private azureIssuers = new Map<string, JwtAsymmetricDiscoveryTokenIssuer>();

	private props: JwtAzureMultitenantTokenIssuerProps;

	constructor(props: JwtAzureMultitenantTokenIssuerProps = {}) {
		this.props = props;
		this.props.logger?.info(`JwtAzureMultitenantTokenIssuer created for ${String(this.props.allowedIssuers?.length)} issuers rules`);
	}

	public listKeyIds(issuerUrl: string): Promise<string[]> {
		return this.getIssuer(issuerUrl).listKeyIds(issuerUrl);
	}

	public issuerMatch(issuerUrl: string) {
		// this.props.logger?.debug(`${this.type} issuerMatch ${issuerUrl} ${this.props.allowedIssuers}`);
		if (this.props.allowedIssuers && this.props.allowedIssuers.length > 0 && !this.props.allowedIssuers.includes(issuerUrl)) {
			return false;
		}
		const isSts = issuerUrl.startsWith('https://sts.windows.net/');
		const isLogin = issuerUrl.startsWith('https://login.microsoftonline.com/');
		return isSts || isLogin;
	}

	public add(issuerUrl: string, keyId: string, cert: Buffer) {
		this.props.logger?.debug(`${this.type} add ${issuerUrl} ${keyId}`);
		this.getIssuer(issuerUrl).add(issuerUrl, keyId, cert);
	}

	public async get(issuerUrl: string, keyId: string) {
		this.props.logger?.debug(`${this.type} get ${issuerUrl} ${keyId}`);
		return this.getIssuer(issuerUrl).get(issuerUrl, keyId);
	}

	public import(issuers: Record<string, CertSymmetricIssuer | CertAsymmetricIssuerFile>) {
		Object.keys(issuers).forEach((issuerUrl) => {
			if (this.issuerMatch(issuerUrl)) {
				this.getIssuer(issuerUrl).import(issuers);
			}
		});
	}

	public toJSON(): Record<string, CertAsymmetricIssuerFile> {
		return Array.from(this.azureIssuers.values()).reduce<Record<string, CertAsymmetricIssuerFile>>((last, issuer) => {
			return {
				...last,
				...issuer.toJSON(),
			};
		}, {});
	}

	private getIssuer(issuerUrl: string): JwtAsymmetricDiscoveryTokenIssuer {
		this.props.logger?.debug(`${this.type} getIssuer ${issuerUrl}`);
		if (!this.issuerMatch(issuerUrl)) {
			throw new Error('Issuer does not match');
		}
		let issuer = this.azureIssuers.get(issuerUrl);
		if (!issuer) {
			issuer = new JwtAsymmetricDiscoveryTokenIssuer([issuerUrl], this.props);
			this.azureIssuers.set(issuerUrl, issuer);
		}
		return issuer;
	}
}
