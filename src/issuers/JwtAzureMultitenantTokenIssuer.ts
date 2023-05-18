import {CertAsymmetricIssuerFile, CertSymmetricIssuer} from '../interfaces/IJwtCertStore';
import {ILoggerLike} from '@avanio/logger-like';
import {JwtAsymmetricDiscoveryTokenIssuer} from './JwtAsymmetricDiscoveryTokenIssuer';

interface JwtAzureMultitenantTokenIssuerProps {
	logger?: ILoggerLike;
	allowedIssuers?: string[];
}

export class JwtAzureMultitenantTokenIssuer extends JwtAsymmetricDiscoveryTokenIssuer {
	private azureIssuers = new Map<string, JwtAsymmetricDiscoveryTokenIssuer>();
	public readonly type = 'asymmetric';

	private props: JwtAzureMultitenantTokenIssuerProps;

	constructor(props: JwtAzureMultitenantTokenIssuerProps = {}) {
		super([/^https:\/\/sts.windows.net\//], props.logger);
		this.props = props;
	}

	public issuerMatch(issuerUrl: string) {
		if (this.props.allowedIssuers && this.props.allowedIssuers.length > 0) {
			return this.props.allowedIssuers.includes(issuerUrl);
		}
		return issuerUrl?.startsWith('https://sts.windows.net/');
	}

	public add(issuerUrl: string, keyId: string, cert: Buffer) {
		this.getIssuer(issuerUrl).add(issuerUrl, keyId, cert);
	}

	public async get(issuerUrl: string, keyId: string) {
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
		return Array.from(this.azureIssuers.values()).reduce((last, issuer) => {
			return {
				...last,
				...issuer.toJSON(),
			};
		}, {});
	}

	private getIssuer(issuerUrl: string): JwtAsymmetricDiscoveryTokenIssuer {
		if (!this.issuerMatch(issuerUrl)) {
			throw new Error('Issuer does not match');
		}
		let issuer = this.azureIssuers.get(issuerUrl);
		if (!issuer) {
			issuer = new JwtAsymmetricDiscoveryTokenIssuer([issuerUrl], this.props.logger);
			this.azureIssuers.set(issuerUrl, issuer);
		}
		return issuer;
	}
}
