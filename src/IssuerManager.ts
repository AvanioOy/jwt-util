import {IIssuerManager} from './interfaces/IIssuerManager';
import {IJwtTokenIssuer} from './interfaces/IJwtTokenIssuer';
import {ILoggerLike} from '@avanio/logger-like';

interface IssuerManagerOptions {
	logger?: ILoggerLike;
}

/**
 * Issuer manager gets secret or public key for key id from all added issuers
 * If you have already validation in place, you can use this class to get the secret or public key for jwt verification
 * @example
 * const issuer = new JwtSymmetricTokenIssuer([ISSUER_URL]);
 * issuer.add(ISSUER_URL, '01', 'very-long-secret-here');
 * const issuerManager = new IssuerManager([issuer]);
 * const secretOrPublic: string | Buffer | undefined = await issuerManager.get(ISSUER_URL, kid);
 */
export class IssuerManager implements IIssuerManager {
	private issuers: Set<IJwtTokenIssuer>;
	private options: IssuerManagerOptions;
	constructor(issuers: IJwtTokenIssuer[] | Set<IJwtTokenIssuer> = [], options: IssuerManagerOptions = {}) {
		this.issuers = new Set(issuers);
		this.options = options;
	}

	/**
	 * Add issuer(s) to set of issuers
	 */
	public add(issuer: IJwtTokenIssuer | IJwtTokenIssuer[]): void {
		const issuers = Array.isArray(issuer) ? issuer : [issuer];
		issuers.forEach((i) => {
			this.options.logger?.debug(`Adding issuer: ${i.type}`);
			this.issuers.add(i);
		});
	}

	/**
	 * Delete issuer from set of issuers
	 */
	public delete(issuer: IJwtTokenIssuer): boolean {
		this.options.logger?.debug(`Deleting issuer: ${issuer.type}`);
		return this.issuers.delete(issuer);
	}

	/**
	 * Get secret or public key for issuer and key id from all issuers
	 */
	public get(issuerUrl: string, keyId: string): Promise<string | Buffer | undefined> {
		this.options.logger?.debug(`Getting issuer: ${issuerUrl} '${keyId}' size: ${this.issuers.size}`);
		const issuer = this.getIssuers(issuerUrl)[0];
		if (!issuer) {
			this.options.logger?.debug(`Issuer not found: ${issuerUrl}`);
			return Promise.resolve(undefined);
		}
		return issuer.get(issuerUrl, keyId);
	}

	public issuerSolverCount(issuerUrl: string): number {
		return this.getIssuers(issuerUrl).length;
	}

	private getIssuers(issuerUrl: string): IJwtTokenIssuer[] {
		return Array.from(this.issuers).filter((issuer) => issuer.issuerMatch(issuerUrl));
	}
}
