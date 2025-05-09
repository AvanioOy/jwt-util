import {type ILoggerLike} from '@avanio/logger-like';
import {type IIssuerManager} from './interfaces/IIssuerManager';
import {type IJwtTokenIssuer} from './interfaces/IJwtTokenIssuer';

interface IIssuerManagerOptions {
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
	private options: IIssuerManagerOptions;
	constructor(issuers: IJwtTokenIssuer[] | Set<IJwtTokenIssuer> = [], options: IIssuerManagerOptions = {}) {
		this.issuers = new Set(issuers);
		this.options = options;
	}

	/**
	 * Add issuer(s) to set of issuers
	 * @param issuer - issuer
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
	 * @param issuer - issuer
	 * @returns boolean if deleted
	 */
	public delete(issuer: IJwtTokenIssuer): boolean {
		this.options.logger?.debug(`Deleting issuer: ${issuer.type}`);
		return this.issuers.delete(issuer);
	}

	/**
	 * Get secret or public key for issuer and key id from all issuers
	 * @param issuerUrl - issuer url
	 * @param keyId - JWT key id
	 * @returns JWT string (symmetric), buffer (asymmetric) or undefined
	 */
	public get(issuerUrl: string, keyId: string): string | Buffer | undefined | Promise<string | Buffer | undefined> {
		this.options.logger?.debug(`Getting issuer: ${issuerUrl} '${keyId}' size: ${this.issuers.size.toString()}`);
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
