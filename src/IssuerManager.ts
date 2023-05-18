import {IJwtTokenIssuer} from './interfaces/IJwtTokenIssuer';
import {ILoggerLike} from '@avanio/logger-like';
import {IIssuerManager} from './interfaces/IIssuerManager';

interface IssuerManagerOptions {
	logger?: ILoggerLike;
}

export class IssuerManager implements IIssuerManager {
	private issuers: Set<IJwtTokenIssuer>;
	private options: IssuerManagerOptions;
	constructor(issuers: IJwtTokenIssuer[] = [], options: IssuerManagerOptions = {}) {
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
		return this.issuers.delete(issuer);
	}

	/**
	 * Get secret or public key for issuer and key id from all issuers
	 */
	public get(issuerUrl: string, keyId: string): Promise<string | Buffer | undefined> {
		const issuer = this.getIssuers(issuerUrl)[0];
		if (!issuer) {
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
