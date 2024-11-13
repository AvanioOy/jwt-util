import {type CertAsymmetricIssuerFile, type CertSymmetricIssuer} from './IJwtCertStore';

export interface JwtIssuerSymmetricObject {
	_ts: Date;
	type: 'symmetric';
	keys: Record<string, string>;
}

export interface JwtIssuerAsymmetricObject {
	_ts: Date;
	type: 'asymmetric';
	keys: Record<string, Buffer>;
}

export interface IJwtTokenSymmetricIssuer {
	/**
	 * Match url to issuer url pattern
	 */
	issuerMatch: (issuerUrl: string) => boolean;
	/**
	 * type of the issuer
	 */
	type: 'symmetric';
	/**
	 * Add new key and secret to the issuer
	 */
	add: (issuerUrl: string, keyId: string, privateKey: string) => void;
	/**
	 * Get the secret from the issuer
	 */
	get: (issuerUrl: string, keyId: string) => Promise<string | undefined>;
	/**
	 * List all the key ids from the issuer
	 */
	listKeyIds: (issuerUrl: string) => Promise<string[]>;
	/**
	 * Import the issuer data from all the issuers
	 */
	import: (issuers: Record<string, CertSymmetricIssuer>) => void;
	/**
	 * Export the issuer data
	 */
	toJSON(): Record<string, CertSymmetricIssuer>;
}

export interface IJwtTokenAsymmetricIssuer {
	/**
	 * Match url to issuer url pattern
	 */
	issuerMatch: (issuerUrl: string) => boolean;
	/**
	 * type of the issuer
	 */
	type: 'asymmetric';
	/**
	 * Add new key and public key (Buffer) to the issuer
	 */
	add: (issuerUrl: string, keyId: string, cert: Buffer) => void;
	/**
	 * Get the public key from the issuer
	 */
	get: (issuerUrl: string, keyId: string) => Promise<Buffer | undefined>;
	/**
	 * List all the key ids from the issuer
	 */
	listKeyIds: (issuerUrl: string) => Promise<string[]>;
	/**
	 * Import the issuer data from all the issuers
	 */
	import: (issuers: Record<string, CertAsymmetricIssuerFile>) => void;
	/**
	 * Export the issuer data
	 */
	toJSON(): Record<string, CertAsymmetricIssuerFile>;
}

export type IJwtTokenIssuer = IJwtTokenSymmetricIssuer | IJwtTokenAsymmetricIssuer;
