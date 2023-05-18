import {CertAsymmetricIssuer, CertAsymmetricIssuerFile, CertSymmetricIssuer} from './IJwtCertStore';

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
	issuerMatch: (issuerUrl: string) => boolean;
	type: 'symmetric';
	add: (issuerUrl: string, keyId: string, cert: string) => void;
	get: (issuerUrl: string, keyId: string) => Promise<string | undefined>;
	listKeyIds: (issuerUrl: string) => Promise<string[]>;
	import: (issuers: Record<string, CertSymmetricIssuer>) => void;
	toJSON(): Record<string, CertSymmetricIssuer>;
}

export interface IJwtTokenAsymmetricIssuer {
	issuerMatch: (issuerUrl: string) => boolean;
	type: 'asymmetric';
	add: (issuerUrl: string, keyId: string, cert: Buffer) => void;
	get: (issuerUrl: string, keyId: string) => Promise<Buffer | undefined>;
	listKeyIds: (issuerUrl: string) => Promise<string[]>;
	/**
	 * import the issuer data from all the issuers
	 */
	import: (issuers: Record<string, CertAsymmetricIssuerFile>) => void;
	toJSON(): Record<string, CertAsymmetricIssuerFile>;
}

export type IJwtTokenIssuer = IJwtTokenSymmetricIssuer | IJwtTokenAsymmetricIssuer;
/* export interface IJwtTokenIssuer {
	issuerMatch: (issuerUrl: string) => boolean;
	type: 'asymmetric' | 'symmetric';
	add: (issuerUrl: string, keyId: string, cert: string | Buffer) => void;
	get: (issuerUrl: string, keyId: string) => Promise<string | Buffer | undefined>;
	import: (issuers: Record<string, CertSymmetricIssuer | CertAsymmetricIssuerFile>) => void;
	toJSON(): Record<string, CertSymmetricIssuer | CertAsymmetricIssuerFile>;
} */
