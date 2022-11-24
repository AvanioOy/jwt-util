export type CertSymmetricIssuer = {
	_ts: number;
	type: 'symmetric';
	keys: Record<string, string | undefined>;
};

export type CertAsymmetricIssuer = {
	_ts: number;
	type: 'asymmetric';
	keys: Record<string, Buffer | undefined>;
};

export type CertStore = {
	_ts: number;
	issuers: Record<string, CertSymmetricIssuer | CertAsymmetricIssuer>;
};

type AddAsymmetric = (issuerUrl: string, keyId: string, type: 'asymmetric', cert: Buffer) => Promise<void>;
type AddSymmetric = (issuerUrl: string, keyId: string, type: 'symmetric', cert: string) => Promise<void>;

export interface IJwtCertStore {
	init: () => Promise<void>;
	addCert: AddAsymmetric | AddSymmetric;
	getCert: (issuerUrl: string, keyId: string) => Promise<Buffer | string | undefined>;
	deleteCert: (issuerUrl: string, keyId: string) => Promise<boolean>;
	updateIssuerCerts: (issuerUrl: string, type: 'asymmetric' | 'symmetric', keys: Record<string, Buffer | string>) => Promise<void>;
	isEmpty: () => Promise<boolean>;
	haveIssuer: (issuerUrl: string) => Promise<boolean>;
}
