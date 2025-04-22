export interface IIssuerManager {
	get(issuerUrl: string, keyId: string): string | Buffer | undefined | Promise<string | Buffer | undefined>;
}
