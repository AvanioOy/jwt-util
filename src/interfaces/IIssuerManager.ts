export interface IIssuerManager {
	get(issuerUrl: string, keyId: string): Promise<string | Buffer | undefined>;
}
